# Offline regression tests for the CVE database builder. Synthetic feed only.
# No internet access, Active Directory, or real vulnerability data required.
BeforeAll {
    $script:builder = Join-Path $PSScriptRoot '..\Build-TJETCveDatabase.ps1'
    $script:feedRoot = Join-Path $TestDrive 'cvelistV5'
    $script:cvesDir = Join-Path $script:feedRoot 'cves'
    New-Item -ItemType Directory -Path $script:cvesDir -Force | Out-Null

    function Write-SyntheticCve {
        param([string]$Id, [string]$State = 'PUBLISHED', $Affected, [double]$Score = 8.8)
        $record = @{
            cveMetadata = @{ cveId = $Id; state = $State }
            containers = @{
                cna = @{
                    affected = @($Affected)
                    metrics = @(@{ cvssV3_1 = @{
                        baseScore = $Score
                        vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    } })
                }
            }
        }
        $json = $record | ConvertTo-Json -Depth 20
        $path = Join-Path $script:cvesDir ($Id + '.json')
        Set-Content -LiteralPath $path -Value $json -Encoding UTF8
    }

    Write-SyntheticCve -Id 'CVE-2026-0001' -Affected @{
        vendor = 'Example Corp'; product = 'Example Browser'; defaultStatus = 'unaffected'
        versions = @(
            @{ status = 'affected'; version = '1.0.0'; lessThan = '2.0.0' }
            @{ status = 'unaffected'; version = '1.5.0' }
            @{ status = 'affected'; version = '3.0.0'; lessThanOrEqual = '3.2.0' }
            @{ status = 'affected'; version = '1.2-beta' }
            @{ status = 'affected'; version = '1.2.*' }
            @{ status = 'affected'; version = '1.2.3.4.5' }
            @{ status = 'affected'; version = 'Windows 10 for 32-bit Systems' }
            @{ status = 'affected'; version = '4.0.0'; lessThan = 'publication' }
            @{ status = 'affected'; version = '5.0.0'; lessThan = '6.0.0'; changes = @(@{ at = '5.5.0'; status = 'unaffected' }) }
            @{ status = 'unknown'; version = '8.0.0' }
            @{ status = ''; version = '8.1.0' }
        )
    } -Score 8.8

    Write-SyntheticCve -Id 'CVE-2026-0002' -Affected @{
        vendor = 'Example Corp'; product = 'Example Browser'; defaultStatus = 'unaffected'
        versions = @(@{ status = 'affected'; version = '2.0.0'; lessThan = '2.5.0' })
    } -Score 4.0

    Write-SyntheticCve -Id 'CVE-2026-0003' -Affected @{
        vendor = 'Example Corp'; product = 'Example Browser'; defaultStatus = 'unaffected'
        versions = @(@{ status = 'affected'; version = '7.0.0' })
    } -Score 3.0

    Write-SyntheticCve -Id 'CVE-2026-0004' -Affected @{
        vendor = 'Example Corp'; product = 'Example Browser'; defaultStatus = 'unaffected'
        versions = @(@{ status = 'affected'; version = '*' })
    } -Score 8.0

    Write-SyntheticCve -Id 'CVE-2026-0005' -Affected @{
        vendor = 'Example Corp'; product = 'Example Browser'; defaultStatus = 'unaffected'
        versions = @(@{
            status = 'affected'; version = '1.0.0'; lessThan = '5.0.0'
            changes = @(@{ at = '3.0.0'; status = 'unaffected' })
        })
    } -Score 8.0

    $script:kevFile = Join-Path $TestDrive 'kev.json'
    @{ vulnerabilities = @(@{ cveID = 'CVE-2026-0002' }) } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:kevFile -Encoding UTF8
    $script:epssFile = Join-Path $TestDrive 'epss.csv'
    @('#model_version: 2026-01-01', 'cve,epss,percentile', 'CVE-2026-0002,0.42,0.99') |
        Set-Content -LiteralPath $script:epssFile -Encoding UTF8
}

Describe 'ThreatJET CVE database builder' {
    It 'emits numeric ranges, inclusive upper bounds, and explicit unaffected exceptions' {
        $output = Join-Path $TestDrive 'numeric.csv'
        & $script:builder -CveListPath $script:feedRoot -OutputPath $output | Out-Null
        $rows = @(Import-Csv -LiteralPath $output)
        $first = @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0001' })
        $first.Count | Should -Be 4
        @($first | Where-Object { $_.vulnerable_spec -eq 'Ver: 1.0.0 to <2.0.0' }).Count | Should -Be 1
        @($first | Where-Object { $_.vulnerable_spec -eq 'Ver: 3.0.0 to <3.2.0' }).Count | Should -Be 1
        @($first | Where-Object { $_.vulnerable_spec -eq 'Ver: 3.2.0' }).Count | Should -Be 1
        @($first | Where-Object { $_.unaffected_spec -eq 'Ver: 1.5.0' }).Count | Should -Be 1
    }

    It 'does not emit wildcard or status-transition ranges by default' {
        $output = Join-Path $TestDrive 'strict.csv'
        & $script:builder -CveListPath $script:feedRoot -OutputPath $output | Out-Null
        $rows = @(Import-Csv -LiteralPath $output)
        @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0004' }).Count | Should -Be 0
        @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0005' }).Count | Should -Be 0
        @($rows | Where-Object { $_.vulnerable_spec -match '(beta|publication|Windows|8\.1|1\.2\.3\.4\.5)' }).Count | Should -Be 0
    }

    It 'keeps KEV records despite the CVSS threshold and enriches EPSS' {
        $output = Join-Path $TestDrive 'enriched.csv'
        & $script:builder -CveListPath $script:feedRoot -OutputPath $output -MinCvss 7 -KevPath $script:kevFile -EpssPath $script:epssFile | Out-Null
        $rows = @(Import-Csv -LiteralPath $output)
        $kev = @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0002' })
        $kev.Count | Should -Be 1
        $kev[0].kev | Should -Be 'TRUE'
        $kev[0].epss | Should -Be '0.42'
        @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0003' }).Count | Should -Be 0
    }

    It 'only emits no-version wildcard rows when explicitly opted in' {
        $output = Join-Path $TestDrive 'unversioned.csv'
        & $script:builder -CveListPath $script:feedRoot -OutputPath $output -IncludeNoVersion | Out-Null
        $rows = @(Import-Csv -LiteralPath $output)
        $wild = @($rows | Where-Object { $_.cve_id -eq 'CVE-2026-0004' })
        $wild.Count | Should -Be 1
        $wild[0].vulnerable_spec | Should -Be ''
    }
}
