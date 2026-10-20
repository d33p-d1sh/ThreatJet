# SPDX-License-Identifier: MIT
# ThreatJET - Build-TJETCveDatabase.ps1
# Copyright (c) 2026 Melvin Salyers (d33p-d1sh) - https://github.com/d33p-d1sh/ThreatJet
# Licensed under the MIT License; see LICENSE in the project repository.

<#
.SYNOPSIS
    Builds a ThreatJET-format CVE database (CSV) from a local copy of MITRE's cvelistV5.
.DESCRIPTION
    ThreatJET's offline CVE scan (-IncludeCVEScan) reads a module-free CSV with these
    columns:

        cve_id, product_name, vendor_name, vulnerable_spec, cvss

    where vulnerable_spec is one of:
        "Ver: X to <Y"   -> affected range  [X, Y)   (X inclusive, Y exclusive)
        "Ver: X"         -> exact affected version X

    This script walks a local checkout of the CVE Project's cvelistV5 repository (the
    official CVE record store, JSON 5.x) and flattens every affected product/version into
    those rows, picking the best CVSS base score it can find on each record.

    THIS RUNS ON YOUR WORKSTATION, not on an assessment target. It has no module
    dependencies and works on Windows PowerShell 5.1 and PowerShell 7.

    GET cvelistV5 FIRST (either one):
        # a) clone (large, ~GBs, full history):
        git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
        # b) or download a nightly release bundle (smaller, no history) and extract it:
        #    https://github.com/CVEProject/cvelistV5/releases  -> the *_all_CVEs_at_midnight.zip

    Point -CveListPath at the checkout root (the folder containing "cves") or directly at
    the "cves" folder.

.PARAMETER CveListPath
    Path to the cvelistV5 checkout root or its "cves" subfolder.
.PARAMETER OutputPath
    Where to write the CSV. Default .\cves.csv in the current directory.
.PARAMETER MinCvss
    Skip records whose best CVSS base score is below this (0 = keep all, including records
    with no CVSS). Use e.g. 7 to build a smaller "High and above" database.
.PARAMETER IncludeNoVersion
    Also emit a row for an affected product that lists no usable version (defaultStatus
    "affected" with no version detail). These match at LOW confidence in ThreatJET. Off by
    default to keep the database tighter.
.PARAMETER Limit
    Stop after processing this many CVE files (for a quick test run). 0 = no limit.
.EXAMPLE
    .\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves.csv
.EXAMPLE
    # A smaller database of only CVSS 7.0+ findings:
    .\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves_high.csv -MinCvss 7
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CveListPath,

    [string]$OutputPath = (Join-Path (Get-Location) 'cves.csv'),

    [ValidateRange(0, 10)]
    [double]$MinCvss = 0,

    [switch]$IncludeNoVersion,

    [int]$Limit = 0
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- locate cves/ ---
$cvesDir =
    if (Test-Path (Join-Path $CveListPath 'cves')) { Join-Path $CveListPath 'cves' }
    elseif ((Split-Path $CveListPath -Leaf) -eq 'cves') { $CveListPath }
    else { $CveListPath }   # assume the given path already holds CVE-*.json somewhere below

if (-not (Test-Path $cvesDir)) {
    throw "Could not find a CVE record folder under '$CveListPath'. Point -CveListPath at the cvelistV5 checkout root or its 'cves' folder."
}

Write-Host "Scanning $cvesDir for CVE records..." -ForegroundColor Cyan

# --------------------------------------------------------------------- helpers ---

# CSV-escape a single field: wrap in quotes, double any internal quotes. Keeps commas,
# quotes and newlines in product/vendor strings from breaking the file.
function ConvertTo-CsvField {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    return '"' + ($Value -replace '"', '""') + '"'
}

# Pull the best CVSS base score from a metrics array. Priority: v3.1 > v3.0 > v4.0 > v2.0;
# within the chosen version take the highest base score seen.
function Get-BestCvss {
    param($MetricsArrays)   # one or more metrics[] arrays (cna + adp)

    $byVer = @{ '31' = @(); '30' = @(); '40' = @(); '20' = @() }

    foreach ($metrics in $MetricsArrays) {
        if (-not $metrics) { continue }
        foreach ($m in @($metrics)) {
            if ($m.cvssV3_1 -and $null -ne $m.cvssV3_1.baseScore) { $byVer['31'] += [double]$m.cvssV3_1.baseScore }
            if ($m.cvssV3_0 -and $null -ne $m.cvssV3_0.baseScore) { $byVer['30'] += [double]$m.cvssV3_0.baseScore }
            if ($m.cvssV4_0 -and $null -ne $m.cvssV4_0.baseScore) { $byVer['40'] += [double]$m.cvssV4_0.baseScore }
            if ($m.cvssV2_0 -and $null -ne $m.cvssV2_0.baseScore) { $byVer['20'] += [double]$m.cvssV2_0.baseScore }
        }
    }

    foreach ($pref in '31','30','40','20') {
        if ($byVer[$pref].Count -gt 0) {
            return ([double](($byVer[$pref] | Measure-Object -Maximum).Maximum))
        }
    }
    return $null
}

# Turn one affected-product entry into zero or more vulnerable_spec strings.
function ConvertTo-Specs {
    param($Affected)

    $specs = New-Object System.Collections.Generic.List[string]
    $versions = @($Affected.versions)

    $emittedAny = $false

    foreach ($v in $versions) {
        if (-not $v) { continue }
        # Only versions explicitly marked affected (ignore 'unaffected' carve-outs).
        if ($v.status -and $v.status -ne 'affected') { continue }

        $ver = "$($v.version)".Trim()

        if ($v.lessThan) {
            # [ver, lessThan)  -> exactly ThreatJET's "Ver: X to <Y"
            $specs.Add("Ver: $ver to <$($v.lessThan)")
            $emittedAny = $true
        }
        elseif ($v.lessThanOrEqual) {
            # [ver, lessThanOrEqual] -- ThreatJET has no inclusive upper form, so emit the
            # range up to the endpoint PLUS an exact row for the endpoint itself.
            $specs.Add("Ver: $ver to <$($v.lessThanOrEqual)")
            $specs.Add("Ver: $($v.lessThanOrEqual)")
            $emittedAny = $true
        }
        elseif (-not [string]::IsNullOrWhiteSpace($ver) -and $ver -ne '*' -and $ver -ne 'n/a' -and $ver -ne 'unspecified') {
            # Single exact affected version.
            $specs.Add("Ver: $ver")
            $emittedAny = $true
        }
    }

    # Whole-product-affected (defaultStatus affected, no usable per-version detail).
    if (-not $emittedAny -and $Affected.defaultStatus -eq 'affected' -and $IncludeNoVersion) {
        $specs.Add('')   # empty spec -> ThreatJET treats as affected at LOW confidence
    }

    return $specs
}

# ------------------------------------------------------------------ enumerate ---
# [System.IO] enumeration streams the file list instead of building a giant array first,
# which matters on a tree of ~300k JSON files.
$files = [System.IO.Directory]::EnumerateFiles($cvesDir, 'CVE-*.json', [System.IO.SearchOption]::AllDirectories)

$writer = New-Object System.IO.StreamWriter($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
$writer.WriteLine('cve_id,product_name,vendor_name,vulnerable_spec,cvss')

$processed = 0
$rows      = 0
$skippedRejected = 0

try {
    foreach ($file in $files) {

        if ($Limit -gt 0 -and $processed -ge $Limit) { break }
        $processed++

        if (($processed % 5000) -eq 0) {
            Write-Host ("  processed {0:N0} records, wrote {1:N0} rows..." -f $processed, $rows) -ForegroundColor DarkGray
        }

        try {
            $json = Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch { continue }   # malformed or partial file: skip, don't abort the whole build

        $cveId = "$($json.cveMetadata.cveId)".Trim()
        if (-not $cveId) { continue }

        # Skip rejected/withdrawn records -- they are not actionable.
        if ("$($json.cveMetadata.state)" -eq 'REJECTED') { $skippedRejected++; continue }

        $cna = $json.containers.cna
        if (-not $cna) { continue }

        # CVSS from the CNA metrics and any ADP (enrichment) container metrics.
        $adpMetrics = @()
        if ($json.containers.adp) {
            foreach ($adp in @($json.containers.adp)) { if ($adp.metrics) { $adpMetrics += ,$adp.metrics } }
        }
        $cvss = Get-BestCvss -MetricsArrays (@(,$cna.metrics) + $adpMetrics)

        if ($MinCvss -gt 0) {
            if ($null -eq $cvss -or $cvss -lt $MinCvss) { continue }
        }

        $cvssField = if ($null -ne $cvss) { "$cvss" } else { '' }

        # Affected can live on the CNA and/or on ADP containers.
        $affectedAll = @()
        if ($cna.affected) { $affectedAll += @($cna.affected) }
        if ($json.containers.adp) {
            foreach ($adp in @($json.containers.adp)) { if ($adp.affected) { $affectedAll += @($adp.affected) } }
        }

        foreach ($aff in $affectedAll) {
            if (-not $aff) { continue }

            $product = "$($aff.product)".Trim()
            $vendor  = "$($aff.vendor)".Trim()

            # Skip entries with no usable product name or wildcard-everything.
            if ([string]::IsNullOrWhiteSpace($product) -or $product -eq '*' -or $product -eq 'n/a') { continue }
            if ([string]::IsNullOrWhiteSpace($vendor)) { $vendor = 'n/a' }

            foreach ($spec in (ConvertTo-Specs -Affected $aff)) {
                $writer.WriteLine( (@(
                    (ConvertTo-CsvField $cveId),
                    (ConvertTo-CsvField $product),
                    (ConvertTo-CsvField $vendor),
                    (ConvertTo-CsvField $spec),
                    (ConvertTo-CsvField $cvssField)
                ) -join ',') )
                $rows++
            }
        }
    }
}
finally {
    $writer.Flush()
    $writer.Dispose()
}

Write-Host ''
Write-Host ("Done. {0:N0} CVE record(s) processed, {1:N0} rejected and skipped." -f $processed, $skippedRejected) -ForegroundColor Green
Write-Host ("Wrote {0:N0} product/version row(s) to:" -f $rows) -ForegroundColor Green
Write-Host "    $OutputPath"
Write-Host ''
Write-Host "Point ThreatJET at it:" -ForegroundColor Gray
Write-Host "    Invoke-ThreatJetAssessment -IncludeCVEScan -CVEDatabasePath '$OutputPath'" -ForegroundColor White
Write-Host "  (or set CVEDatabasePath in Config.ps1 / the menu)" -ForegroundColor Gray
