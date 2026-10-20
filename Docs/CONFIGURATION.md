# Configuration

All tunable values live in `Private/Config.ps1` as a single hashtable.

```powershell
$script:TJETConfig = @{
    CollectorVersion                 = "2.1.2"
    CorrelationVersion               = "2.1.2"
    SchemaVersion                    = "1.2"
    PrivilegedPasswordBaselineLength = 14
    KrbtgtWarningDays                = 365
    KrbtgtCriticalDays               = 730
    MachineAccountQuotaThreshold     = 0
    Encoding                         = "UTF8"
}
```

## What to tune

### `PrivilegedPasswordBaselineLength` (default 14)
Drives **ID-011**. Set it to the standard you are assessing against, not an
aspiration — otherwise every privileged account produces a finding and the report
loses signal.

| Context | Typical |
|---|---|
| DoD / high security | 15–16 |
| Commercial baseline | 14 |
| Legacy environment | 12 |

### `KrbtgtWarningDays` / `KrbtgtCriticalDays` (365 / 730)
Drives **DOM-001**. Lower these if you have a formal rotation schedule.

### `MachineAccountQuotaThreshold` (0)
Drives **DOM-005**. Anything above this is flagged; 0 is the hardened state.

## Versioning fields

`CollectorVersion`, `CorrelationVersion` and `SchemaVersion` are stamped on every
finding. **Bump them when you change detection logic.** Without that, a finding
appearing or disappearing between assessments is ambiguous: you cannot tell whether
the environment changed or the tool did.

## Adding or refining ATT&CK / detection guidance

The mapping lives in one place: `Private/Get-TJETFindingMetadata.ps1`, keyed by
Finding_ID. Enrichment is applied at export time in `Export-Findings`, so detectors
need no changes and two detectors emitting the same ID cannot disagree.

To add a technique mapping, add an entry with `Attack`, `Mitre` and `Detect` keys. The
smoke test asserts that every emitted Finding_ID has a mapping and that technique IDs
are well formed, so an unmapped detection fails the build.

## Adding a detection

1. Collect the attribute in the relevant `Collectors\Collect-*.ps1`.
2. Detect in the relevant `Correlation\Invoke-*Findings.ps1`.
3. **Emit through `New-Finding`** — never hand-build a `[PSCustomObject]`. The factory
   enforces the output contract; bypassing it produces missing columns that misalign
   the CSV.
4. Add a fixture and assertion to `Tests\Invoke-SmokeTest.ps1`.
5. Document it in `Docs\FINDINGS.md`.
6. Bump `CorrelationVersion`, and `SchemaVersion` if columns changed.

**The rule that matters:** a field consumed by correlation must be produced by a
collector. That contract breaking silently is this codebase's most common historical
failure — the detector runs, finds nothing, and the report looks clean. The
"no privileged principals identified" warning exists to catch exactly that.

## Syntax constraint worth knowing

PowerShell continues a line that **ends** with a binary operator, but cannot resume a
finished expression with one. This is a parse error that takes down the whole module:

```powershell
if (
    ($a -is [string])
    -and                      # WRONG: parse error
    ($b -isnot [int])
) { }
```

```powershell
if (
    ($a -is [string]) -and    # correct
    ($b -isnot [int])
) { }
```

Run `Tests\Test-Syntax.ps1` after editing. It reports every syntax error across all
files at once.
