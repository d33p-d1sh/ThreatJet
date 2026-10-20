# Validation

Run in order. Each stage gates the next.

## Stage 0 — Syntax check (seconds, always first)

```powershell
.\Tests\Test-Syntax.ps1
```

Parses every file with PowerShell's own parser and reports **all** syntax errors at
once with line numbers. `Import-Module` stops at the first bad file and buries the
cause under dozens of "command not recognized" cascades; this does not.

On Linux/macOS CI without a PowerShell runtime, `python3 Tests/Check-Syntax.py` is a
heuristic fallback. `Test-Syntax.ps1` is authoritative.

## Stage 1 — Offline smoke test (no domain, ~10 seconds)

```powershell
.\Tests\Invoke-SmokeTest.ps1
.\Tests\Invoke-SmokeTest.ps1 -KeepArtifacts   # keep generated CSVs
```

Runs a syntax gate, then module load, then the full offline pipeline against
synthetic data: 20 detections, the finding contract, HTML-injection escaping, and
baseline key collisions. Aborts early if the module fails to import rather than
emitting a cascade.

**Exit 0 = proceed. Exit 1 = stop and fix.**

## Stage 2 — Static analysis

```powershell
Install-Module PSScriptAnalyzer -Force
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error
```

Expect warnings about `Collect-*` verbs not being on the approved list. These are
private functions; it is cosmetic.

## Stage 3 — Lab domain

```powershell
Invoke-ThreatJetAssessment -Path C:\LabAudit -OpenReport
```

Use a lab with **known** weaknesses so you can verify the tool finds what you planted.

### Fields never validated against live AD

Inspect these in the CSVs by hand before trusting findings:

1. **`Retrieval_Principals`** in `AD_ServiceAccounts_Audit.csv` — does
   `PrincipalsAllowedToRetrieveManagedPassword` serialise as a friendly name, a DN,
   or a SID? GMSA-001 matches on *names*. If your AD emits DNs or SIDs, the pattern
   in `Invoke-GMSAFindings.ps1` needs a branch. **Highest-risk field.**
2. **`AppliesTo` / `AppliesTo_Names`** in `AD_FGPP_Audit.csv` — parsing assumes `CN=Name,...`.
3. **`Rights`** in `AD_ACL_Audit.csv` — confirm values match the detector regex.
4. **`Is_Domain_Controller`** — an RODC must read `True` (PrimaryGroupID 521).
5. **Header completeness** — confirm derived columns such as
   `Potentially_Privileged_Direct` actually appear.

### Sanity checks

- **Zero findings on a real domain means the tool is broken**, not that the domain is
  perfect. Check the collection summary and correlation log.
- Watch for `No privileged principals identified` — that means six detections are
  silently disabled.
- Everything Critical is equally suspect; check for a mis-scoped detector.

## Stage 4 — Baseline drift

```powershell
Invoke-ThreatJetAssessment -Path C:\LabAudit2 `
    -BaselinePath C:\LabAudit\AD_Assessment_Findings.csv
```

Confirm the remediated item shows as `RESOLVED` and nothing else moved.

## Stage 5 — Production

Only after all of the above. Coordinate with the AD team, prefer off-peak, start with
`-AclMode Targeted`, treat the output directory as sensitive.
