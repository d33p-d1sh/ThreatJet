# ThreatJet — Evaluation of the Modular Refactor

**Verdict: the refactor's architecture is a clear improvement, but the version as
submitted could not run at all.** Four defects were fatal; several more meant
detections silently produced nothing. All are fixed below.

The structure (Private / Collectors / Correlation / Reporting / Public, config object,
finding factory, logging, context builder) is genuinely better than the monolith it
replaces. The problems are wiring and contract breaks introduced during the split.

---

## Blockers — the module could not function

### B1. Three of five code directories were never loaded  *(fatal)*

`ThreatJet.psm1` dot-sourced only `Private\` and `Public\`. `Collectors\`,
`Correlation\` and `Reporting\` were never loaded, so **every** collector, **every**
detector and the entire reporting layer were undefined at runtime.

`Export-ThreatJetData` would fail on its first `& $collector.Function` call;
`Invoke-ThreatJetCorrelation` would fail on every detector and then on
`Export-Findings`.

**Fixed:** explicit ordered load (`Private` → `Collectors` → `Correlation` →
`Reporting` → `Public`), with a hard `throw` on any file that fails to load. A
silently unloaded detector is indistinguishable from "no findings", so load failures
must be loud.

### B2. Invalid GUID in the manifest  *(fatal)*

`GUID = 'REPLACE-WITH-NEW-GUID'` is not parseable. `Import-Module .\ThreatJet.psd1`
— the exact command in the README — fails immediately.

**Fixed:** real GUID generated.

### B3. Two referenced collectors did not exist  *(fatal for the flagship finding)*

`Export-ThreatJetData` dispatches to `Collect-ACLs` and `Collect-GPOs`. Neither
file existed. So `AD_ACL_Audit.csv` was never produced, `Import-AssessmentData` then
failed on the missing file, and **PATH-001 — the attack-path finding this framework
exists for — had no data and could never fire.**

**Fixed:** both collectors written, emitting exactly the field names the detectors
consume.

### B4. Parse error in `Invoke-FGPPFindings.ps1`  *(fatal for that file)*

```powershell
[int]$pso.MinPasswordLength -
lt
[int]$pso.Domain_Default_MinLength
```

`-lt` was split across two lines. This does not parse. The file could not be loaded,
so **DOM-006 and ID-011 were absent from every assessment.**

**Fixed:** rewritten as a single-line comparison via `ConvertTo-Int`.

---

## Silent-failure defects — code runs, detections never fire

These are the dangerous class: no error, no output, and an assessment report that
looks clean because the detector is inert.

### S1. `Potentially_Privileged_Direct` was consumed but never produced

`New-TJETContext` builds the privilege model by filtering
`$_.Potentially_Privileged_Direct -eq "True"`. **`Collect-Users` never set that
field.** The user half of `PrivilegedSIDs`/`PrivilegedGUIDs` was therefore always
empty, disabling ID-009, ID-011 and the user side of PATH-001.

This is the identical failure mode to the original PATH-002 defect: a field consumed
on one side of the CSV boundary and never produced on the other.

**Fixed:** computed in `Collect-Users` (container-independent group-name match plus
RID-500). Accounts with `adminCount=1` are now also treated as privileged — residual
privilege is exactly the case worth catching.

### S2. `Is_Empty_Privileged` never produced → GRP-001 dead
### S3. `Applies_To_Privileged_Name_Match` never produced → DOM-006 never escalated

**Fixed:** both produced by their collectors.

### S4. `Resolve-PrincipalRiskContext` was defined but never called

The principal resolver — the primitive that keeps Tier 0 determination consistent —
existed in `Private\` and had zero callers. DOM-006 instead relied on the raw name
heuristic.

**Fixed:** DOM-006 now resolves `AppliesTo` names to group SIDs through the resolver
and only falls back to the name heuristic when nothing resolves. Confidence tracks
that certainty (High when SID-resolved, Medium on fallback); severity still tracks
impact.

### S5. Trusts collected, never correlated

`Collect-Trusts` ran and wrote a CSV. **No trust detector existed** and none was
registered. A trust without SID filtering is a direct cross-domain escalation path.

**Fixed:** `Invoke-TrustFindings` (DOM-004) added and registered.

### S6. ID-011 keyed the baseline off `$fgpp[0]`

The privileged-password-baseline check read `Domain_Default_MinLength` from the first
PSO. A domain with a weak default and **no PSOs at all** — the worst case — returned
early and produced nothing.

**Fixed:** reads `MinPwdLength` from the domain summary (newly collected) and runs
independently of whether any PSO exists.

---

## Coverage regressions — data collected, never evaluated

The following attributes were being collected and had **no consumer whatsoever**.
Collecting an attribute and never evaluating it is equivalent to not collecting it,
while costing the same query time and creating the same sensitive-data exposure.

| Data collected | Was unused | Now |
|---|---|---|
| `ServicePrincipalNames` | yes | ID-001 Kerberoasting |
| `msDS-AllowedToDelegateTo` | yes | ID-002 constrained delegation |
| `TrustedForDelegation` (user) | yes | ID-004 unconstrained delegation |
| `SIDHistory` | yes | ID-005 (namespace-aware, whole-SID) |
| staleness | yes | ID-006 dormant privileged account |
| `PasswordNotRequired` | yes | ID-010 |
| `Has_RBCD_Configured` | yes | INF-002 |
| `Has_LAPS` | yes | INF-003 |
| `OperatingSystem` | yes | INF-004 unsupported OS |
| trusts | yes | DOM-004 |
| GPO data | not collected | GPO-001/002/003 |

Detections went from **9 to 24**.

---

## Security defect in the reporting layer

### HTML injection in `New-ThreatJetReport`

Finding fields — `Target`, `Finding`, `Evidence` — were interpolated raw into the
HTML report. AD object names, descriptions and DNs are attacker-influenceable: a
low-privileged user who can name an object can inject script into the assessment
report an administrator later opens.

The monolithic version encoded these with `[System.Net.WebUtility]::HtmlEncode`;
the refactor dropped it.

**Fixed:** all interpolated fields HTML-encoded, and the severity CSS class
whitelisted. The smoke test asserts a `<script>` payload comes back escaped.

---

## Correctness and robustness fixes

| Issue | Fix |
|---|---|
| `Test-Tier0Sid` dropped RIDs 502, 517 and built-in 552 | restored |
| `Import-AssessmentData` unguarded — missing file gave a raw error and a null property | each source optional and logged; degrades one detector, not the run |
| Domain summary crashed when `krbtgt.PasswordLastSet` was null | null-safe, returns `Unknown` |
| `New-Finding` had `Severity` optional with no default | `Severity`, `Category`, `Target`, `Finding` all mandatory |
| `Compare-ThreatJetBaseline` reported only NEW/REMOVED — "no change" and "failed" looked alike | reports NEW / RESOLVED / PERSISTENT plus a summary; excludes Info |
| `Export-ThreatJetJSON` and `New-AssessmentSummary` defined but never called or exported | JSON now emitted by correlation; both exported |
| `Compare-ThreatJetBaseline` in manifest but not in `Export-ModuleMember` | exported |
| `ActiveDirectory`/`GroupPolicy` as hard `RequiredModules` blocked offline correlation on non-RSAT workstations | removed from manifest; checked at call time in collectors |
| README documented `-InputDirectory`; functions use `-InDir` / `-InputPath` | README corrected |
| Disabled users/computers evaluated, producing noise from stale flags | skipped |
| `Tests\` and `Docs\` empty | smoke test and this document added |

---

## Retained deliberately

- **Deny ACEs are still collected.** `AccessType` is preserved as evidence and
  correlation decides actionability. Filtering at collection would discard evidence.
- **DOM-006 compares against the domain default, not an absolute number.** A 20-char
  PSO in a 12-char domain is not a finding.
- **gMSA breadth, not privilege, drives GMSA-001.** Retrieval by a Tier 0 group is
  expected; retrieval by `Domain Users` is the misconfiguration.
- **ID-011 remains direct-assignment only,** with Confidence=Medium and explicit
  evidence text. Group-based PSO inheritance is genuinely not resolved yet.

---

## Validation status — read this before trusting output

**None of this has been executed.** It was authored and reviewed statically; no
PowerShell runtime or AD environment was available. Verified statically:

- every function reference resolves (no missing collectors or detectors)
- every field consumed by correlation is produced by a collector
- all files brace/paren balanced; no residual split-operator hazards
- no `Describe`-scope phase-boundary issues

**Run `Tests\Invoke-SmokeTest.ps1` first.** It needs no domain, takes seconds, and
checks manifest validity, module load, all five directories loading, 20 detections
firing, the finding contract, HTML-injection escaping, and baseline key collisions.

Then, on a **lab** domain, verify these fields — they have never touched real AD and
are the most likely to need adjustment:

1. **`Retrieval_Principals`** — how `PrincipalsAllowedToRetrieveManagedPassword`
   stringifies (friendly name vs DN vs SID). GMSA-001 matches on names; if AD emits
   DNs or SIDs, the pattern needs a branch. *Highest-risk field.*
2. **`AppliesTo` parsing** in `Collect-FGPP` — assumes `CN=Name,...`.
3. **ACL `Rights` values** from `Get-Acl "AD:..."` against the detector regex.
4. **RODC** should report `Is_Domain_Controller = True` (PrimaryGroupID 521).
