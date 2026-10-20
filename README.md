# ThreatJET — Jumbo Evaluation Toolkit

A **read-only, RSAT-free** PowerShell security assessment for Active Directory and the
Windows hosts within it. Point it at a domain and it collects configuration over
LDAP/ADSI, correlates the weaknesses into **real attack paths to Tier 0**, scans installed
software against an **offline CVE database**, and produces an interactive HTML report plus
a **safety-guarded remediation** script.

It ships as a **single self-contained `.ps1`** you can drop on a hardened jump box or
assessment laptop and run — no module install, no RSAT, no internet.

> **Collection is read-only.** The toolkit never writes to Active Directory. Generated
> remediation commands are guarded (`-WhatIf` or commented out) and never run on their own.

---

## Why it exists

AD compromise is rarely one catastrophic setting — it's dozens of small ones that *chain*
from an ordinary account to Domain Admin. ThreatJET is built around the useful questions:
**which weaknesses actually connect into a path to Tier 0, what single fix breaks the most
paths, and exactly what command fixes each finding** — while being honest about how much of
the directory it actually managed to read.

## Highlights

- **RSAT-free collection** over `System.DirectoryServices` (ADSI/LDAP). GPO settings are
  parsed straight from SYSVOL, so the `ActiveDirectory`/`GroupPolicy` modules are optional
  accelerators, never requirements.
- **Attack-path analysis** — builds a control graph (membership + ACL + delegation) and
  traces paths from non-privileged principals to Tier 0, then reports **choke points**
  (the node that cuts the most paths) and **blast radius** (the account that reaches the
  most Tier 0 targets).
- **Multi-signal privilege model** so a Domain Admin can't be misclassified by a single
  data glitch, and a Tier 0 group member is never reported as its own "attack path".
- **Offline CVE scan with no external modules** — reads a CSV/JSON CVE database natively,
  aggregates results **per product**, and ranks them by **CVSS** in their own panel so they
  never bury the configuration findings.
- **Trust signals built in** — per-area coverage status (so a clean-looking report with
  failed collection is flagged, not trusted), fail-closed suppression of accepted risks
  with expiry, baseline drift between runs, and a run manifest + human-readable run ID.
- **ATT&CK-mapped findings** — each finding carries the offensive technique, its MITRE
  ATT&CK ID, blue-team detection guidance, and a remediation with prerequisite/rollback.
- **Interactive HTML report** — sortable, filterable, self-contained (opens from an email
  attachment), plus machine-readable CSV/JSON exports.

---

## Requirements

| Stage | Needs |
|---|---|
| **AD collection / correlation / reporting** | Windows, PowerShell 5.1+, a domain user context (or `-Credential`), and network reach to a DC. **No RSAT.** |
| **Local-host checks** | PowerShell 5.1+. No domain needed. Some checks return richer results elevated. |
| **Offline CVE scan** (opt-in) | A CVE database as `.csv` or `.json` (no module). A `.db`/`.sqlite` database is supported only as an optional fast path if the `PSSQLite` module happens to be installed. |

The `ActiveDirectory`/`GroupPolicy` modules are used automatically **if present** (a richer
inventory projection) and fall back to ADSI when absent. They are never required.

---

## Quick start

```powershell
# On the target host:
Get-ChildItem . | Unblock-File          # clear MOTW if copied from a share
. .\ThreatJet.ps1            # dot-source to load the commands
Show-TJETMenu                           # interactive, guided run
```

Or run it directly:

```powershell
# From a non-domain / local account, pin the DC and supply credentials:
Invoke-ThreatJetAssessment -Server dc01.corp.local -Credential (Get-Credential) -OpenReport

# Standard run in the current domain context:
Invoke-ThreatJetAssessment -OpenReport
```

### Profiles

A profile bundles sensible options so you don't have to remember switches:

```powershell
Invoke-ThreatJetAssessment -Profile Quick       # AD only, targeted ACLs, fast triage
Invoke-ThreatJetAssessment -Profile Standard    # AD + local host + attack paths (default)
Invoke-ThreatJetAssessment -Profile Deep        # everything: full ACLs, inventory, CVE
Invoke-ThreatJetAssessment -Profile Identity    # AD + attack paths, identity-focused
Invoke-ThreatJetAssessment -Profile Endpoint    # local host + software + CVE only (no domain)
Invoke-ThreatJetAssessment -Profile PurpleTeam  # AD + attack paths, ATT&CK-focused
```

Any explicit parameter overrides the profile.

### Scoping and re-analysis

```powershell
Invoke-ThreatJetAssessment -Scope LocalHost                     # local privesc only, no AD
Invoke-ThreatJetAssessment -Scope AD,AttackPath                 # AD + path tracing
Invoke-ThreatJetAssessment -ADObjectType Users,Groups           # only certain object types
Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -SkipCollection    # re-correlate existing data
Invoke-ThreatJetAssessment -Path C:\Audit\Q3 `
    -BaselinePath C:\Audit\Q2\AD_Assessment_Findings.csv        # drift vs. a prior run
```

Large or multi-domain estates: pin a DC with `-Server`, pace with `-ThrottleMs`, and note
that an unattended run against a very large directory stops unless `-ForceLargeEnvironment`
is passed (so a scheduled job can't accidentally hammer a production DC).

---

## Attack-path analysis

ThreatJET models who-can-control-what as a directed graph and traces control paths to
Tier 0:

- **PATH-001/002/003** — direct dangerous rights over Tier 0 objects (delegated ACLs,
  AdminSDHolder backdoors, widespread stamping).
- **PATH-GRAPH** — genuine *multi-hop* chains a single-ACE check can't see
  (`userA -[GenericAll]-> HelpDesk -[MemberOf]-> Domain Admins`).
- **PATH-CHOKE** — the intermediate node the most paths run through: "fix this one thing
  first."
- **PATH-BLAST** — the source principal that reaches the most Tier 0 targets: "this is the
  account to lock down."

The traced paths, choke-point ranking and blast-radius ranking are also written as CSVs for
pivoting or loading into a graph tool.

---

## Offline CVE scanning (no modules)

Enable with `-IncludeCVEScan` and point `-CVEDatabasePath` at a CVE database. The format is
chosen by extension and `.csv`/`.json` are read with native PowerShell — no install on the
target:

```
cve_id, product_name, vendor_name, vulnerable_spec[, cvss]
```

`vulnerable_spec` is `Ver: X to <Y` (range `[X, Y)`) or `Ver: X` (exact); `cvss` is an
optional base score that drives severity and ranking. Results are **aggregated per product**
and shown in a dedicated, **CVSS-ranked "Vulnerable Software" panel**, kept out of the
posture dashboard so a wall of CVEs can't bury the configuration findings. Full per-CVE
detail is written to `CVE_By_Product.csv` and `CVE_Matches.csv`.

Build the database from MITRE's cvelistV5 with the included tool:

```powershell
# one-off, on your workstation:
.\Tools\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves.csv -MinCvss 7
```

---

## Output

| File | Contents |
|---|---|
| `ThreatJet_Report.html` | Interactive report: severity cards, findings, attack-path insights, Vulnerable Software panel, coverage |
| `AD_Assessment_Findings.csv` / `.json` | Findings with RunId, type, ATT&CK mapping and detection guidance |
| `ATTACK_Coverage.csv` | Techniques the domain is exposed to, active vs. suppressed, with max severity |
| `Remediation_Report.html` / `Remediation_Script.ps1` | Fix list and a guarded, review-before-run change script |
| `Assessment_Summary.csv` | Posture counts by severity, plus separate vulnerability tallies |
| `Coverage.json` | Per-area collection status (Successful / Incomplete / Failed) |
| `Run_Manifest.json` | Who ran it, from where, against which DC, when, and what it produced |
| `CVE_By_Product.csv` / `CVE_Matches.csv` | Vulnerable software, per product and per CVE |
| `Baseline_Comparison.csv` | Drift vs. a baseline (New / Resolved / Persistent / Regressed / Improved) |
| `Attack_Paths.csv` + choke/blast CSVs | Traced paths and their rankings |
| `AD_*_Audit.csv` | Collected source data |
| `Inventory\` | With `-IncludeInventory`: every object, every property, plus normalised `REL_*` edge lists |

Every finding carries: **Finding/Evidence** (what, on what), **Attack_Technique** (red),
**MITRE_Technique** (ATT&CK ID), **Detection_Guidance** (blue), **Recommendation**, and
independent **Severity** (impact) and **Confidence** (certainty).

---

## Reading the results

**Severity** is impact if real; **Confidence** is certainty — they're independent.

1. Critical + High confidence → act now.
2. Critical/High + Medium confidence → verify, then act.
3. Medium → schedule. Low/Info → track.

Then check the **Assessment Coverage** panel. A report with few findings but a failed or
incomplete collection area is **not** a clean environment — it's an incomplete scan. A
scanner reporting zero findings on a real domain is more likely broken than accurate.

---

## Building the single-file distributable

The structured module under source control is the source of truth; the standalone is
generated from it:

```powershell
.\Build\Build-SingleFile.ps1          # -> dist\ThreatJet.ps1
.\Tests\Invoke-AllTests.ps1           # regression suite (also checks the build is fresh)
```

The standalone embeds a content hash of the source; `Test-BuildFresh.ps1` flags a stale
build so you never review or run out-of-date code.

---

## Limitations

- **Single domain per run.** For a forest, run once per domain.
- **Attack-path model is the control plane** (ACL / membership / delegation). It does not
  collect sessions (BloodHound's `HasSession`), so session-based paths aren't modeled.
- **ACL collection defaults to `Targeted`;** `-AclMode Full` is thorough but slow.
- **Inventory uses `-Properties *`** and is the slowest, largest part of a run.
- **Local-host checks are detection-only** — they report that a credential store exists and
  is reachable; they never decrypt or print its contents.
- **The report never prints a discovered secret** — only the object, attribute and a
  redacted preview.
- **CVE matching is conservative** and version-aware; an unparseable version is reported at
  low confidence rather than dropped or over-claimed.
- **Detection guidance assumes auditing is configured** (e.g. 4662 needs a SACL).

## Operational cautions

- Read-only, but **not zero-impact** — it enumerates every object. Coordinate before a
  production run and prefer off-peak; pin a DC with `-Server`.
- **Output is highly sensitive** — the inventory is a complete map of the directory's
  privilege structure. Encrypt at rest, restrict access, delete when the engagement ends.
- Directory **read** access is sufficient; Domain Admin is not required.

---

## Documentation

| Document | Purpose |
|---|---|
| [Docs/TOOLKIT.md](Docs/TOOLKIT.md) | The assessment surfaces and how they fit together |
| [Docs/FINDINGS.md](Docs/FINDINGS.md) | Every finding: meaning, ATT&CK mapping, remediation |
| [Docs/INVENTORY.md](Docs/INVENTORY.md) | Inventory schema and worked analysis examples |
| [Docs/VALIDATION.md](Docs/VALIDATION.md) | How to validate before trusting output |
| [Docs/CONFIGURATION.md](Docs/CONFIGURATION.md) | Tuning thresholds and baselines |

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Melvin Salyers ([d33p-d1sh](https://github.com/d33p-d1sh)).

The published single-file `ThreatJet.ps1` carries the full MIT notice in its header, so the
license travels with the file on its own.

---

*ThreatJET is an assessment tool. Run it only against environments you are authorized to
test.*
