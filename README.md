# ThreatJET — Jumbo Evaluation Toolkit

A **read-only, RSAT-free** PowerShell security assessment for Active Directory and the
Windows hosts within it. Point it at a domain and it collects configuration over
LDAP/ADSI, correlates the weaknesses into **real attack paths to Tier 0**, scans installed
software against an **offline CVE database**, and produces an interactive HTML report plus
a **safety-guarded remediation** script.

It ships as a **single self-contained `ThreatJet.ps1`** you can drop on a hardened jump box
or assessment laptop and run — no module install, no RSAT, no internet.

> **Collection is read-only.** The toolkit never writes to Active Directory. Generated
> remediation commands are guarded (`-WhatIf` or commented out) and never run on their own.
> **Run it only against environments you are authorized to assess.**

---

## Contents

- [What it is](#what-it-is)
- [Requirements](#requirements)
- [Install and quick start](#install-and-quick-start)
- [Usage](#usage)
- [Viewing attack paths](#viewing-attack-paths)
- [Offline CVE scanning](#offline-cve-scanning)
- [Suppressing accepted risks](#suppressing-accepted-risks)
- [Baseline comparison](#baseline-comparison)
- [Output files](#output-files)
- [Reading the results](#reading-the-results)
- [Findings catalogue](#findings-catalogue)
- [Configuration](#configuration)
- [Before you trust the output](#before-you-trust-the-output)
- [Limitations](#limitations)
- [Operational cautions](#operational-cautions)
- [License](#license)

---

## What it is

AD compromise is rarely one catastrophic setting — it's dozens of small ones that *chain*
from an ordinary account to Domain Admin. ThreatJET is built around the useful questions:
**which weaknesses actually connect into a path to Tier 0, what single fix breaks the most
paths, and exactly what command fixes each finding** — while being honest about how much of
the directory it actually managed to read.

It assesses four surfaces in one run:

1. **Active Directory** — users, computers, groups, GPOs, ACLs, trusts, FGPP, gMSA, ADCS,
   domain summary. Detectors cover identity risk, delegation, privilege, password hygiene,
   trusts, Group Policy and Tier 0 ACL exposure. Collection is over `System.DirectoryServices`
   (ADSI/LDAP); GPO settings are parsed straight from SYSVOL, so **no RSAT is required**.
2. **Local host** (WinPEAS-style) — unquoted/modifiable services, AlwaysInstallElevated,
   writable PATH, autoruns, stored credentials, dangerous token privileges, UAC, credential
   protection, SMB signing, legacy protocols, and ~16 extended checks. Detection only; no AD
   needed; benefits from an elevated session.
3. **Attack-path graph** (BloodHound-style) — a control graph of membership + ACL +
   delegation edges, traced from non-privileged principals to Tier 0, with **choke-point**
   and **blast-radius** analysis.
4. **Object inventory** (optional) — every AD object with every property, plus normalised
   relationship edge lists.

Every finding carries an **offensive technique**, its **MITRE ATT&CK ID**, **blue-team
detection guidance**, and ordered **remediation steps** — so the output drives both
remediation and detection engineering.

---

## Requirements

| Stage | Needs |
|---|---|
| **AD collection / correlation / reporting** | Windows, PowerShell 5.1+, a domain user context (or `-Credential`), and network reach to a DC. **No RSAT.** |
| **Local-host checks** | PowerShell 5.1+. No domain needed. Some checks return richer results when elevated. |
| **Offline CVE scan** (opt-in) | A CVE database as `.csv` or `.json` (no module). A `.db`/`.sqlite` database works only as an optional fast path if the `PSSQLite` module happens to be installed. |

The `ActiveDirectory` / `GroupPolicy` modules are used automatically **if present** (a richer
inventory projection) and fall back to ADSI when absent. They are never required.

---

## Install and quick start

`ThreatJet.ps1` is the whole tool. Copy it to the host and dot-source it.

```powershell
# clear Mark-of-the-Web if the file came from a share or download:
Unblock-File .\ThreatJet.ps1

# load the commands:
. .\ThreatJet.ps1

# guided, interactive run:
Show-TJETMenu
```

Or run it directly:

```powershell
# Standard run in the current domain context, open the report when done:
Invoke-ThreatJetAssessment -OpenReport

# From a non-domain or local account, pin the DC and supply domain credentials:
Invoke-ThreatJetAssessment -Server dc01.corp.local -Credential (Get-Credential) -OpenReport
```

> Running from a **local account** (e.g. `localuser`) with no domain identity will fail the
> ADSI bind — supply `-Server <dc-fqdn>` and `-Credential` with any domain user (read access
> is enough; Domain Admin is not required).

---

## Usage

### Profiles

A profile bundles sensible options so you don't have to remember switches. Any explicit
parameter overrides the profile.

```powershell
Invoke-ThreatJetAssessment -Profile Quick       # AD only, targeted ACLs, fast triage
Invoke-ThreatJetAssessment -Profile Standard    # AD + local host + attack paths (default)
Invoke-ThreatJetAssessment -Profile Deep        # everything: full ACLs, inventory, CVE
Invoke-ThreatJetAssessment -Profile Identity    # AD + attack paths, identity-focused
Invoke-ThreatJetAssessment -Profile Endpoint    # local host + software + CVE only (no domain)
Invoke-ThreatJetAssessment -Profile PurpleTeam  # AD + attack paths, ATT&CK-focused
```

### Key parameters

| Parameter | Purpose |
|---|---|
| `-Path <dir>` | Output folder. Defaults to `ThreatJet_<timestamp>` in the current directory. |
| `-Profile <name>` | Preset option bundle (see above). |
| `-Scope <list>` | `All` (default), `AD`, `LocalHost`, `AttackPath`, `Inventory`. |
| `-ADObjectType <list>` | Restrict AD collection: `Users,Computers,Groups,ServiceAccounts,GPOs,ACLs,Trusts,FGPP,Domain,ADCS`. |
| `-AclMode <Targeted\|Full>` | `Targeted` (default, fast) or `Full` (exhaustive, slow). |
| `-Server <fqdn>` | Pin a specific domain controller instead of letting the DC locator choose. |
| `-Credential <pscred>` | Alternate credentials for directory queries. |
| `-IncludeInventory` | Also export every object with every property (large, slow). |
| `-DataminePasswords` | Scan the filesystem for stored credentials (reads file contents). |
| `-IncludeCVEScan` | Run the offline CVE scan (needs a CVE database). |
| `-CVEDatabasePath <file>` | Path to the CVE database (`.csv` / `.json` / `.db`). |
| `-BaselinePath <csv>` | Compare against a prior `AD_Assessment_Findings.csv`. |
| `-SuppressionPath <json>` | Apply an approved-exceptions file. |
| `-ThrottleMs <n>` | Pause between per-object operations (courtesy pacing on busy DCs). |
| `-ForceLargeEnvironment` | Proceed unattended against a very large directory without prompting. |
| `-SkipCollection` | Re-correlate and re-report existing data in `-Path` (offline, no DC). |
| `-OpenReport` | Open the HTML report when the run finishes. |

### Common runs

```powershell
# Re-analyse already-collected data (offline, no DC contact):
Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -SkipCollection

# Only certain object types:
Invoke-ThreatJetAssessment -ADObjectType Users,Groups

# AD plus attack-path tracing, skipping the local host:
Invoke-ThreatJetAssessment -Scope AD,AttackPath

# Full local-host review with credential datamine and CVE scan (no domain needed):
Invoke-ThreatJetAssessment -Scope LocalHost -DataminePasswords -IncludeCVEScan
```

Large or multi-domain estates: pin a DC with `-Server`, pace with `-ThrottleMs`, and note
that an **unattended** run against a very large directory stops unless `-ForceLargeEnvironment`
is passed, so a scheduled job can't accidentally hammer a production DC. **One domain per
run** — for a forest, run once per domain.

### Available commands

Dot-sourcing `ThreatJet.ps1` exposes:

| Command | Does |
|---|---|
| `Show-TJETMenu` | Interactive front end over everything below. |
| `Invoke-ThreatJetAssessment` | The full pipeline: collect → correlate → report. |
| `Export-ThreatJetData` | Collection only. |
| `Export-ADObjectInventory` | Full object inventory only. |
| `Invoke-ThreatJetCorrelation` | Correlate existing collected data (offline). |
| `New-ThreatJetReport` | Build the HTML report from existing findings. |
| `New-TJETRemediationReport` | Build the remediation report + guarded script. |
| `Find-TJETAttackPath` | Trace and print attack paths from an existing collection. |
| `Compare-ThreatJetBaseline` | Diff two assessments. |
| `New-AssessmentSummary` / `Export-ThreatJetJSON` | Summary and JSON exports. |

---

## Viewing attack paths

Attack-path analysis runs with the Standard / Deep / Identity / PurpleTeam profiles, or with
`-Scope AttackPath` / `All`. Results land in the output folder (`ThreatJet_<timestamp>` or
your `-Path`).

**In the HTML report (`ThreatJet_Report.html`):**
- The **Attack-Path Insights** strip near the top shows choke-point and blast-radius counts.
- In the findings table, type `path` in the global search (or filter the **ID** column to
  `PATH`). You'll see `PATH-001/002/003` (direct rights over Tier 0), `PATH-GRAPH` (multi-hop
  chains), and `PATH-BLAST` / `PATH-CHOKE` (summaries).
- Click a row's **Evidence** cell to expand the full chain, e.g.
  `jdoe -[GenericAll]-> HELPDESK -[MemberOf]-> Domain Admins`.

**In the CSVs (the most complete view):**
- **`Attack_Paths.csv`** — one row per path: source, Tier 0 target, hop count, the full
  written-out chain, and a **`Break_At`** column naming the single edge to cut to break it.
- **`Attack_Path_ChokePoints.csv`** — nodes ranked by how many paths run through them ("fix
  this first").
- **`Attack_Path_BlastRadius.csv`** — source principals ranked by how many Tier 0 targets
  they can reach ("lock this down first").

**On demand, without re-collecting:**
```powershell
. .\ThreatJet.ps1
Find-TJETAttackPath -Path C:\path\to\ThreatJet_<timestamp> -Top 50
```
It prints every principal that can reach Tier 0 with the full chain, shortest first.

If nothing shows under `PATH` and those CSVs are absent, attack-path analysis either didn't
run (check the profile/scope) or found no paths on that domain.

---

## Offline CVE scanning

Enable with `-IncludeCVEScan` and point `-CVEDatabasePath` at a CVE database. **No module is
required** — a `.csv` or `.json` database is read with native PowerShell:

```
cve_id, product_name, vendor_name, vulnerable_spec[, cvss]
```

- `vulnerable_spec` is `Ver: X to <Y` (the half-open range `[X, Y)` — upper bound exclusive)
  or `Ver: X` (exact affected version).
- `cvss` is an **optional** base score (0.0–10.0). When present it drives severity and
  ranking (≥9 Critical, ≥7 High, ≥4 Medium, >0 Low). When absent, severity falls back to
  match confidence and ranking is by CVE count.

Matching is deliberately conservative (a CVE feed keyed on free-text product names is noisy):
product name is normalised and gated on exact/contained match, and the installed version is
tested against the spec; an unparseable version is reported at **Low** confidence rather than
dropped or over-claimed. **A CVE match is not proof of exploitability** — the recommendation
is always "validate, then patch."

Results are **aggregated per product** (`Finding_Type = Vulnerability`) and shown in a
dedicated, **CVSS-ranked "Vulnerable Software" panel**, kept out of the posture dashboard so a
wall of CVEs can't bury the configuration findings. Full detail is written to
`CVE_By_Product.csv` (one row per product) and `CVE_Matches.csv` (one row per matched CVE).

### Building the CVE database

Use the included **`Build-TJETCveDatabase.ps1`** on your workstation (not the target). It
walks a local checkout of MITRE's [cvelistV5](https://github.com/CVEProject/cvelistV5) and
writes the CSV in exactly the format above.

```powershell
# 1. Get cvelistV5 (either one):
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
#    or download a nightly bundle from the repo's Releases and extract it.

# 2. Build the database (High-and-above keeps it small and fast):
.\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves.csv -MinCvss 7

# 3. Point ThreatJET at it:
Invoke-ThreatJetAssessment -IncludeCVEScan -CVEDatabasePath C:\Security\cves.csv
```

Useful switches: `-MinCvss <n>` (drop anything below a CVSS base score), `-Limit <n>` (quick
partial run to eyeball the output), `-IncludeNoVersion` (also emit products affected at all
versions, which match at low confidence).

Under the hood, each cvelistV5 record maps to one or more rows:

- `cveMetadata.cveId` → `cve_id`
- `containers.cna.affected[].product` / `.vendor` → `product_name` / `vendor_name`
- `affected[].versions[]`: a `lessThan` bound → `Ver: <version> to <lessThan>`; a
  `lessThanOrEqual` bound → that range **plus** an exact `Ver: <lessThanOrEqual>` row; a bare
  `version` → `Ver: <version>`
- best base score across `cna.metrics[]` and the CISA-ADP container (prefer CVSS v3.1 → v3.0
  → v4.0 → v2.0) → `cvss`
- skip records whose `cveMetadata.state` is `REJECTED`

If you already have a SQLite CVE database, convert it once with the standalone `sqlite3` CLI
(a single binary, not a PowerShell module):

```
sqlite3 -header -csv cves.db "SELECT cve_id, product_name, vendor_name, vulnerable_spec, cvss FROM vulnerabilities;" > cves.csv
```

> The full cvelistV5 corpus is large (~300k CVEs → millions of rows). On a workstation,
> build a tighter database (e.g. CVSS ≥ 7 only) to keep load fast — the scan loads the file
> before filtering to your installed software.

---

## Suppressing accepted risks

Accepted risks are suppressed with an auditable record rather than deleted. Pass a JSON file
with `-SuppressionPath`:

```json
[
  {
    "Finding_ID": "DOM-005",
    "Target": "corp.local",
    "Reason": "MAQ required for the VDI provisioning service account",
    "Ticket": "CHG-10492",
    "Expires": "2026-12-31"
  }
]
```

A match is flagged `Suppressed` and separated in the report — never dropped. An **expired or
malformed** suppression fails **closed**: the finding comes back as active and the lapse is
visible, so an exception can't silently hide forever.

---

## Baseline comparison

Re-run against a prior assessment's findings CSV to see drift instead of a fresh list:

```powershell
Invoke-ThreatJetAssessment -Path C:\Audit\Q3 `
    -BaselinePath C:\Audit\Q2\AD_Assessment_Findings.csv
```

Each finding is classified **New / Resolved / Persistent / Regressed / Improved**, written to
`Baseline_Comparison.csv`.

---

## Output files

Everything lands in the output folder (the run prints `Output: <path>`):

| File | Contents |
|---|---|
| `ThreatJet_Report.html` | Interactive report: severity cards, findings, attack-path insights, Vulnerable Software panel, coverage |
| `AD_Assessment_Findings.csv` / `.json` | Findings with RunId, type, ATT&CK mapping, detection guidance, remediation |
| `ATTACK_Coverage.csv` | Techniques the domain is exposed to, active vs. suppressed, with max severity |
| `Remediation_Report.html` / `Remediation_Script.ps1` | Fix list and a guarded, review-before-run change script |
| `Assessment_Summary.csv` | Posture counts by severity, plus separate vulnerability tallies |
| `Coverage.json` | Per-area collection status (Successful / Incomplete / Failed) |
| `Run_Manifest.json` | Who ran it, from where, against which DC, when, and what it produced |
| `CVE_By_Product.csv` / `CVE_Matches.csv` | Vulnerable software, per product and per CVE |
| `Baseline_Comparison.csv` | Drift vs. a baseline |
| `Attack_Paths.csv` + choke/blast CSVs | Traced paths and their rankings |
| `AD_*_Audit.csv` | Collected source data |
| `Inventory\` | With `-IncludeInventory`: every object/property + normalised `REL_*` edge lists |

The HTML report is self-contained (no CDN, opens from a share or email attachment): click a
column header to **sort** (severity sorts by rank), filter under each header, **global
search**, toggle severity bands with the cards, and **Export visible to CSV**.

---

## Reading the results

**Severity** is impact if real; **Confidence** is certainty — they're independent. A
High/Medium is a serious issue needing verification, not a lesser one.

| Severity | Meaning | Response |
|---|---|---|
| Critical | Direct path to domain compromise | Immediate |
| High | Significant escalation or persistence risk | Days |
| Medium | Hardening gap; needs a chain to exploit | Scheduled |
| Low | Hygiene or precondition only | Opportunistic |
| Info | Context, no action implied | None |

| Confidence | Meaning |
|---|---|
| High | Deterministic from collected attributes |
| Medium | Legitimate explanations exist; verify first |
| Low | Heuristic; treat as a lead |

Then check the **Assessment Coverage** panel. A report with few findings but a failed or
incomplete collection area is **not** a clean environment — it's an incomplete scan. For
detection engineering, work from `ATTACK_Coverage.csv`: the techniques the domain is exposed
to, ranked by severity, with the finding IDs behind each.

**Detection guidance assumes auditing is configured** — event 4662 in particular requires a
SACL on the objects concerned.

---

## Findings catalogue

Each finding in the CSV carries `Attack_Technique` (red), `MITRE_Technique` (ATT&CK ID), and
`Detection_Guidance` (blue), plus ordered `Remediation_Steps`.

### Domain and forest

**DOM-001 — KRBTGT password age** · Critical (>730d) / High (>365d) · High
The `krbtgt` password derives the key signing every Kerberos ticket; with it an attacker
forges Golden Tickets. *Fix:* rotate **twice**, waiting a full replication cycle (10+ hours)
between rotations — two quick rotations cause a domain-wide outage.

**DOM-004 — Trust crosses a forest boundary without SID filtering** · Critical (external) /
High (forest) · High
Without SID filtering a compromised trusted domain can inject a privileged SID via
SIDHistory. Intra-forest trusts are excluded (the forest is the security boundary). *Fix:*
`netdom trust <trusting> /domain:<trusted> /quarantine:yes` (test first).

**DOM-005 — MachineAccountQuota > 0** · Low · High
The default (10) lets any authenticated user create computer accounts — a precondition for
RBCD and shadow-credential chains. *Fix:* set to 0 and delegate machine-join to a controlled
group.

**DOM-006 — Fine-grained password policy weaker than the domain default** · High (Tier 0
scoped) / Medium · High/Medium
A weaker PSO silently lowers the bar, worst case scoped to Domain Admins. *Fix:* raise the
PSO to baseline or rescope it away from privileged principals.

### Identity

**ID-001 — User account with an SPN (Kerberoasting)** · Critical / High / Medium · High
Any authenticated user can request a service ticket for an SPN-bearing account and crack it
offline. *Fix:* migrate to a gMSA, or set a 25+ character random password.

**ID-002 — Constrained delegation on a user account** · High · High
The account can impersonate users to its target services. *Fix:* prefer resource-based
constrained delegation.

**ID-004 — Unconstrained delegation on a user account** · Critical · High
Caches the TGT of everyone who authenticates to it, including admins. *Fix:* remove
`TrustedForDelegation`; use RBCD; add sensitive accounts to **Protected Users**.

**ID-005 — SIDHistory populated** · Critical (Tier 0 SID) / High · High/Medium
Hidden privilege that membership reviews won't show. *Fix:* clear it if migration is
complete; a Tier 0 SID with no migration to explain it is a compromise indicator.

**ID-006 — Dormant privileged account** · High · Medium
An admin account nobody uses is one nobody notices being used. *Fix:* disable, then delete
after a retention window.

**ID-007 — Kerberos pre-auth not required (AS-REP roasting)** · Critical / High · High/Medium
Anyone can request an AS-REP and crack it offline — no credentials needed. *Fix:* clear
`DONT_REQ_PREAUTH`.

**ID-008 — `msDS-KeyCredentialLink` populated (shadow credentials)** · High / Medium · Medium
Allows certificate-based auth as the account. Windows Hello / Azure AD device registration
populate it legitimately. *Fix:* review each entry; remove unrecognised ones.

**ID-009 — Privileged account password never expires** · High · High
Static credential on a privileged account. *Fix:* remove the flag or migrate to a gMSA.

**ID-010 — Privileged account with PASSWD_NOTREQD** · Critical · High
The account may have an empty password. *Fix:* clear the flag, set a compliant password
immediately, check auth logs for prior use.

**ID-011 — Privileged identity with no directly assigned PSO** · High · Medium
Inherits a domain default weaker than your privileged baseline (`PrivilegedPasswordBaselineLength`,
default 14). Only *direct* assignment is evaluated — verify group-inherited PSOs before
acting. Disabled accounts, `krbtgt` and `Guest` are excluded. *Fix:* assign a strong PSO.

### Infrastructure

**INF-001 — Unconstrained delegation on a non-DC** · Critical · High — caches TGTs of
everyone who connects; with coercion, captures a DC's TGT. *Fix:* remove it; use RBCD.
**INF-002 — Resource-based constrained delegation configured** · High · High — legitimate,
but also the standard escalation primitive. *Fix:* verify each is intentional.
**INF-003 — No LAPS evidence on a member server** · Medium · Medium — local admin passwords
often identical across machines. *Fix:* deploy Windows LAPS.
**INF-004 — Unsupported operating system** · High · High — no updates; weak protocols. *Fix:*
upgrade/decommission/isolate.
**INF-005 — Computer object with `msDS-KeyCredentialLink`** · High (DC) / Medium · Medium —
allows auth as the machine account; on a DC that is domain compromise. *Fix:* validate
against expected device registrations.

### Group Policy

**GPO-001 — GPO modifiable by a broad principal** · Critical (linked to DCs) / High · High —
GPO edit rights are code execution on every machine the policy applies to. *Fix:* restrict
edit rights.
**GPO-002 — Unexpected SYSVOL modify rights** · High · Medium — write access to SYSVOL equals
GPO edit rights, bypassing AD delegation. *Fix:* restore default SYSVOL permissions.
**GPO-003 — Non-default GPO assigns privileged user rights** · Medium · Medium —
`SeDebug`/`SeBackup`/`SeTakeOwnership` are effectively administrative. *Fix:* confirm the
rights go only to the intended tier.

### Groups

**GRP-001 — Custom privileged group has no members** · Low · High — unused privileged group
is unmonitored privilege (custom groups only; empty built-in operator groups are the hardened
state). *Fix:* delete if unused, else monitor.
**GRP-002 — Custom Tier 0 group has no owner** · Info · High — no accountable owner
(`ManagedBy`). *Fix:* assign an owner.
**GRP-003 — Tier 0 group nested inside another group** · Medium · Medium — nesting extends
Tier 0 privilege invisibly. *Fix:* flatten privileged nesting.

### Service accounts

**GMSA-001 — gMSA password retrievable by a broad principal** · Critical · High — anyone who
can retrieve the managed password can authenticate as the service (e.g. `Domain Users`).
Retrieval by an already-privileged Tier 0 group is not flagged. *Fix:* restrict
`PrincipalsAllowedToRetrieveManagedPassword` to the specific host group.

### Attack paths

**PATH-001 — Non-privileged principal with modification rights over a Tier 0 object** ·
Critical · High
The flagship finding. `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` or a dangerous
control-access right (including `DS-Replication-Get-Changes-All` — **DCSync**) over a Tier 0
object. `SYSTEM`/`SELF`, Deny ACEs and the default Change-Password right are excluded;
Everyone / Authenticated Users / Domain Users are filtered by *right*, not identity. *Fix:*
remove the ACE, then audit how it was granted.

**PATH-002 — Dangerous rights over AdminSDHolder** · Critical · High
AdminSDHolder's ACL is stamped onto every `adminCount=1` object ~hourly by SDProp, so an ACE
here propagates to every protected object — a persistence backdoor. *Fix:* clean
AdminSDHolder **first**, then the stamped copies (SDProp restores them otherwise).

**PATH-003 — One principal holds the same right across many Tier 0 objects** · Critical · High
Uniform rights across protected objects indicate AdminSDHolder propagation, consolidated into
one root-cause finding. *Fix:* inspect `CN=AdminSDHolder,CN=System` and remediate there.

**PATH-GRAPH — Multi-hop control path to Tier 0** · Critical · High
The whole multi-hop chain from a non-privileged principal to Tier 0 (a one-hop chain is
already PATH-001), e.g. `jdoe -[GenericAll]-> HELPDESK -[MemberOf]-> Domain Admins`. *Fix:*
break the chain at its weakest link — one edge severs every path through it.

**PATH-CHOKE / PATH-BLAST** · Critical · High
Choke point = the node the most paths run through (fix it to collapse the most paths). Blast
radius = the source principal that reaches the most Tier 0 targets (lock it down first).

### Local host privilege escalation (`LOCAL-*`)

Detection only — the tool reports the misconfiguration and how to remove it; it never
exploits it.

| ID | Check | Severity |
|---|---|---|
| LOCAL-000 | Assessment context (ran as local admin; routes shown are the unprivileged view) | Info |
| LOCAL-001 | Unquoted service path | High |
| LOCAL-002 | Modifiable service (runs as SYSTEM) | Critical |
| LOCAL-003 | AlwaysInstallElevated (HKLM + HKCU) | Critical |
| LOCAL-004 | Writable %PATH% directory | High |
| LOCAL-005 | Autorun with a writable target | High |
| LOCAL-006 | Stored credential (autologon, cmdkey, unattend) | High |
| LOCAL-007 | Dangerous token privilege (SeImpersonate, SeDebug, SeBackup…) | Critical |
| LOCAL-008 | UAC weakened | Medium |
| LOCAL-009 | Credential protection gap (WDigest / RunAsPPL / Credential Guard) | High |
| LOCAL-010 | SMB signing not required | Medium |
| LOCAL-011 | Legacy protocol available (SMBv1 / PowerShell v2) | Medium |
| LOCAL-012 | Scheduled task runs as SYSTEM from a user-writable directory | Critical |
| LOCAL-013 | Writable directory usable for DLL/binary planting | High |
| LOCAL-014 | PowerShell history contains credential-like commands | High |
| LOCAL-015 | Unattend/sysprep answer file left on disk | Critical |
| LOCAL-016 | Cloud credential file (AWS/Azure/GCP/kube/docker) | High |
| LOCAL-017 | SSH private key present | High |
| LOCAL-018 | Saved PuTTY/WinSCP/RDP session, possibly with stored password | Medium |
| LOCAL-019 | VNC/SNMP/autologon credential in the registry | Critical |
| LOCAL-020 | Accessibility binary debugger hijack (sethc/utilman) | Critical |
| LOCAL-021 | WSUS served over cleartext HTTP | High |
| LOCAL-022 | RDP enabled with NLA disabled | Medium |
| LOCAL-023 | Defender real-time or tamper protection disabled | High |
| LOCAL-024 | A firewall profile is disabled | Medium |
| LOCAL-025 | Print Spooler running (PrintNightmare / coercion) | Medium |
| LOCAL-026 | Non-administrative share published | Low |
| LOCAL-027 | Non-default member of local Administrators | Medium |

**LOCAL-020** (sethc/utilman debugger) and **LOCAL-019** have essentially no legitimate use —
treat them as compromise indicators and check every other host for the same key.
**LOCAL-015** is usually an *image* defect: every machine built from that image shares the
exposed local administrator password.

### Other host and data findings

- **CRED-001 — Credential in an AD attribute** · Critical · High/Medium. Secrets in
  `description`, `info`, `userPassword`, `extensionAttribute*`, etc. The matched value is
  never written to the report — only the object, attribute, and a redacted preview. *Fix:*
  **rotate first** (clearing the attribute doesn't invalidate a known password), then clear
  it; assume domain-wide exposure.
- **CRED-002 — Filesystem credential** · High · Medium. With `-DataminePasswords`:
  credential-bearing filenames and assignment patterns in config/script files. Value never
  written — only file, line, redacted preview. (OS telemetry and the tool's own
  artifacts are excluded from the scan to avoid false positives.)
- **PORT-001 — Network exposure** · High/Medium/Low. Listening ports that matter
  (legacy-cleartext and lateral-movement services), scaled by service and bind scope; a
  loopback-only listener does not generate noise.
- **PATCH-001 — Patch level** · High (>180d) / Medium (>90) / Low (>60), from the most recent
  installed hotfix.
- **CVE-PRODUCT — Vulnerable software** · by CVSS (or match confidence). One finding per
  product; see [Offline CVE scanning](#offline-cve-scanning).

---

## Configuration

Tunable values live in a `$script:TJETConfig` hashtable near the top of `ThreatJet.ps1`. Edit
them in place, or override the equivalents via parameters.

```powershell
$script:TJETConfig = @{
    CollectorVersion                 = "2.3.2"
    CorrelationVersion               = "2.3.2"
    SchemaVersion                    = "1.5"

    EnableFilesystemCredentialScan   = $false    # -DataminePasswords
    CVEDatabasePath                  = "C:\Security\cves.csv"   # -CVEDatabasePath

    # Production scale + safety
    PerObjectThrottleMs              = 0          # -ThrottleMs; pace per-object work
    LargeObjectWarningThreshold      = 50000      # warn/stop above this object count
    MaxAttackPathSources             = 25000      # cap BFS source principals on huge graphs

    # Risk thresholds
    PrivilegedPasswordBaselineLength = 14         # drives ID-011
    KrbtgtWarningDays                = 365         # drives DOM-001
    KrbtgtCriticalDays               = 730
    MachineAccountQuotaThreshold     = 0          # drives DOM-005
    Encoding                         = "UTF8"
}
```

Set `PrivilegedPasswordBaselineLength` to the standard you are assessing against (not an
aspiration), or every privileged account produces a finding and the report loses signal —
typically 15–16 (high security), 14 (commercial), 12 (legacy).

---

## Before you trust the output

- **Zero findings on a real domain means the tool is broken, not that the domain is
  perfect.** Check the coverage panel / collection summary and the log for `No privileged
  principals identified` (which means several detections are silently disabled).
- **Test against a lab with known weaknesses first** so you can confirm it finds what you
  planted, then confirm a remediated item shows as `RESOLVED` in a baseline re-run.
- **Spot-check serialization** in the raw CSVs before trusting related findings — especially
  `PrincipalsAllowedToRetrieveManagedPassword` (GMSA-001 matches on names; if your AD emits
  DNs or SIDs the match may miss), FGPP `AppliesTo`, ACL `Rights`, and that an RODC reads as a
  domain controller.
- **Everything Critical being identical** is a sign of a mis-scoped detector — investigate
  before reporting.

---

## Limitations

- **Single domain per run.** For a forest, run once per domain.
- **Attack-path model is the control plane** (ACL / membership / delegation). It does not
  collect sessions (BloodHound's `HasSession`), so session-based paths aren't modeled.
- **ACL collection defaults to `Targeted`;** `-AclMode Full` is thorough but slow.
- **Inventory uses `-Properties *`** and is the slowest, largest part of a run.
- **Local-host checks are detection-only** — they report that a credential store exists and
  is reachable; they never decrypt or print its contents, and the report never prints a
  discovered secret (only object/attribute + redacted preview).
- **CVE matching is conservative and version-aware**; a match is not proof of exploitability.
- **Detection guidance assumes auditing is configured** (e.g. 4662 needs a SACL).

---

## Operational cautions

- Read-only, but **not zero-impact** — it enumerates every object. Coordinate before a
  production run, prefer off-peak, and pin a DC with `-Server`.
- **Output is highly sensitive** — the inventory is a complete map of the directory's
  privilege structure. Encrypt at rest, restrict access, and delete when the engagement ends.
- Directory **read** access is sufficient; Domain Admin is not required.

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Melvin Salyers ([d33p-d1sh](https://github.com/d33p-d1sh)).

The published `ThreatJet.ps1` carries the full MIT notice in its header, so the license
travels with the file on its own.

---

*ThreatJET is an assessment tool. Run it only against environments you are authorized to test.*
