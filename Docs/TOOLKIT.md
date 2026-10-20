# Security Assessment Toolkit Overview

ThreatJet assesses four surfaces in one run and reports each finding with both an
offensive and a defensive view, plus concrete remediation steps.

```
                 ┌─────────────────────────────────────────────┐
                 │            Invoke-ThreatJetAssessment      │
                 └─────────────────────────────────────────────┘
                                      │
        ┌──────────────┬──────────────┼──────────────┬─────────────────┐
        ▼              ▼              ▼              ▼                 ▼
   AD objects     Local host     Attack-path      Object          Findings +
   (collectors)   (WinPEAS-      graph            inventory       remediation
                   style)        (BloodHound-      (every object,  (per finding)
                                 style)            all properties)
```

## The four surfaces

### 1. Active Directory
Users, computers, groups, GPOs, ACLs, trusts, FGPP, gMSA, domain summary. Detectors
cover identity risk, delegation, privilege, password hygiene, trust, GPO, and Tier 0
ACL attack paths. See [FINDINGS.md](FINDINGS.md).

### 2. Local host (WinPEAS-style)
`Collect-LocalHost` inspects the machine the assessment runs on for the highest-signal
local privilege-escalation categories: unquoted/modifiable services,
AlwaysInstallElevated, writable PATH, autoruns, stored credentials, dangerous token
privileges, UAC, credential-protection state, SMB signing, legacy protocols. Findings
are `LOCAL-*`.

This is **detection, not exploitation** — every check reports whether a misconfiguration
is present and how to remove it. It requires no AD and benefits from (but does not
require) an elevated session; where a check can only run partially without elevation,
that is recorded in the finding rather than hidden.

**Scope honesty:** WinPEAS runs hundreds of checks. This covers the categories that most
reliably lead to SYSTEM, structured so new checks slot into the same
collector→detector→remediation pipeline. It is a strong foundation, not a line-for-line
reimplementation.

### 3. Attack-path graph (BloodHound-style)
`Build-TJETGraph` assembles a control graph from three edge types — group membership
(transitive), dangerous ACLs (GenericAll, WriteDacl, WriteOwner, GenericWrite,
ForceChangePassword, AddMember), and delegation — then runs a breadth-first search for
the shortest path from every non-privileged principal to a Tier 0 node. Multi-hop chains
become `PATH-GRAPH` findings that print the full path.

The engine writes **`Attack_Paths.csv`**: one row per path with the source, the Tier 0
target, the hop count, the full chain written out, and `Break_At` naming the specific
link to cut.

**Scope honesty:** BloodHound is a graph database with dozens of edge types and a query
UI. This computes the single most important query — shortest path to Tier 0 — over the
edges the collectors already gather, and writes each path out in readable form rather
than as a graph to visualise. Sessions and some Azure/certificate edges are out of
scope.

Run it standalone against an existing collection:

```powershell
Find-TJETAttackPath -Path C:\Audit
```

### 4. Object inventory
Every AD object with every property, plus normalised relationship files. See
[INVENTORY.md](INVENTORY.md).

## Every finding is purple

Enrichment is applied once, at export, from three lookup tables keyed by `Finding_ID`:

| Column | Source | View |
|---|---|---|
| `Attack_Technique` | `Get-TJETFindingMetadata` | what an operator does with it — red |
| `MITRE_Technique` | `Get-TJETFindingMetadata` | ATT&CK ID |
| `Detection_Guidance` | `Get-TJETFindingMetadata` | telemetry / event IDs to hunt — blue |
| `Remediation_Steps` | `Get-TJETRemediation` | numbered, ordered fix steps |

Because the tables are keyed by ID and applied centrally, a detector cannot emit a
finding that lacks any of these — the smoke test asserts full coverage across all three
tables, so an unmapped finding fails the build.

`Remediation_Steps` is an ordered, numbered sequence with the actual commands and the
operational cautions (for example: rotate krbtgt twice *with a replication cycle
between*, or clean AdminSDHolder *before* the objects it stamps).

## One-command run

```powershell
Invoke-ThreatJetAssessment -IncludeInventory -OpenReport
```

Produces, in a timestamped folder:

```
AD_*_Audit.csv                 collected AD data
AD_LocalHost_Audit.csv         local host surface
AD_Assessment_Findings.csv     findings + ATT&CK + detection + remediation
AD_Assessment_Findings.json    same, machine-readable
ATTACK_Coverage.csv            techniques the environment is exposed to
Attack_Paths.csv               traced paths: chain, hop count, link to cut
Inventory\AD_Inventory_*.csv   every object, all properties
Inventory\REL_*.csv            normalised relationship edge lists
ThreatJet_Report.html       human-readable report
Assessment_Summary.csv         counts + provenance
```

## What this toolkit is and is not

It is a single, validated pipeline that assesses AD and the local host, computes attack
paths, inventories the directory, and hands every finding to a remediator with the
exact steps. It shares the highest-value checks of WinPEAS and the core pathfinding of
BloodHound in one place, with a consistent finding contract and offline-capable
analysis.

It is not a complete reimplementation of either tool, and does not try to be. Where it
stops, it hands off cleanly — the graph export drops straight into BloodHound. See
[ROADMAP.md](ROADMAP.md) for what would extend each surface next.
