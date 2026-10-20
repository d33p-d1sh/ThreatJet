# Findings Catalogue

Every detection: what it means, why it matters, how to fix it.

Each finding in the CSV also carries three security-assessment columns, generated from a single
mapping table (`Private/Get-TJETFindingMetadata.ps1`):

| Column | View |
|---|---|
| `Attack_Technique` | what an operator does with the finding (**red**) |
| `MITRE_Technique` | the ATT&CK ID, so it maps to your detection programme |
| `Detection_Guidance` | telemetry and Windows event IDs to hunt (**blue**) |

`ATTACK_Coverage.csv` aggregates these into the set of techniques the domain is
currently exposed to, ranked by severity — the natural starting point for detection
engineering.

**Detection guidance assumes auditing is configured.** Event 4662 in particular
requires a SACL on the objects concerned; without one, the events described will not
be generated no matter how good the rule is.

**Severity** = impact if real. **Confidence** = certainty of the detection. They are
independent — a High/Medium is a serious issue needing verification, not a lesser one.

---

## Domain and forest

### DOM-001 — KRBTGT password age
**Critical** (>730d) / **High** (>365d) · Confidence High

The `krbtgt` password derives the key signing every Kerberos ticket. An attacker with
it can forge Golden Tickets for any principal. Rotating once does not evict them — the
account keeps two key generations.

**Fix:** Rotate twice, waiting a full replication cycle (typically 10+ hours) between
rotations. Rotating twice in quick succession invalidates all tickets domain-wide and
causes an outage.

### DOM-004 — Trust crosses a forest boundary without SID filtering
**Critical** (external) / **High** (forest) · Confidence High

SID filtering stops a compromised trusted domain injecting a privileged SID via
SIDHistory. Without it, compromise of the trusted side is compromise of yours.

**Intra-forest trusts are excluded.** Within a forest the *forest* is the security
boundary, not the domain: SID filtering is disabled there by design and enabling
quarantine on a parent-child trust breaks normal operation. The detector reads the
`WITHIN_FOREST` (`0x20`) bit of `TrustAttributes` to tell them apart.

**Fix:** `netdom trust <trusting> /domain:<trusted> /quarantine:yes`. Test first —
quarantine can break legitimate access relying on SIDHistory.

### DOM-005 — MachineAccountQuota > 0
**Low** · Confidence High

The default (10) lets any authenticated user create computer accounts. Not an
escalation alone, but a precondition for RBCD and shadow-credential chains.

**Fix:** Set to 0 and delegate machine-join to a controlled group.

### DOM-006 — Fine-grained password policy weaker than the domain default
**High** (Tier 0 scoped) / **Medium** · Confidence High (SID-resolved) / Medium (name heuristic)

PSOs take precedence over the domain default, so a weaker PSO silently lowers the bar
— worst case, one scoped to Domain Admins. Compares against the domain default, not
an absolute number: a 20-character PSO in a 12-character domain is correctly ignored.

**Fix:** Raise the PSO to the baseline, or rescope it away from privileged principals.

---

## Identity

### ID-001 — User account with an SPN (Kerberoasting)
**Critical** (privileged, password >365d) / **High** (privileged, or stale password) /
**Medium** · Confidence High

Any authenticated user can request a service ticket for an SPN-bearing account and
crack it offline. When the account is privileged, cracking it yields privilege.

**Fires for any SPN-bearing user account.** An earlier version required the account to
be privileged, so ordinary service accounts — the standard Kerberoasting target —
produced no finding at all. Privilege now scales the severity rather than gating the
detection.

**Fix:** Migrate to a gMSA (120-character auto-rotated password). Otherwise set a 25+
character random password.

### ID-002 — Constrained delegation on a user account
**High** · Confidence High

The account can impersonate users to its target services. Compromise cascades to
every service it can delegate to.

**Fix:** Review the need; prefer resource-based constrained delegation.

### ID-004 — Unconstrained delegation on a user account
**Critical** · Confidence High

Caches the TGT of everyone who authenticates to it, including administrators.

**Fix:** Remove `TrustedForDelegation`; use RBCD. Add sensitive accounts to
**Protected Users** so their TGTs cannot be delegated.

### ID-005 — SIDHistory populated
**Critical** (Tier 0 SID) / **High** · Confidence High / Medium

SIDHistory grants the rights of the historical SID — hidden privilege that group
membership reviews will not show. A known persistence technique as well as a
migration leftover.

**Fix:** Clear it if migration is complete. A Tier 0 SID with no migration to explain
it is a compromise indicator; investigate.

### ID-006 — Dormant privileged account
**High** · Confidence Medium

An admin account nobody uses is one nobody notices being used. Medium confidence
because `lastLogonTimestamp` replicates lazily (~14 days).

**Fix:** Disable, then delete after a retention window.

### ID-007 — Kerberos pre-authentication not required (AS-REP roasting)
**Critical** (privileged) / **High** · Confidence High / Medium

Anyone can request an AS-REP and crack it offline — no credentials needed to start.

**Fix:** Clear `DONT_REQ_PREAUTH`. Where a legacy app requires it, enforce a long
random password and monitor.

### ID-008 — `msDS-KeyCredentialLink` populated (shadow credentials)
**High** (privileged) / **Medium** · Confidence Medium

Allows certificate-based authentication as the account — an attacker persistence
technique. But Windows Hello and Azure AD device registration populate it
legitimately, hence Medium confidence.

**Fix:** Review each entry against expected registrations; remove unrecognised ones.

### ID-009 — Privileged account password never expires
**High** · Confidence High

Static credential on a privileged account: unbounded exposure, often predating
current complexity standards.

**Fix:** Remove the flag, or migrate the workload to a gMSA.

### ID-010 — Privileged account with PASSWD_NOTREQD
**Critical** · Confidence High

The account may have an empty password. Frequently a provisioning leftover.

**Fix:** Clear the flag, set a compliant password immediately, check auth logs for
prior use.

### ID-011 — Privileged identity with no directly assigned PSO
**High** · Confidence Medium

Inherits a domain default weaker than your privileged baseline (default 14; see
[CONFIGURATION.md](CONFIGURATION.md)).

**Known limitation:** only *direct* assignment is evaluated. An admin covered via
group membership is still flagged — verify before acting.

Disabled accounts, `krbtgt` (RID 502) and `Guest` (RID 501) are excluded: their
credentials are machine-generated or unused, so a password policy is meaningless.

**Fix:** Assign a strong PSO to privileged accounts or their groups.

---

## Infrastructure

### INF-001 — Unconstrained delegation on a non-DC
**Critical** · Confidence High

Caches TGTs of everyone who connects. With a coercion technique, an attacker can
force a DC to authenticate and capture its TGT.

**Fix:** Remove it; use RBCD and Protected Users.

### INF-002 — Resource-based constrained delegation configured
**High** · Confidence High

Legitimate, but also the standard escalation primitive: write access to a computer
object plus `MachineAccountQuota > 0` lets an attacker configure RBCD and impersonate
anyone to that host.

**Fix:** Verify each is intentional. Unexplained RBCD is a compromise indicator.

### INF-003 — No LAPS evidence on a member server
**Medium** · Confidence Medium

Without LAPS, local admin passwords are often identical across machines, enabling
lateral movement from one compromise.

**Fix:** Deploy Windows LAPS. Medium confidence because third-party coverage is not
visible in AD attributes.

### INF-004 — Unsupported operating system
**High** · Confidence High

No security updates, and often forces weak protocol support (NTLMv1, SMBv1)
domain-wide.

**Fix:** Upgrade or decommission; otherwise isolate and document the exception.

### INF-005 — Computer object with `msDS-KeyCredentialLink`
**High** (domain controller) / **Medium** · Confidence Medium

Allows authentication as the machine account. On a DC that is domain compromise.

**Fix:** Validate against expected device registrations.

---

## Group Policy

### GPO-001 — GPO modifiable by a broad principal
**Critical** (linked to Domain Controllers) / **High** · Confidence High

GPO edit rights are code execution on every machine the policy applies to.

**Fix:** Restrict edit rights to Domain Admins or a dedicated delegated group.

### GPO-002 — Unexpected SYSVOL modify rights
**High** · Confidence Medium

GPO content lives in SYSVOL. Write access there equals GPO edit rights, bypassing
AD-level delegation entirely.

**Fix:** Restore default SYSVOL permissions for the policy folder.

### GPO-003 — Non-default GPO assigns privileged user rights
**Medium** · Confidence Medium

Excludes the Default Domain and Default Domain Controllers policies, whose purpose is
to assign these rights — reporting them was unactionable noise present in every domain.

`SeDebugPrivilege`, `SeBackupPrivilege` and `SeTakeOwnershipPrivilege` are effectively
administrative — `SeBackupPrivilege` alone permits reading `NTDS.dit`.

**Fix:** Confirm the rights go only to the intended administrative tier.

---

## Groups

### GRP-001 — Custom privileged group has no members
**Low** · Confidence High

Unused privileged group = unmonitored privilege. Adding a member is a quiet
escalation path that membership reviews rarely cover.

**Scoped to custom groups only.** Built-in operator groups (Account Operators, Backup
Operators, Print Operators, Server Operators, Replicator, Key Admins, DnsAdmins) ship
empty, and empty is the *hardened* state recommended by CIS and Microsoft — reporting
them told administrators to break a correct configuration.

**Groups whose membership comes from `primaryGroupID`** (Domain Users, Domain
Computers, Domain Controllers, Read-only Domain Controllers) are never reported: their
`member` attribute is always empty, so the old check was simply wrong.

**Fix:** Delete if unused; otherwise monitor membership changes.

### GRP-002 — Custom Tier 0 group has no owner
**Info** · Confidence High

No `ManagedBy` means no accountable owner for membership decisions.

**Scoped to custom groups only.** Microsoft never populates `ManagedBy` on built-in
groups, so the unscoped check produced a dozen permanent, unactionable findings in
every domain.

**Fix:** Assign an owner; include in periodic access reviews.

### GRP-003 — Tier 0 group nested inside another group
**Medium** · Confidence Medium

Nesting extends Tier 0 privilege to the outer group's members, which a review of the
Tier 0 group's own membership will not reveal.

**Fix:** Flatten privileged group nesting so Tier 0 membership is explicit.

---

## Service accounts

### GMSA-001 — gMSA password retrievable by a broad principal
**Critical** · Confidence High

Anyone who can retrieve the managed password can authenticate as the service. When
that is `Domain Users`, every user in the domain can become the service — defeating
the entire purpose of a gMSA.

Retrieval by a Tier 0 group is deliberately **not** flagged: those principals are
already privileged, so it is not an escalation.

**Fix:** Restrict `PrincipalsAllowedToRetrieveManagedPassword` to the specific host
group running the service.

---

## Attack paths

### PATH-001 — Non-privileged principal with modification rights over a Tier 0 object
**Critical** · Confidence High

The flagship finding. `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` or a
dangerous control-access right held by a non-privileged principal over a Tier 0 object
is a direct escalation path: the holder can add themselves to the group, reset the
password, or rewrite the ACL.

**What is deliberately excluded**, because reporting it is equivalent to reporting that
AD exists:

- `NT AUTHORITY\SYSTEM` and `NT AUTHORITY\SELF` — infrastructure principals holding
  broad rights on nearly every object by design.
- **Deny** ACEs — collected as evidence, never an attack path.
- The default **Change Password** extended right
  (`ab721a53-1e2f-11d0-9819-00aa0040529b`) granted to Everyone on user objects.

**What is NOT excluded:** Everyone, Authenticated Users and Domain Users are filtered
by *right*, not identity. A `GenericAll` or `WriteDacl` held by Everyone is a genuine
critical finding, as is `DS-Replication-Get-Changes-All` — the **DCSync** right.

**Fix:** Remove the ACE after confirming no automation depends on it, then audit how
it was granted, because the same pattern is usually present elsewhere.

### PATH-002 — Dangerous rights over AdminSDHolder
**Critical** · Confidence High

AdminSDHolder's ACL is **stamped** (copied, not inherited) onto every `adminCount=1`
object roughly hourly by SDProp. An ACE added here therefore propagates to every
protected user and group in the domain — the classic persistence backdoor.

**Fix:** Clean AdminSDHolder **first**, then remove the copies it stamped onto
protected objects. Removing only the copies is ineffective: SDProp restores them
within the hour.

### PATH-003 — One principal holds the same right across many Tier 0 objects
**Critical** · Confidence High

Uniform rights across all protected objects indicate AdminSDHolder propagation rather
than many independent delegation mistakes. This consolidates what would otherwise be
one Critical per protected object into a single root-cause finding.

**Fix:** Inspect `CN=AdminSDHolder,CN=System` and remediate there.

---

## Local host privilege escalation (`LOCAL-*`)

Collected by `Collect-LocalHost` from the machine the assessment runs on (no AD
required; benefits from an elevated session). These are the highest-signal categories a
tool like WinPEAS checks. Detection only — the framework reports the misconfiguration
and how to remove it; it never exploits it.

### LOCAL-001 — Unquoted service path
**High.** A service `ImagePath` contains a space and is unquoted, so Windows may execute
an attacker-planted binary earlier in the path (e.g. `C:\Program.exe`).
**Fix:** quote the path, or move the binary out of a user-writable directory.

### LOCAL-002 — Modifiable service
**Critical.** A non-administrator can change a service binary or its configuration, and
services run as SYSTEM. Direct local-to-SYSTEM.
**Fix:** correct the service or binary ACL so only administrators can modify it.

### LOCAL-003 — AlwaysInstallElevated
**Critical.** Both the HKLM and HKCU `AlwaysInstallElevated` policies are set, so any
user can install an MSI as SYSTEM.
**Fix:** set both policies to 0.

### LOCAL-004 — Writable %PATH% directory
**High.** A directory in the system `%PATH%` is writable by the current user, enabling
binary planting against anything that resolves a bare command name.
**Fix:** remove write access, or drop the directory from PATH.

### LOCAL-005 — Autorun with a writable target
**High.** An autorun entry points at a binary the current user can overwrite — code
execution as the next principal to log on.
**Fix:** correct the target ACL or remove the autorun.

### LOCAL-006 — Stored credential
**High.** A plaintext credential was found in a well-known location (autologon registry
values, `cmdkey` store, unattend/sysprep XML).
**Fix:** remove it; rotate the exposed secret; use LAPS or a vault instead.

### LOCAL-007 — Dangerous token privilege
**Critical.** The current context holds a privilege that enables SYSTEM escalation —
`SeImpersonatePrivilege` (Potato attacks), `SeAssignPrimaryToken`, `SeDebugPrivilege`,
`SeBackup`/`SeRestore`, `SeTakeOwnership`.
**Fix:** remove the privilege from the account unless the role genuinely requires it.

### LOCAL-008 — UAC weakened
**Medium.** UAC is disabled or set to never prompt, removing a barrier to silent
elevation.
**Fix:** restore `EnableLUA=1` and a prompting `ConsentPromptBehaviorAdmin`.

### LOCAL-009 — Credential protection gap
**High.** WDigest credential caching is enabled, LSA protection (RunAsPPL) is off, or
Credential Guard is not running — all of which ease credential theft from LSASS.
**Fix:** disable WDigest, enable RunAsPPL, and deploy Credential Guard where supported.

### LOCAL-010 — SMB signing not required
**Medium.** SMB signing is not enforced, enabling relay attacks.
**Fix:** require SMB signing on clients and servers via policy.

### LOCAL-011 — Legacy protocol available
**Medium.** SMBv1 or PowerShell v2 is present — downgrade and logging-evasion surface.
**Fix:** remove the SMB1 feature and the PowerShell v2 engine.

## Credential exposure (`CRED-001`)

**Critical.** Confidence High for secret-bearing attributes, Medium for content matches.

Collectors capture **every** attribute precisely because credentials turn up in fields
nobody audits: `description`, `info`, `comment`, `extensionAttribute*`, and the legacy
`userPassword` / `unixUserPassword`. Two signal classes:

1. **Attributes that should never hold a secret** - any value is reportable.
2. **Assignment patterns in free text** - `password = x`, `pwd:`, connection strings,
   API keys, private key headers. Anchored on a separator so prose like
   "user must change password at next logon" does not fire.

**The matched value is never written to the findings CSV** - only the object, the
attribute name, and a redacted preview. Copying discovered credentials into a report
that then gets emailed around is its own incident.

**Fix:** rotate the credential *first* (clearing the attribute does not invalidate a
password that is already known), then clear the attribute. Assume domain-wide exposure:
these attributes are readable by any authenticated user by default, and that read
leaves no distinctive audit trail.

## Assessment context (`LOCAL-000`)

**Info.** Emitted once when the scan ran as a local administrator.

When the operator already holds administrator rights, listing every escalation route is
noise - and several checks would fire because of the operator's own token (an admin
inherently holds SeDebug, SeBackup, SeRestore, SeTakeOwnership). In a privileged run the
tool records this finding and then reports only routes an **unprivileged** user could
take on that host. Re-run as a standard user to enumerate from that perspective.

### Extended host checks (`LOCAL-012` - `LOCAL-027`)

WinPEAS-style enumeration beyond the core set. All detection-only: the tool reports
that a credential store exists and is reachable, never its contents.

| ID | Check | Severity |
|---|---|---|
| LOCAL-012 | Scheduled task runs as SYSTEM from a user-writable directory | Critical |
| LOCAL-013 | Writable directory usable for DLL/binary planting | High |
| LOCAL-014 | PowerShell console history contains credential-like commands | High |
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
| LOCAL-025 | Print Spooler running (PrintNightmare / coercion surface) | Medium |
| LOCAL-026 | Non-administrative share published | Low |
| LOCAL-027 | Non-default member of local Administrators | Medium |

**LOCAL-020 deserves special attention.** A debugger set on `sethc.exe` or `utilman.exe`
has essentially no legitimate use and yields SYSTEM from the logon screen without
authenticating. Treat it as a compromise indicator, not a misconfiguration, and check
every other host for the same key.

**LOCAL-015 is an image defect, not a host defect.** An answer file with a password
usually means every machine built from that image shares the exposed local
administrator password.

## Network exposure (`PORT-001`)

**High / Medium / Low**, scaled by service and bind scope.

Every listening TCP/UDP port is inventoried with its owning process; the detector
reports the ones that matter: legacy-cleartext services (Telnet, FTP, rlogin, TFTP) and
high-value lateral-movement surfaces (SMB, RDP, WinRM, RPC, LDAP, databases). A service
bound to `0.0.0.0`/`::` (network-reachable) outranks the same service bound to loopback,
so a local-only listener does not generate noise.

**Fix:** confirm the service is needed and correctly scoped; disable it or firewall it to
the required networks; require encrypted, authenticated access.

## Patch level (`PATCH-001`)

**High** (>180 days) / **Medium** (>90) / **Low** (>60).

Derived from the most recent installed hotfix. A patch gap widens exposure to every
vulnerability fixed since. A host that has stopped patching has usually also stopped
reporting to WSUS/Windows Update.

## Filesystem credentials (`CRED-002`)

**High**, Confidence Medium.

The credential datamine (`-DataminePasswords`) extended onto disk: credential-bearing
filenames (web.config, *.kdbx, id_rsa, .env, unattend.xml) and assignment-style patterns
inside config and script files. Like CRED-001, **the value is never written to the
report** - only the file, the line number, and a redacted preview. Scanning is bounded
by a root list, a file-size ceiling, and a findings cap.

## Offline CVE scan (`CVE-001`)

**High / Medium / Low**, by match confidence.

An offline vulnerability scan: the installed-software inventory (name + version) matched
against a local SQLite database built from MITRE's cvelistV5. Enabled with
`-IncludeCVEScan`; requires the PSSQLite module and the database, and skips gracefully if
either is absent.

Matching is deliberately conservative because a CVE feed keyed on free-text product
names is noisy:

- **Product**: normalised exact match is High confidence; substring containment is
  Medium.
- **Version**: parsed and tested against the `vulnerable_spec`. A range `Ver: X to <Y`
  is the half-open interval `[X, Y)` - the upper bound is exclusive. An exact `Ver: X`
  must equal the installed version. If a version cannot be parsed, the match is reported
  at **Low** confidence and flagged for manual triage rather than dropped or overstated.

**A CVE match is not proof of exploitability** - the vulnerable component may not be in
use or the code path may not be reachable. The recommendation is always "validate, then
patch", and severity tracks match confidence, not CVSS.

Build the database from https://github.com/CVEProject/cvelistV5 into the schema
`vulnerabilities(cve_id, product_name, vendor_name, vulnerable_spec)`.

## Attack path graph (`PATH-GRAPH`)

Built by the attack-path engine from group membership, ACL, and delegation edges. Where
`PATH-001` reports a single dangerous ACE, `PATH-GRAPH` reports the **whole multi-hop
chain** from a non-privileged principal to Tier 0 — the BloodHound-style view.

**Critical** for chains of two or more hops (a one-hop chain is already covered by
PATH-001). The evidence field prints the full path, e.g.
`jdoe -[GenericAll]-> HELPDESK -[MemberOf]-> Domain Admins`.

**Fix:** break the chain at its weakest link — usually a single delegated right or group
nesting mid-path, not the endpoint. Removing one edge severs every path through it.

The engine writes **`Attack_Paths.csv`**: one row per path with the source, the Tier 0
target, the hop count, the full chain written out, and `Break_At` naming the specific
link to cut.

---

## Reference

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
