# Security policy

## Supported versions

Security fixes are prioritized for the latest published version of ThreatJET.
Older builds may not receive backported fixes. See [Releases](https://github.com/d33p-d1sh/ThreatJet/releases)
for the latest published version. Until the first GitHub Release, the `main`
branch is development code, not a supported release.

## Reporting a vulnerability privately

**Do not open a public GitHub issue with an unpatched security vulnerability.**

1. Visit the repository's [Security](https://github.com/d33p-d1sh/ThreatJet/security) tab.
2. Use **Report a vulnerability** / private vulnerability reporting, if enabled.
3. Include the affected version or commit, impact, minimal reproduction, and
   proposed mitigation, without submitting live credentials or sensitive data.
4. If private vulnerability reporting is unavailable, do not publish exploit
   details in Issues. Request a private contact channel from the maintainer
   without disclosing the vulnerability itself.

Please allow time for validation and coordinated disclosure. No fixed response
or remediation SLA is promised.

## Scope and responsible use

ThreatJET is a read-only assessment utility but can enumerate sensitive
Active Directory topology, identities, and privilege relationships. Assessment
output and logs may contain highly sensitive environment data.

- Never submit real assessment CSVs, reports, credentials, hashes, or domain
  inventories to public issues, pull requests, or CI logs.
- Use only authorized environments. Reproduce reports with fabricated data or
  a disposable lab where possible.
- Generated remediation commands are guidance for human review; do not
  execute them blindly.

## Dependencies and feeds

The CVE database builder consumes external CVE/KEV/EPSS data. Validate sources
and inputs before processing, and avoid publishing proprietary or sensitive
copies of generated assessment data.
