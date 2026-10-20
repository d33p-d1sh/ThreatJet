# Changelog

Notable changes are recorded here. Version numbers follow the version embedded
in the standalone `ThreatJet.ps1` build. A version in source code is **not**
necessarily a published GitHub Release.

## [Unreleased]

### Added
- GitHub Actions syntax checks, Pester smoke tests, and advisory
  PSScriptAnalyzer diagnostics.
- Security disclosure policy, contributing guide, issue and pull-request
  templates, and a release checklist.
- README project branding and documentation navigation.

### Changed
- README configuration example aligned with the current standalone script
  (`CollectorVersion` / `CorrelationVersion` 2.4.0; `SchemaVersion` 1.6).

## [2.4.0] — source version, not yet tagged as a GitHub Release

- Standalone PowerShell 5.1+ assessment with LDAP/ADSI collection,
  misconfiguration findings, attack-path correlation, offline CVE matching,
  reporting, and guarded remediation guidance.
- See the [README](README.md) for the current feature set and limitations.

> Historical release notes will be expanded as versioned releases are
> published. This changelog does not imply that older versions were released
> on GitHub.
