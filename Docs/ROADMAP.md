# Recommended Improvements

Prioritised. Work top-down.

## Tier 0 — Before production use

### 1. Validate the collection layer against a lab domain
The offline pipeline is smoke-tested; **the collectors have never touched live AD**.
See [VALIDATION.md](VALIDATION.md) Stage 3. The `Retrieval_Principals` serialisation
question is the most likely thing to silently break a detection.

### 2. Multi-domain support (`-Server` / `-Credential`)
Every `Get-AD*` call targets the current domain implicitly. In a multi-domain forest
you can only assess the domain you are joined to, and cannot use alternate
credentials. Add both parameters to `Export-ThreatJetData` and splat them through
all nine collectors.

### 3. Restrict output directory permissions at creation
The CSVs are a complete map of your privilege structure. Set a restrictive ACL when
the directory is created rather than relying on the operator to remember.

## Tier 1 — Detection quality

### 4. Resolve group-based PSO inheritance
Closes the ID-011 limitation. Expand group membership (including nesting) and match
against PSO `AppliesTo`. Confidence then rises from Medium to High.

### 5. Parse `msDS-KeyCredentialLink` blobs
ID-008/INF-005 currently report *presence*, which is noisy wherever Windows Hello is
deployed. Parsing yields creation time and device ID, enabling a real detection:
*key credential added recently by an unexpected principal* → Critical.

### 6. ADCS certificate template abuse (ESC1–ESC14)
The largest coverage gap. `Has_ADCS` is collected but nothing acts on it.
Misconfigured templates are among the most reliably exploitable AD escalation paths.

### 7. Nested group expansion for Tier 0
A group nested inside Domain Admins confers the same privilege but is not itself
flagged, so its members are invisible to the privilege model. Compute effective
membership transitively.

### 8. Cheap missing detections
Data already collected: DOM-002 (Protected Users unused), DOM-003 (ADCS present),
GRP-003 (Tier 0 nested outbound), ID-003 (orphaned adminCount).

## Tier 2 — Scale

### 9. Replace `-Properties *` in `Collect-ServiceAccounts`
The last wildcard fetch. Slow, and serialises attributes you do not need into a
sensitive file.

### 10. Stream to CSV for large estates
Above ~50k objects, collectors build the full result set in memory before writing.

### 11. Parallel collection on PowerShell 7
The nine collectors are independent. Keep a sequential 5.1 fallback.

## Tier 3 — Reporting

### 12. Executive summary in the HTML report
Top 5 risks in plain language, remediation effort, trend vs baseline. For most
audiences this is the only page that gets read.

### 13. Attack path graph export
PATH-001 findings are edges. BloodHound-compatible JSON or Mermaid is far more
persuasive than a table of ACEs.

### 14. Restore control framework mapping
The original monolith carried a `Control_Mapping` field (NIST/CIS) that the refactor
dropped. For compliance-driven engagements it is often what makes findings actionable.

### 15. SIEM-friendly output
Newline-delimited JSON alongside the CSV.

## Tier 4 — Engineering

### 16. Pester unit tests alongside the smoke test
Priority cases: the SID namespace distinction (a domain SID ending `-544` must not be
Tier 0) and SIDHistory whole-SID matching.

### 17. CI on every commit
`Test-Syntax.ps1` + `Invoke-SmokeTest.ps1` on a Windows runner. This codebase has
shipped a load-breaking change more than once; CI catches that class immediately.

### 18. Signed releases
Removes the `Unblock-File` step and matters for enterprise deployment.

## Known architectural debt

**Thresholds are code, not data.** Severity assignments live inline in each detector.
A rules file would let assessors tune per engagement without editing PowerShell.

**No incremental collection.** Every run is a full enumeration; `uSNChanged` deltas
would make frequent runs practical.
