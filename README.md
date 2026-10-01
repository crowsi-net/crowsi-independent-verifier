# Crowsi Independent Verifier

This crate verifies signed state read-back and intrusion evidence without
trusting a PEP receipt. Evidence is accepted only when its sensor key,
capability, security domain, canonical resource URI, provenance, freshness,
deployment, and signature match a pinned trust registration. Resource
authorization is exact; textual URI prefixes never grant access to sibling
resources.

Isolation is `verified` only after at least two configured, distinct
independence groups agree on the command, state, exact opaque provider resource
version, and minimum fence. The same minimum applies to a clear intrusion
assessment; one trusted detection is still surfaced immediately. Numeric
ordering is never inferred from ETags or other provider-native versions.
Contradictory quorum is reported explicitly. Missing, stale, forged,
same-group, or disconnected evidence remains `unknown`.

A single trusted IDS detection is surfaced immediately. A clear assessment
requires fresh evidence from the configured number of independent groups.
Signed artifacts and sensor time watermarks are journaled in SQLite to reject
identifier collision and rollback. Multiple overlapping keys may be
registered for one sensor only when all independence claims remain identical.

`verify_signed_readback` emits the closed
`crowsi.signed-readback-report.v1` artifact. It binds command, domain,
deployment, resource, expected state, exact provider version, fence, quorum,
evaluation and expiry times, and sorted accepted-evidence digests. Signing is
delegated through `ReportSigningPort` to an HSM, TPM, or credential broker and
verified against `TrustedReportKey`. The production library exposes no
software private-key constructor. Report key identifiers and public material
must also be distinct from every registered sensor key, preventing one
credential from asserting both observation and independent aggregation roles.
`TrustedReportKey::verify_signature` proves authenticity and context integrity,
not freshness; runtime consumers must enforce `expires_at_ms` with a durable
trusted clock.

`fixtures/conformance/v1/signed-readback-report-v1.json` is the byte-stable,
actually signed consumer fixture. Its public-only verification metadata is in
`readback-report-trust-manifest-v1.json`; the closed manifest schema is
published under `schemas/`. A generation test reconstructs and verifies those
exact bytes. Conformance private keys exist only in test code.

Production verification time is owned by a sealed system-clock boundary and
durably watermarked in the evidence SQLite journal. Debug tests may use a
fixed clock; production callers cannot inject `now`.

The local conformance sample performs no network access:

```bash
cargo run --offline --quiet -- sample
```

## Verification

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
```
