# Security boundary

The verifier library contains no sensor or report private keys and exposes no
raw-seed signer. Software signers exist only inside conformance tests and the
local-only CLI sample. Real sensors and `ReportSigningPort` implementations
must keep keys in a TPM, HSM, or equivalent non-exportable workload identity
boundary.

Independence groups are security assertions, not labels to infer
automatically. Operators must prove that quorum members do not share the same
host, credential, control plane, telemetry source, or failure domain.
`TrustStore` rejects reuse of one public key under another key ID, sensor, or
independence group. Each resource URI is registered as one canonical,
exact-match authorization scope. The report-signing role must not reuse any
sensor key identifier or public key material; signed report generation rejects
either collision.

Provider-native resource versions are opaque strings. Read-back requires exact
equality with the version bound to the command or receipt; the verifier never
uses lexical or numeric ordering for ETags and similar values.

Signed read-back reports include the accepted sensor evidence digests and all
command/deployment/resource/CAS/quorum/time context. Consumers must pin
`TrustedReportKey`, call the explicitly authenticity-only
`verify_signature`, and reject it at expiry using a durable trusted clock.
The local trusted-clock watermark rejects host-clock rollback across process
restart; an external signed time or rollback anchor is still required against
full database rollback.

Production use additionally requires:

- a signed, rollback-resistant trust bundle with revocation and rotation;
- independent remote IDS or network telemetry;
- protected trusted time;
- append-only external anchoring of the local evidence journal;
- sensor liveness monitoring and explicit `unknown` on loss;
- a tested management lifeline and Rescue Console.

Report suspected bypasses privately without credentials, customer identifiers,
addresses, or raw telemetry.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
