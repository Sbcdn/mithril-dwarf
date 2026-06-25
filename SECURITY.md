# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue for a
security report.

- Preferred: GitHub private vulnerability reporting — the **Security** tab of
  this repository, **Report a vulnerability**.
- Alternatively: email <sbcdn@pm.me> with `[mithril-dwarf security]` in the
  subject line.

Include a description, the affected version or commit, and a reproduction (input
bytes, a failing vector, or a test) where possible. Reports are acknowledged, and
fixes are coordinated with the reporter before public disclosure.

## Scope

`mithril-dwarf` re-implements Cardano Mithril certificate verification and must
produce the same accept/reject verdict as upstream `mithril-common`'s
`MithrilCertificateVerifier`. The security-critical property is soundness:

> dwarf must never accept a certificate, or a lottery ticket, that upstream
> Mithril rejects.

In scope:

- A certificate dwarf accepts but upstream rejects — through any path: the BLS
  aggregate, the AVK Merkle proof, the certificate-hash preimage, or the BLS
  eligibility lottery.
- A difference in what enters a SHA-256 preimage, the canonical signed message,
  or a Merkle leaf, versus upstream. These are hashed bytes and must be identical.
- A lottery or threshold miscomputation that admits an ineligible signer.
- A panic, out-of-bounds access, or non-termination reachable from
  attacker-controlled certificate bytes. The verifier runs as zkVM proving cost;
  a panic aborts proof generation.

The equivalence contract is enforced by the harness in `mithril-dwarf-harness/`:
byte-equivalence over a real-certificate corpus, a mutation suite, and a
differential lottery fuzz against an arbitrary-precision re-port of upstream's
eligibility check. The pinned upstream revision is recorded in `Cargo.toml`.

## Out of scope, or by design

- Documented intentional divergences. Some checks are deliberately leaner than
  upstream as zkVM cycle trade-offs; each is registered, bounded, and pin-tested
  in
  [`mithril-dwarf-harness/tests/intentional_divergences.rs`](mithril-dwarf-harness/tests/intentional_divergences.rs).
  Each is verdict-equivalent, or strictly more conservative, on real chains. A
  report that one of them changes the verdict on a real certificate is in scope;
  the existence of a documented, behaviour-preserving divergence is not.
- The U2048 lottery wide-fallback ceiling. An eligibility computation whose
  intermediate values exceed U2048 aborts rather than deciding; it never falsely
  accepts. This is unreachable for any production stake distribution (see the
  lottery notes in `src/certificate_verification/complex_checks.rs`).
- Cryptographic primitives. The BLS (`blst`), SHA-256 (`sha2`), Blake2
  (`blake2`), Ed25519 (`ed25519-dalek`), and RISC Zero precompile implementations
  are dependencies and assumed correct. Report primitive bugs to their projects.
- Host-only tooling. The harness, fetchers, and serializers behind the `host`
  feature are developer tooling, not part of the guest verifier.

## Supported versions

This crate is pre-1.0. Security fixes land on `main`; only the latest release is
supported.
