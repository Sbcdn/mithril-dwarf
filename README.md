# mithril-dwarf

A cycle-optimized, allocation-free Cardano Mithril certificate verifier in Rust. Primary target: zkVM guests ([RISC Zero](https://risczero.com)). Verdicts are bit-equivalent to `mithril-common`'s `MithrilCertificateVerifier` and gated by an equivalence harness.

## At a glance

- Re-implementation of Mithril chain verification against the binary layer, no `serde` or canonical-JSON on the hot path.
- Custom zero-copy wire format: `CertificateZeroCopy<'a>` holds slice references into the source `&[u8]`.
- Tiered cheapest-first: invalid chains fail in `O(1)` comparisons before any cryptography runs.
- Bit-equivalent to upstream Mithril at pinned rev `7e787de` — verified per check and at the top level for every corpus cert and every mutation, plus a differential lottery fuzz against an arbitrary-precision re-port of upstream's eligibility check.
- Optional, off-by-default `tx-inclusion` / `tx-parsing` / `tx-components` features add Cardano transaction Merkle-inclusion proofs and byte-exact CBOR component extraction for downstream guests.

## Background

[Mithril](https://mithril.network/) is a stake-based threshold multi-signature protocol on Cardano. Stake pool operators sign individual messages, an aggregator combines them into a single multi-signature once enough stake has weighed in, and the result is a Mithril certificate attesting to some piece of Cardano state. Certificates are chained: each non-genesis cert is verified against the AVK certified in the previous epoch, and the chain terminates at a genesis cert signed with an Ed25519 key baked into the network's bootstrap.

Inside a zkVM, every cycle in this chain walk is proving cost. Generic crypto crates, heap-heavy `serde` deserialization, and canonical-JSON hashing multiply that cost. `mithril-dwarf` is a purpose-built verifier sized for that constraint.

## Architecture

```
src/
├── parser/
│   ├── byte_deserializer.rs      FastByteParser + CertificateZeroCopy views
│   ├── byte_serializer.rs        (host-only) Certificate → bytes
│   └── minimal_converter.rs      (host-only) bridges to mithril-common types
└── certificate_verification/
    ├── mod.rs                    verify_certificate{,_chain,_genesis,_standard}
    ├── basic_checks.rs           Phase 1 — comparisons
    ├── medium_checks.rs          Phase 2 — SHA-256 over canonical bytes
    ├── complex_checks.rs         Phases 3–4 — BLS, Merkle, lottery
    └── hash_sink.rs              streaming SHA-256 sink trait
```

[`byte_deserializer.rs`](src/parser/byte_deserializer.rs) defines the binary wire format and a hand-rolled `FastByteParser`. `CertificateZeroCopy<'a>` borrows every field — VK arrays, signature bytes, Merkle leaves — from the source buffer:

```rust
pub enum SignatureBasicZeroCopy<'a> {
    Genesis { signature_bytes: &'a [u8] },
    Multi   { signature: &'a [u8], /* ... */ },
}
```

The host-only `byte_serializer.rs` and `minimal_converter.rs` bridge from upstream's `CertificateMessage` into this format so chains pulled from an aggregator can feed the guest.

### Verification phases

[`verify_standard_certificate`](src/certificate_verification/mod.rs#L85) runs four phases in increasing cost order; each runs only if the cheaper phases passed.

| Phase | What it proves |
|------:|----------------|
| 1. Basic    | No self-chaining; epoch matches the protocol message; epoch chains (`E` or `E+1`); `previous_hash` links to `prev_cert`. |
| 2. Medium   | `certificate_hash` matches a recomputation; `signed_message == SHA256(protocol_message)`. Canonical bytes are hand-built; no `serde_json`. |
| 3. Chain    | Same-epoch: AVK and protocol params must match exactly. Cross-epoch: must match the `next_*` parts carried by the previous cert. |
| 4. BLS      | Aggregate BLS via `blst`; Merkle batch proof via Blake2b; lottery via Taylor-series `ln(1 − φ_f)` over rational arithmetic. |

[`VerifyError`](src/certificate_verification/mod.rs#L14) is a 4-byte `Copy` enum (pinned by a unit test); failure paths allocate nothing. The per-cert `ln(1 − φ_f)` and the per-signer `x = −w · c` are hoisted out of the inner loop, and the Taylor error-bound sequence is built once per signer and replayed across that signer's indices. The lottery (rational `exp(x)` comparison) and the BLS aggregate are the dominant cycle buckets and the focus of the optimization work.

## Public API

From [`src/lib.rs`](src/lib.rs):

```rust
pub use certificate_verification::{
    verify_certificate,            // dispatch on genesis vs. standard
    verify_certificate_chain,      // newest → oldest, walks to genesis
    verify_genesis_certificate,    // Ed25519 only
    verify_standard_certificate,   // BLS multi-sig only
};
pub use parser::{CertificateZeroCopy, certificate_from_bytes};
```

Minimal guest-side example:

```rust
use mithril_dwarf::{certificate_from_bytes, verify_certificate_chain};

fn verify(chain_bytes: &[&[u8]], genesis_vk: &[u8; 32])
    -> Result<(), mithril_dwarf::certificate_verification::VerifyError>
{
    let parsed: Vec<_> = chain_bytes
        .iter()
        .map(|b| certificate_from_bytes(b))
        .collect::<Result<_, _>>()
        .expect("malformed certificate bytes");
    verify_certificate_chain(&parsed, Some(genesis_vk))
}
```

With the `host` feature enabled, `certificate_to_bytes` and `minimal_converter` turn an upstream `Certificate` into the bytes the guest expects.

## Transaction inclusion & parsing

Three optional, off-by-default features let a downstream guest prove a Cardano transaction is included under a certified Mithril `CardanoTransactionsMerkleRoot` and extract its components — byte-equivalent to upstream Mithril and the Cardano ledger. They share none of the certificate path and add nothing to the default guest image.

- **`tx-inclusion`** — decode an `MKMapProof` (custom serde-free wire), `verify` / `contains` / `compute_root`, and the binding-folded entrypoints `verify_tx_inclusion_v1`/`_v2(proof, leaves, expected_root)`. The `compute_root() == expected_root` check is folded in so a guest cannot ship without binding to the certified feed.
- **`tx-parsing`** — `cardano_tx_id` (blake2b-256 over the original body CBOR) plus `script_hash` / `datum_hash`; the txid hasher pulls in no CBOR machinery.
- **`tx-components`** — `locate_tx_components` (byte-exact redeemer/datum/script sub-slices) and `verify_script_data`, via a `no_std` pallas Conway decode.

The `host` feature additionally exposes the proof and cost-model transcoders (`tx_proof_to_wire_v1`/`_v2`, `cost_models_to_wire`) and re-exports the Mithril fetch types, so a host needs no direct Mithril dependency.

The bindings are folded so the guest cannot skip them: inclusion proves the txid leaf is under the certified root, `cardano_tx_id` re-derives that txid from the body, and `verify_script_data` ties the witness-set redeemers and datums to the body's `script_data_hash`. Each step returns `Err` on mismatch — never a silent pass.

## Feature flags

| Feature   | Pulls in | When to enable |
|-----------|----------|----------------|
| *(default)* | `blake2`, `blst`, `sha2`, `ed25519-dalek`, `risc0-zkvm`, `crypto-ratio`, `fixed` | Guest verifier; this is what you compile into the RISC0 ELF. |
| `tx-inclusion` | `ckb-merkle-mountain-range` | Cardano tx set-proof `verify`/`contains`/`compute_root` + `verify_tx_inclusion_v1`/`_v2` (guest). |
| `tx-parsing` | `blake2` (already present) | `cardano_tx_id`, `script_hash`, `datum_hash` (guest). |
| `tx-components` | `pallas-primitives`, `pallas-codec`, `pallas-crypto` | `locate_tx_components`, `verify_script_data` — Conway CBOR decode (guest). |
| `host`    | `mithril-client`, `mithril-common`, `mithril-stm`, `anyhow` | Host glue: aggregator fetch, wire serialization, converter, and the tx proof/cost-model transcoders. |

The `host` feature tracks Mithril at a frozen rev on `Sbcdn/mithril.git` carrying `num-integer-backend` and crypto-version pins needed for clean RISC0 builds.

## Fetching real chains

The `fetch_certificates` binary lives in [`mithril-dwarf-harness`](mithril-dwarf-harness/), walks an aggregator from a given hash back to genesis, and serializes each cert as a `bincode` file under `tests/test_data/certificates/`.

```bash
cargo run -p mithril-dwarf-harness --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash 0b1ad46fd90bad9a8b52595c444e722fe8b0a883e1943f144481afc947ab369c

# Custom output directory, depth cap, alternate network:
cargo run -p mithril-dwarf-harness --bin fetch_certificates -- \
    --network preprod \
    --certificate-hash <hash> \
    --output-dir mithril-dwarf-harness/tests/test_data/preprod_certificates \
    --max-certificates 50
```

Supported networks: `mainnet`, `preprod`, `preview`. Aggregator URLs and genesis keys are baked into the binary. The diverse-corpus fetcher script at [`tests/test_data/fetch_diverse_corpus.sh`](mithril-dwarf-harness/tests/test_data/fetch_diverse_corpus.sh) pulls one chain per `SignedEntityType` variant plus a preprod chain — this is the shape the equivalence harness expects.

## Equivalence harness

The [`mithril-dwarf-harness`](mithril-dwarf-harness/) sub-crate is the ship gate. For every cert in the corpus it:

1. Runs every upstream check and records the canonical bytes.
2. Runs the matching dwarf check and records the canonical bytes.
3. Bitwise-compares per check, then bitwise-compares the top-level verdict.
4. Re-runs the same comparison against a mutation suite (~25 axes × N corpus certs) covering hashes, signature/AVK envelopes, epochs, protocol params, signer stake, `NextAvk` / `NextProtocolParameters` JSON, and BLS-algebraic mutations.

Hard-failure cases (the harness exits non-zero):

- **Critical** — upstream rejected, dwarf accepted (false positive; attacker-craftable).
- **Soundness regression** — dwarf rejected, upstream accepted.
- **Mutation insufficient** — both accepted; the mutation isn't actually adversarial.

Both impls rejecting with different `ErrorCategory` values is a **soft divergence** — surfaced in the report but verdict-equivalent.

A separate byte-level fuzz test mutates the raw dwarf wire bytes (no upstream gatekeeper) and asserts dwarf rejects, modelling the in-guest threat shape.

```bash
cargo test -p mithril-dwarf-harness --test equivalence
cargo test -p mithril-dwarf-harness --test intentional_divergences
cargo run  -p mithril-dwarf-harness --bin audit
```

The lottery is security-critical and the positive corpus cannot exercise its decision boundary, so the comparison primitive carries dedicated tests in [`src/certificate_verification/complex_checks.rs`](src/certificate_verification/complex_checks.rs) — heavy differential fuzz against an arbitrary-precision `num` re-port of upstream `mithril-stm`'s lottery, plus exact and near-equality pins against the underlying rational comparison. Run them with `cargo test --release -- --ignored`.

### Intentional divergences

The places where dwarf's observable behaviour or precision differs from upstream — BLS identity rejected at pairing time rather than at deserialise, asymmetric epoch-chaining, check ordering, usize-vs-u64 BLS scalar index width, bytewise NextAvk chain compare, and two numeric lottery approximations (`ev_max` and the U2048 wide-fallback ceiling) — are documented and pin-tested in [`tests/intentional_divergences.rs`](mithril-dwarf-harness/tests/intentional_divergences.rs). Each is verdict-equivalent (or strictly safer) on real chains; a corpus-wide gate catches any future change that breaks that equivalence.

### Upstream drift CI

[`.github/workflows/upstream-drift-check.yml`](.github/workflows/upstream-drift-check.yml) rebuilds the harness against `Sbcdn/mithril.git#main` instead of the pinned rev. A build or behaviour divergence fails the job and signals that the pin needs revisiting.

## Status

Pre-1.0 (`v0.2.0`). The `host` feature pins a frozen `Sbcdn/mithril.git` rev (`7e787de`); the guest-only default feature set does not depend on the fork.

On representative mainnet certificates, the standard-certificate verifier costs roughly half the RISC0 cycles it did at `v0.1.0` (~46–49% fewer), driven mostly by amortizing the per-signer lottery Taylor expansion and factoring the constant operand out of the per-index comparison. The lottery (`TaylorBounds`) and BLS aggregate remain the dominant buckets.

The RISC0 precompile patches for `ed25519-dalek`, `blst`, and `sha2` are intentionally commented out in [`Cargo.toml`](Cargo.toml) — they must be applied at the workspace level by the downstream guest consumer (e.g. `oaks_cert/guest`). See the comment block above the patches for the rationale.

Contributions, audits, and bug reports are welcome. The equivalence harness is the contract.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Torben Poguntke.
