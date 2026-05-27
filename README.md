# mithril-dwarf

A cycle-optimized, allocation-free Mithril certificate verifier in Rust — small enough to live inside a zkVM guest, faithful enough to accept the same chains a stock Mithril client would.

The name fits the role: **dwarf**, because the goal is to compress a piece of Mithril verification into the smallest, densest, most cycle-frugal shape that still produces a bit-identical answer.

---

## At a glance

- Re-implementation of Mithril's certificate-chain verification logic, written from scratch against the binary layer rather than via `serde`/`mithril-common`.
- Designed for **zkVM guests** (primary target: [RISC Zero](https://risczero.com)) and other compute-constrained environments where every cycle and every heap allocation costs.
- **Bit-identical to upstream** — every intermediate hash, lottery outcome, AVK transition and BLS aggregate is checked against `mithril-common`'s `MithrilCertificateVerifier` in the equivalence harness.
- Custom **zero-copy wire format** for certificates: a `CertificateZeroCopy` is just typed views into a `&[u8]`. No heap, no `serde`, no JSON parser on the hot path.
- Verification is **tiered cheapest-first** so invalid chains fail in the comparison phase, before any cryptography runs.

---

## Background: what's being verified?

[Mithril](https://mithril.network/) is a stake-based threshold multi-signature protocol layered on Cardano. Stake pool operators (SPOs) act as **signers**; an **aggregator** collects their individual signatures and combines them into a single multi-signature once enough stake has weighed in. The artifact that comes out the other end is a **Mithril certificate** — a small, signed object that attests to some piece of Cardano state (a database snapshot digest, a stake distribution, a transaction-set commitment, etc.).

Certificates are **chained**. Each non-genesis certificate is verified using the aggregate verification key (AVK) that was certified in the previous epoch, and the chain terminates at a **genesis certificate** signed with an Ed25519 key baked into the network's bootstrap parameters. A client that wants to trust an artifact walks the chain backward to genesis, verifying every link.

That walk is what `mithril-dwarf` does — just faster and leaner.

### Why care about cycles?

Inside a zkVM, "cycles" are the proving cost. Verifying a Mithril chain with the stock `mithril-client` is correct but expensive: generic crypto crates, heap-heavy `serde` deserialization, and canonical-JSON hashing all multiply the cycle count, and cycle count maps approximately linearly to proving time and dollars. A purpose-built verifier is the difference between "it proves" and "it proves cheaply enough to ship."

The same properties — small static binary, no allocator, predictable cost — make the crate friendly for embedded and bare-metal use cases too, even if RISC Zero is the named target.

---

## Architecture

```
src/
├── parser/                       zero-copy binary deserializer
│   ├── byte_deserializer.rs      FastByteParser + CertificateZeroCopy views
│   ├── byte_serializer.rs        (host-only) Certificate → bytes
│   └── minimal_converter.rs      (host-only) bridges to mithril-common types
└── certificate_verification/
    ├── mod.rs                    verify_certificate{,_chain,_genesis,_standard}
    ├── basic_checks.rs           Phase 1 — comparisons
    ├── medium_checks.rs          Phase 2 — SHA-256 over canonical bytes
    └── complex_checks.rs         Phases 3–4 — BLS, Merkle proofs, lottery
```

### The parser

[src/parser/byte_deserializer.rs](src/parser/byte_deserializer.rs) defines a custom binary representation of a Mithril certificate and a hand-rolled `FastByteParser` that walks it without allocating. The output, `CertificateZeroCopy<'a>`, holds slice references into the original `&[u8]` — VK arrays, signature bytes, Merkle tree leaves, and so on are all borrowed, never copied. The signature variant is captured as an enum so genesis (Ed25519) and standard (BLS aggregate) certificates can be discriminated without re-parsing:

```rust
pub enum SignatureBasicZeroCopy<'a> {
    Genesis { signature_bytes: &'a [u8] },
    Multi   { signature: &'a [u8], /* ... */ },
}
```

The host-only `byte_serializer.rs` and `minimal_converter.rs` exist purely to convert from `mithril-common`'s `CertificateMessage` into this binary format — they're how real chains pulled from an aggregator get fed to the guest.

### The verification tiers

`verify_standard_certificate` in [src/certificate_verification/mod.rs:92](src/certificate_verification/mod.rs#L92) is structured as four phases ordered by cost. Each phase only runs if the cheaper phases passed:

| Phase | What it proves |
|------:|----------------|
| 1. Basic checks    | Hash isn't pointing at itself; epoch matches the protocol message; epoch chains correctly (`E` or `E+1`); `previous_hash` links to `prev_cert`. |
| 2. Medium checks   | `certificate_hash` matches a recomputation of the hash; `signed_message == SHA256(protocol_message)` (the next AVK is itself one of the protocol-message parts). SHA-256 runs over hand-built canonical bytes — no `serde_json`. |
| 3. Chain checks    | Same epoch ⇒ AVK and protocol params must match exactly; epoch boundary ⇒ they must match the `next_*` fields carried in the previous certificate. |
| 4. BLS multi-sig   | Aggregate BLS verification via `blst`, Merkle batch proof via Blake2b, lottery check via Taylor-series `ln(1 - φ_f)` over rational arithmetic. |

Two design choices are worth flagging:

- **Lightweight error type.** [`VerifyError`](src/certificate_verification/mod.rs#L13) is a `Copy` enum that fits in 4 bytes (tested explicitly). No string allocation on failure paths — failure reasons survive the trip back from a guest without dragging a heap with them.
- **Cached lottery math.** `ln(1 - φ_f)` is the same for every certificate with the same protocol params, so the result is cached per-φ_f. Combined with rational arithmetic via the [`crypto-ratio`](https://crates.io/crates/crypto-ratio) crate (rather than `num-bigint`), the lottery check is the largest single source of speedup vs. the upstream reference path.

---

## Public API

The crate's surface is small. From [src/lib.rs](src/lib.rs):

```rust
pub use certificate_verification::{
    verify_certificate,            // dispatch on genesis vs. standard
    verify_certificate_chain,      // newest → oldest, walks to genesis
    verify_genesis_certificate,    // Ed25519 only
    verify_standard_certificate,   // BLS multi-sig only
};
pub use parser::{CertificateZeroCopy, certificate_from_bytes};
```

A minimal guest-side example:

```rust
use mithril_dwarf::{certificate_from_bytes, verify_certificate_chain};

// `chain_bytes` is a Vec<&[u8]>, newest certificate first.
// `genesis_vk` is the 32-byte Ed25519 verification key for the target network.
fn verify(chain_bytes: &[&[u8]], genesis_vk: &[u8; 32]) -> Result<(), mithril_dwarf::certificate_verification::VerifyError> {
    let parsed: Vec<_> = chain_bytes
        .iter()
        .map(|b| certificate_from_bytes(b))
        .collect::<Result<_, _>>()
        .expect("malformed certificate bytes");

    verify_certificate_chain(&parsed, Some(genesis_vk))
}
```

On the host side (with the `host` feature enabled), `certificate_to_bytes` and the converter module in [src/parser/](src/parser/) let you turn a `mithril-common` `Certificate` into the bytes the guest expects.

---

## Feature flags

The default build is intentionally lean so the guest binary stays small. Heavyweight dependencies are opt-in.

| Feature   | Pulls in | When to enable it |
|-----------|----------|-------------------|
| *(default)* | `blake2`, `blst`, `sha2`, `ed25519-dalek`, `risc0-zkvm`, `crypto-ratio`, `fixed` | The guest-only verifier. This is what you compile into your RISC0 ELF. |
| `host`    | `mithril-client`, `mithril-common`, `mithril-stm`, `anyhow` | Host-side glue: fetching real certificates from an aggregator, serializing them to the wire format, running the converters. |
| `tests`   | `host` + `reqwest`, `tokio`, `clap`, `serde`, `serde_json`, `bincode`, `slog` | Required for the `fetch_certificates` binary and the equivalence test harness. |

> **Note.** The `host` feature pulls Mithril from a tracked fork: `Sbcdn/mithril.git@mithril_risc0`. The fork exists to expose `num-integer-backend` and ed25519/blst version pinning needed for the RISC Zero precompiles. See [Status](#status) below.

---

## Fetching real chains

The `fetch_certificates` binary walks an aggregator backward from a given certificate hash to genesis and serializes each certificate as a `bincode` file under `tests/test_data/certificates/` (or wherever `--output-dir` points). It also emits a JSON metadata file with the network, genesis key, and chain stats. This is how the equivalence-test corpus is built.

```bash
# Pull a mainnet chain
cargo run -F tests --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash 0b1ad46fd90bad9a8b52595c444e722fe8b0a883e1943f144481afc947ab369c

# Same on preprod, with a custom output directory
cargo run -F tests --bin fetch_certificates -- \
    --network preprod \
    --certificate-hash <hash> \
    --output-dir tests/test_data/preprod_certificates

# Limit how far back the walk goes
cargo run -F tests --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash <hash> \
    --max-certificates 50
```

Supported networks are `mainnet`, `preprod`, and `preview`; aggregator URLs and genesis keys for each are baked into the binary.

---

## Equivalence testing

The correctness story is held together by `tests/equivalence_tests.rs`. For every certificate in the test corpus, the harness:

1. Loads the original `CertificateMessage` from disk.
2. Runs upstream `mithril-common`'s `MithrilCertificateVerifier`, capturing every intermediate value the implementation can hand back (signed message, hash, AVK transitions, lottery results, batch-proof outcomes).
3. Converts the same certificate into the zero-copy wire format and runs `mithril-dwarf`'s verifier.
4. Asserts the two implementations agree at every step — not just the final pass/fail, but each intermediate computation.

> **First-time setup:** the test corpus under `tests/test_data/certificates/` is not committed. Populate it with the [`fetch_certificates`](#fetching-real-chains) binary before running the suite.

```bash
cargo test -F tests --test equivalence_tests
```

If you change anything in `certificate_verification/` or `parser/`, this is the suite that decides whether the change preserves the chain semantics. Any divergence — a different hash, a different lottery outcome, a different rejection reason — is a failure.

The supporting benchmarks live in [benches/](benches/) and cover parsing, per-check cycle costs, and side-by-side performance against the reference path.

---

## Status

This crate is **pre-1.0** (`v0.1.0`) and tracks a specific Mithril branch — the `host` and `tests` features pin against `Sbcdn/mithril.git@mithril_risc0`, which carries the `num-integer-backend` and crypto-version patches needed for clean RISC Zero builds. The guest-side surface (default feature set) does not depend on that fork.

The RISC Zero precompile story for `ed25519-dalek`, `blst`, and `sha2` is currently handled via the commented `[patch.crates-io]` block in [Cargo.toml](Cargo.toml#L34-L37); integrators building a guest binary will typically want to re-enable equivalents in the workspace where the patch can take effect.

Contributions, audits, and bug reports are welcome — the equivalence harness is the contract; if you can break it, please open an issue.
