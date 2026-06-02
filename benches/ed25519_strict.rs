// Host-side instruction-count comparison of `verify` (non-strict,
// cofactored) vs `verify_strict` (un-cofactored + small-order checks)
// on a representative legitimate Ed25519 signature. The genesis cert
// path in dwarf invokes this exactly once per chain.
//
// iai-callgrind reports x86_64 instruction counts; the *ratio* between
// the two paths is what carries over to the RISC0 RV32 cycle delta. The
// absolute zkVM cycle count must be confirmed downstream in `oaks_cert`
// with `--features guest-bench`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

const SEED: [u8; 32] = [42u8; 32];
const MSG: &[u8] = b"ed25519 strict-vs-legacy verify cycle pin";

fn fixture() -> (VerifyingKey, Signature) {
    let sk = SigningKey::from_bytes(&SEED);
    let vk = sk.verifying_key();
    let sig = sk.sign(MSG);
    (vk, sig)
}

#[library_benchmark]
#[bench::measure(fixture())]
fn bench_verify_legacy(input: (VerifyingKey, Signature)) {
    let (vk, sig) = input;
    let r = black_box(&vk).verify(black_box(MSG), black_box(&sig));
    black_box(r).unwrap();
}

#[library_benchmark]
#[bench::measure(fixture())]
fn bench_verify_strict(input: (VerifyingKey, Signature)) {
    let (vk, sig) = input;
    let r = black_box(&vk).verify_strict(black_box(MSG), black_box(&sig));
    black_box(r).unwrap();
}

library_benchmark_group!(
    name = ed25519_benches;
    benchmarks = bench_verify_legacy, bench_verify_strict
);

main!(library_benchmark_groups = ed25519_benches);
