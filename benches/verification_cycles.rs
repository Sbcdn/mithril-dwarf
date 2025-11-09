// benches/verification_cycles.rs

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use mithril_dwarf::{
    certificate_from_bytes,
    certificate_verification::{basic_checks, complex_checks, medium_checks},
};
use std::hint::black_box;

fn load_test_cert() -> Vec<u8> {
    hex::decode(CERT_BYTES).unwrap()
}

fn load_test_prev_cert() -> Vec<u8> {
    // You'll need to add the previous cert bytes
    hex::decode(PREV_CERT_BYTES).unwrap()
}

// === PHASE 1: BASIC CHECKS (~5K cycles) ===

#[library_benchmark]
fn bench_verify_not_infinite_loop() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let result = basic_checks::verify_not_infinite_loop(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_verify_epoch_matches() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let result = basic_checks::verify_epoch_matches_protocol_message(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_verify_epoch_chaining() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();
    let result = basic_checks::verify_epoch_chaining(black_box(&cert), black_box(&prev_cert));
    black_box(result);
}

#[library_benchmark]
fn bench_verify_previous_hash() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();
    let result =
        basic_checks::verify_previous_hash_matches(black_box(&cert), black_box(&prev_cert));
    black_box(result);
}

#[library_benchmark]
fn bench_all_basic_checks() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();

    let result = basic_checks::verify_not_infinite_loop(&cert)
        .and_then(|_| basic_checks::verify_epoch_matches_protocol_message(&cert))
        .and_then(|_| basic_checks::verify_epoch_chaining(&cert, &prev_cert))
        .and_then(|_| basic_checks::verify_previous_hash_matches(&cert, &prev_cert));

    black_box(result);
}

// === PHASE 2: MEDIUM CHECKS (~100K cycles) ===

#[library_benchmark]
fn bench_verify_hash_matches() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let result = medium_checks::verify_hash_matches_content(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_verify_signed_message() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let result = medium_checks::verify_signed_message_matches_protocol(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_all_medium_checks() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();

    let result = medium_checks::verify_hash_matches_content(&cert)
        .and_then(|_| medium_checks::verify_signed_message_matches_protocol(&cert));

    black_box(result);
}

// === PHASE 3: CHAIN VERIFICATION ===

#[library_benchmark]
fn bench_verify_avk_chain() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();

    let result = complex_checks::verify_avk_chain(black_box(&cert), black_box(&prev_cert));
    black_box(result);
}

#[library_benchmark]
fn bench_verify_protocol_params_chain() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();

    let result =
        complex_checks::verify_protocol_params_chain(black_box(&cert), black_box(&prev_cert));
    black_box(result);
}

// === PHASE 4: BLS VERIFICATION (~23M cycles) ===

#[library_benchmark]
fn bench_verify_bls_multisig() {
    let bytes = load_test_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();

    let result = complex_checks::verify_bls_multisig(black_box(&cert));
    black_box(result);
}

// === FULL VERIFICATION ===

#[library_benchmark]
fn bench_full_standard_verification() {
    let bytes = load_test_cert();
    let prev_bytes = load_test_prev_cert();
    let cert = certificate_from_bytes(black_box(&bytes)).unwrap();
    let prev_cert = certificate_from_bytes(black_box(&prev_bytes)).unwrap();

    use mithril_dwarf::certificate_verification::verify_standard_certificate;
    let result = verify_standard_certificate(black_box(&cert), black_box(&prev_cert));
    black_box(result);
}

library_benchmark_group!(
    name = basic_checks_benches;
    benchmarks =
        bench_verify_not_infinite_loop,
        bench_verify_epoch_matches,
        bench_verify_epoch_chaining,
        bench_verify_previous_hash,
        bench_all_basic_checks
);

library_benchmark_group!(
    name = medium_checks_benches;
    benchmarks =
        bench_verify_hash_matches,
        bench_verify_signed_message,
        bench_all_medium_checks
);

library_benchmark_group!(
    name = chain_checks_benches;
    benchmarks =
        bench_verify_avk_chain,
        bench_verify_protocol_params_chain
);

library_benchmark_group!(
    name = complex_checks_benches;
    benchmarks =
        bench_verify_bls_multisig
);

library_benchmark_group!(
    name = full_verification_benches;
    benchmarks =
        bench_full_standard_verification
);

main!(
    library_benchmark_groups = basic_checks_benches,
    medium_checks_benches,
    chain_checks_benches,
    complex_checks_benches,
    full_verification_benches
);

// You'll need to add the certificate bytes
const CERT_BYTES: &str = "400000006630623165636630646238383566313635613833646437633165623731303363663466353365663231623435333030633737386131626238356565376239333740000000363136626638376162393666633264313534633530666235353430616161333261343339636535616431636161373531653231663439653764363566363236325002000000000000070000006d61696e6e657405000000302e312e307609000000000000ed510000000000009a9999999999c93f..."; // Your full cert

const PREV_CERT_BYTES: &str = "..."; // Previous cert bytes
