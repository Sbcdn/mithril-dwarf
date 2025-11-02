// benches/verification_comparison.rs

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use mithril_common::certificate_chain::{CertificateVerifier, MithrilCertificateVerifier};
use mithril_common::entities::Certificate;
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::{
    certificate_from_bytes_fast, certificate_verification::verify_standard_certificate,
};
use once_cell::sync::Lazy;
use std::hint::black_box;
use std::sync::Arc;

// === COMPILE-TIME CONSTANTS (zero runtime cost!) ===

static OUR_CERT_BYTES: &[u8] = include_bytes!("data/cert_current.bin");
static OUR_PREV_BYTES: &[u8] = include_bytes!("data/cert_previous.bin");
static MITHRIL_CERT_BYTES: &[u8] = include_bytes!("data/mithril_current.bin");
static MITHRIL_PREV_BYTES: &[u8] = include_bytes!("data/mithril_previous.bin");

// Parse Mithril certs once at startup
static MITHRIL_CERTS: Lazy<(Certificate, Certificate)> = Lazy::new(|| {
    let cert: CertificateMessage = bincode::deserialize(MITHRIL_CERT_BYTES).unwrap();
    let prev: CertificateMessage = bincode::deserialize(MITHRIL_PREV_BYTES).unwrap();
    (cert.try_into().unwrap(), prev.try_into().unwrap())
});

// === MITHRIL ORIGINAL BENCHMARKS ===

#[library_benchmark]
fn bench_mithril_parsing_only() {
    let cert: CertificateMessage = black_box(bincode::deserialize(MITHRIL_CERT_BYTES).unwrap());
    let prev: CertificateMessage = black_box(bincode::deserialize(MITHRIL_PREV_BYTES).unwrap());
    let cert: Certificate = black_box(cert.try_into().unwrap());
    let prev: Certificate = black_box(prev.try_into().unwrap());
    black_box((cert, prev));
}

#[library_benchmark]
fn bench_mithril_verification_debug() {
    let cert = &MITHRIL_CERTS.0;
    let prev = &MITHRIL_CERTS.1;

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let retriever = Arc::new(create_mock_retriever(prev));
    let verifier = MithrilCertificateVerifier::new(logger, retriever);

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { verifier.verify_standard_certificate(cert, prev).await });

    // CHECK THE RESULT!
    match result {
        Ok(_) => eprintln!("✅ Verification passed"),
        Err(e) => {
            eprintln!("❌ Verification failed: {:?}", e);
            panic!("Verification error: {:?}", e);
        }
    }

    black_box(result);
}

#[library_benchmark]
fn bench_mithril_full_verification() {
    // Parse first
    let cert: CertificateMessage = bincode::deserialize(MITHRIL_CERT_BYTES).unwrap();
    let prev: CertificateMessage = bincode::deserialize(MITHRIL_PREV_BYTES).unwrap();
    let cert: Certificate = cert.try_into().unwrap();
    let prev: Certificate = prev.try_into().unwrap();

    // Then verify
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let retriever = Arc::new(create_mock_retriever(&prev));
    let verifier = MithrilCertificateVerifier::new(logger, retriever);

    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        verifier
            .verify_standard_certificate(black_box(&cert), black_box(&prev))
            .await
    });

    black_box(result);
}

#[library_benchmark]
fn bench_mithril_verification_only() {
    let cert = &MITHRIL_CERTS.0;
    let prev = &MITHRIL_CERTS.1;

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let retriever = Arc::new(create_mock_retriever(prev));
    let verifier = MithrilCertificateVerifier::new(logger, retriever);

    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        verifier
            .verify_standard_certificate(black_box(cert), black_box(prev))
            .await
    });

    black_box(result);
}

#[library_benchmark]
fn bench_mithril_hash_only() {
    let cert = &MITHRIL_CERTS.0;
    let computed_hash = black_box(cert.compute_hash());
    let result = computed_hash == cert.hash;
    black_box(result);
}

#[library_benchmark]
fn bench_mithril_bls_only() {
    let cert = &MITHRIL_CERTS.0;
    if let mithril_common::entities::CertificateSignature::MultiSignature(_, multi_sig) =
        &cert.signature
    {
        let result = multi_sig.verify(
            black_box(cert.signed_message.as_bytes()),
            black_box(&cert.aggregate_verification_key),
            black_box(&cert.metadata.protocol_parameters.clone().into()),
        );
        black_box(result);
    }
}

// === OUR OPTIMIZED BENCHMARKS ===

#[library_benchmark]
fn bench_our_parsing_only() {
    // JUST parsing - ~500K instructions
    let cert = certificate_from_bytes_fast(black_box(OUR_CERT_BYTES));
    let prev = certificate_from_bytes_fast(black_box(OUR_PREV_BYTES));
    black_box((cert, prev));
}

#[library_benchmark]
fn bench_our_full_verification() {
    // Parse + verify
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    let result = verify_standard_certificate(black_box(&cert), black_box(&prev));
    black_box(result);
}

#[library_benchmark]
fn bench_our_verification_only() {
    // Parse first (one-time cost)
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    // JUST verification (what we measure)
    let result = verify_standard_certificate(black_box(&cert), black_box(&prev));
    black_box(result);
}

#[library_benchmark]
fn bench_our_basic_checks() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;

    let result = verify_not_infinite_loop(black_box(&cert))
        .and_then(|_| verify_epoch_matches_protocol_message(black_box(&cert)))
        .and_then(|_| verify_epoch_chaining(black_box(&cert), black_box(&prev)))
        .and_then(|_| verify_previous_hash_matches(black_box(&cert), black_box(&prev)));

    black_box(result);
}

#[library_benchmark]
fn bench_our_medium_checks() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::medium_checks::*;

    let result = verify_hash_matches_content(black_box(&cert))
        .and_then(|_| verify_signed_message_matches_protocol(black_box(&cert)));

    black_box(result);
}

#[library_benchmark]
fn bench_our_chain_checks() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;

    let result = verify_avk_chain(black_box(&cert), black_box(&prev))
        .and_then(|_| verify_protocol_params_chain(black_box(&cert), black_box(&prev)));

    black_box(result);
}

#[library_benchmark]
fn bench_our_bls_only() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;
    let result = verify_bls_multisig(black_box(&cert));
    black_box(result);
}

// === INDIVIDUAL CHECK BENCHMARKS (for detailed profiling) ===

#[library_benchmark]
fn bench_check_infinite_loop() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;
    let result = verify_not_infinite_loop(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_check_epoch_matches() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;
    let result = verify_epoch_matches_protocol_message(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_check_epoch_chaining() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;
    let result = verify_epoch_chaining(black_box(&cert), black_box(&prev));
    black_box(result);
}

#[library_benchmark]
fn bench_check_previous_hash() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;
    let result = verify_previous_hash_matches(black_box(&cert), black_box(&prev));
    black_box(result);
}

#[library_benchmark]
fn bench_check_hash_matches() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::medium_checks::*;
    let result = verify_hash_matches_content(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_check_signed_message() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::medium_checks::*;
    let result = verify_signed_message_matches_protocol(black_box(&cert));
    black_box(result);
}

#[library_benchmark]
fn bench_check_avk_chain() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;
    let result = verify_avk_chain(black_box(&cert), black_box(&prev));
    black_box(result);
}

#[library_benchmark]
fn bench_check_protocol_params() {
    let cert = certificate_from_bytes_fast(OUR_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes_fast(OUR_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;
    let result = verify_protocol_params_chain(black_box(&cert), black_box(&prev));
    black_box(result);
}

// === HELPER ===

use async_trait::async_trait;
use mithril_common::certificate_chain::{CertificateRetriever, CertificateRetrieverError};

struct MockRetriever {
    prev_cert: Certificate,
}

#[async_trait]
impl CertificateRetriever for MockRetriever {
    async fn get_certificate_details(
        &self,
        _hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        Ok(self.prev_cert.clone())
    }
}

fn create_mock_retriever(prev_cert: &Certificate) -> MockRetriever {
    MockRetriever {
        prev_cert: prev_cert.clone(),
    }
}

// === BENCHMARK GROUPS ===

library_benchmark_group!(
    name = mithril_original;
    benchmarks =
        bench_mithril_parsing_only,
        bench_mithril_verification_debug,
        bench_mithril_full_verification,
        bench_mithril_verification_only,
        bench_mithril_hash_only,
        bench_mithril_bls_only
);

library_benchmark_group!(
    name = our_full;
    benchmarks =
        bench_our_parsing_only,
        bench_our_full_verification,
        bench_our_verification_only
);

library_benchmark_group!(
    name = our_phases;
    benchmarks =
        bench_our_basic_checks,
        bench_our_medium_checks,
        bench_our_chain_checks,
        bench_our_bls_only
);

library_benchmark_group!(
    name = individual_checks;
    benchmarks =
        bench_check_infinite_loop,
        bench_check_epoch_matches,
        bench_check_epoch_chaining,
        bench_check_previous_hash,
        bench_check_hash_matches,
        bench_check_signed_message,
        bench_check_avk_chain,
        bench_check_protocol_params
);

main!(
    library_benchmark_groups = mithril_original,
    our_full,
    our_phases,
    individual_checks
);
