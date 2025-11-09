//! Performance comparison between Mithril and mithril-dwarf implementations
//! Uses the same certificate data as equivalence tests

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use mithril_common::certificate_chain::{CertificateVerifier, MithrilCertificateVerifier};
use mithril_common::entities::Certificate;
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::{
    certificate_from_bytes, certificate_to_bytes_opt,
    certificate_verification::verify_standard_certificate,
};
use once_cell::sync::Lazy;
use std::sync::Arc;

// Load test certificates at compile time
static MITHRIL_CERT_BYTES: &[u8] = include_bytes!("../tests/test_data/mithril_current.bin");
static MITHRIL_PREV_BYTES: &[u8] = include_bytes!("../tests/test_data/mithril_previous.bin");

// Parse certificates once at startup
static MITHRIL_CERTS: Lazy<(Certificate, Certificate)> = Lazy::new(|| {
    let cert: CertificateMessage = bincode::deserialize(MITHRIL_CERT_BYTES).unwrap();
    let prev: CertificateMessage = bincode::deserialize(MITHRIL_PREV_BYTES).unwrap();
    (cert.try_into().unwrap(), prev.try_into().unwrap())
});

// Pre-serialize to dwarf format
static DWARF_CERT_BYTES: Lazy<Vec<u8>> = Lazy::new(|| certificate_to_bytes_opt(&MITHRIL_CERTS.0));

static DWARF_PREV_BYTES: Lazy<Vec<u8>> = Lazy::new(|| certificate_to_bytes_opt(&MITHRIL_CERTS.1));

// ============================================================================
// MITHRIL ORIGINAL BENCHMARKS
// ============================================================================

#[library_benchmark]
fn bench_mithril_full_verification() {
    let cert = &MITHRIL_CERTS.0;
    let prev = &MITHRIL_CERTS.1;

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let retriever = Arc::new(create_mock_retriever(prev));
    let verifier = MithrilCertificateVerifier::new(logger, retriever);

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { verifier.verify_standard_certificate(cert, prev).await });

    std::hint::black_box(result);
}

#[library_benchmark]
fn bench_mithril_parsing() {
    let cert: CertificateMessage = bincode::deserialize(MITHRIL_CERT_BYTES).unwrap();
    let prev: CertificateMessage = bincode::deserialize(MITHRIL_PREV_BYTES).unwrap();

    let cert: Certificate = std::hint::black_box(cert.try_into().unwrap());
    let prev: Certificate = std::hint::black_box(prev.try_into().unwrap());

    std::hint::black_box((cert, prev));
}

// ============================================================================
// DWARF BENCHMARKS
// ============================================================================

#[library_benchmark]
fn bench_dwarf_full_verification() {
    let cert = certificate_from_bytes(&DWARF_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes(&DWARF_PREV_BYTES).unwrap();

    let result =
        verify_standard_certificate(std::hint::black_box(&cert), std::hint::black_box(&prev));

    std::hint::black_box(result);
}

#[library_benchmark]
fn bench_dwarf_parsing() {
    let cert = certificate_from_bytes(std::hint::black_box(&DWARF_CERT_BYTES));
    let prev = certificate_from_bytes(std::hint::black_box(&DWARF_PREV_BYTES));
    std::hint::black_box((cert, prev));
}

// ============================================================================
// PHASE BENCHMARKS (Dwarf only - shows verification breakdown)
// ============================================================================

#[library_benchmark]
fn bench_dwarf_basic_checks() {
    let cert = certificate_from_bytes(&DWARF_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes(&DWARF_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::basic_checks::*;

    let result = verify_not_infinite_loop(std::hint::black_box(&cert))
        .and_then(|_| verify_epoch_matches_protocol_message(std::hint::black_box(&cert)))
        .and_then(|_| {
            verify_epoch_chaining(std::hint::black_box(&cert), std::hint::black_box(&prev))
        })
        .and_then(|_| {
            verify_previous_hash_matches(std::hint::black_box(&cert), std::hint::black_box(&prev))
        });

    std::hint::black_box(result);
}

#[library_benchmark]
fn bench_dwarf_medium_checks() {
    let cert = certificate_from_bytes(&DWARF_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::medium_checks::*;

    let result = verify_hash_matches_content(std::hint::black_box(&cert))
        .and_then(|_| verify_signed_message_matches_protocol(std::hint::black_box(&cert)));

    std::hint::black_box(result);
}

#[library_benchmark]
fn bench_dwarf_complex_checks() {
    let cert = certificate_from_bytes(&DWARF_CERT_BYTES).unwrap();
    let prev = certificate_from_bytes(&DWARF_PREV_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;

    let result = verify_avk_chain(std::hint::black_box(&cert), std::hint::black_box(&prev))
        .and_then(|_| {
            verify_protocol_params_chain(std::hint::black_box(&cert), std::hint::black_box(&prev))
        });

    std::hint::black_box(result);
}

#[library_benchmark]
fn bench_dwarf_bls_only() {
    let cert = certificate_from_bytes(&DWARF_CERT_BYTES).unwrap();

    use mithril_dwarf::certificate_verification::complex_checks::*;
    let result = verify_bls_multisig(std::hint::black_box(&cert));
    std::hint::black_box(result);
}

// ============================================================================
// HELPER
// ============================================================================

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

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

library_benchmark_group!(
    name = mithril_benches;
    benchmarks =
        bench_mithril_full_verification,
        bench_mithril_parsing,
);

library_benchmark_group!(
    name = dwarf_benches;
    benchmarks =
        bench_dwarf_full_verification,
        bench_dwarf_parsing,
);

library_benchmark_group!(
    name = dwarf_phases;
    benchmarks =
        bench_dwarf_basic_checks,
        bench_dwarf_medium_checks,
        bench_dwarf_complex_checks,
        bench_dwarf_bls_only
);

main!(
    library_benchmark_groups = mithril_benches,
    dwarf_benches,
    dwarf_phases,
);
