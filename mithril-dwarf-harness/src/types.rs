//! Normalized result types for per-check comparison.
//!
//! Each verification check (whether run via upstream Mithril or via dwarf)
//! produces a [`CheckResult`] containing:
//!
//! - `bytes` — a canonical byte sequence representing the check's full output
//!   (boolean outcome plus any computed intermediate value). This is the
//!   field that gets compared **bitwise** to prove equivalence. Two
//!   implementations are equivalent on a check iff their `bytes` match
//!   byte-for-byte.
//! - `outcome` — the high-level pass/fail/N-A semantic, used for the report
//!   summary and for normalised error-category comparison.
//!
//! The canonical byte encoding for each variant is documented on the
//! [`Outcome`] and [`ErrorCategory`] enums.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub bytes: Vec<u8>,
    pub outcome: Outcome,
}

impl CheckResult {
    pub fn pass(payload: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(TAG_PASS);
        bytes.extend_from_slice(&payload);
        Self {
            bytes,
            outcome: Outcome::Pass,
        }
    }

    pub fn fail(category: ErrorCategory, payload: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(2 + payload.len());
        bytes.push(TAG_FAIL);
        bytes.push(category.as_byte());
        bytes.extend_from_slice(&payload);
        Self {
            bytes,
            outcome: Outcome::Fail(category),
        }
    }

    pub fn not_applicable() -> Self {
        Self {
            bytes: vec![TAG_NA],
            outcome: Outcome::NotApplicable,
        }
    }
}

const TAG_PASS: u8 = 0x00;
const TAG_FAIL: u8 = 0x01;
const TAG_NA: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Pass,
    Fail(ErrorCategory),
    NotApplicable,
}

/// Canonical error categories.
///
/// Both upstream Mithril and dwarf produce native error enums; the harness
/// maps each native error to one of these categories so the comparison is
/// portable across debug-format changes and crate-internal renames. The
/// `as_byte` encoding is what goes into `CheckResult::bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCategory {
    InfiniteLoop,
    EpochInProtocolMessageMismatch,
    EpochChainGap,
    PreviousHashMismatch,
    HashMismatch,
    SignedMessageMismatch,
    AvkMismatch,
    AvkChainMismatch,
    ProtocolParamsMismatch,
    ProtocolParamsChainMismatch,
    BlsVerifyFailed,
    Ed25519VerifyFailed,
    StructuralError,
    /// The implementation panicked instead of returning a result.
    /// Treated as "rejected" for the rejection-equivalence contract but
    /// surfaced as a bitwise divergence so the underlying panic-on-adversarial-
    /// input is visible in the audit report.
    Panicked,
}

impl ErrorCategory {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::InfiniteLoop => 0x01,
            Self::EpochInProtocolMessageMismatch => 0x02,
            Self::EpochChainGap => 0x03,
            Self::PreviousHashMismatch => 0x04,
            Self::HashMismatch => 0x05,
            Self::SignedMessageMismatch => 0x06,
            Self::AvkMismatch => 0x07,
            Self::AvkChainMismatch => 0x08,
            Self::ProtocolParamsMismatch => 0x09,
            Self::ProtocolParamsChainMismatch => 0x0A,
            Self::BlsVerifyFailed => 0x0B,
            Self::Ed25519VerifyFailed => 0x0C,
            Self::StructuralError => 0xFE,
            Self::Panicked => 0xFF,
        }
    }
}

/// Per-cert audit: for each named check, the bytes produced by both impls
/// and whether they matched bitwise.
#[derive(Debug, Clone)]
pub struct CertAudit {
    pub cert_label: String,
    pub kind: CertKind,
    pub per_check: Vec<CheckComparison>,
    pub full_verify: CheckComparison,
    /// `true` if this audit corresponds to a mutation that is **known**
    /// to produce a `(mithril_rejects, dwarf_accepts)` divergence by
    /// design. The report + test contract treat such outcomes as an
    /// **expected, documented** divergence rather than a CRITICAL
    /// false positive. No mutation variants are currently classified
    /// here; the field is preserved so future divergences can be
    /// added cleanly.
    pub mutation_intentionally_diverges: bool,
}

impl CertAudit {
    pub fn all_match(&self) -> bool {
        self.per_check.iter().all(|c| c.matches_bitwise) && self.full_verify.matches_bitwise
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    Standard,
    Genesis,
}

/// A single check's side-by-side comparison.
#[derive(Debug, Clone)]
pub struct CheckComparison {
    pub id: &'static str,
    pub description: &'static str,
    pub mithril: CheckResult,
    pub dwarf: CheckResult,
    pub matches_bitwise: bool,
}

impl CheckComparison {
    pub fn new(
        id: &'static str,
        description: &'static str,
        mithril: CheckResult,
        dwarf: CheckResult,
    ) -> Self {
        let matches_bitwise = mithril.bytes == dwarf.bytes;
        Self {
            id,
            description,
            mithril,
            dwarf,
            matches_bitwise,
        }
    }
}
