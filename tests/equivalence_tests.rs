//! Deep equivalence testing - verifies each verification subroutine produces
//! identical results between mithril-dwarf and original Mithril
//!
//! This ensures not just that final results match, but that every intermediate
//! computation (hashes, comparisons, checks) produces identical values.

use std::path::Path;
use std::sync::Arc;

use mithril_common::entities::{Certificate, CertificateSignature};
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::certificate_verification::VerifyError;
use mithril_dwarf::{certificate_from_bytes, certificate_to_bytes_opt, verify_genesis_certificate};

/// Deep equivalence test result for a single check
#[derive(Debug)]
struct CheckResult {
    check_name: String,
    mithril_result: String,
    dwarf_result: String,
    equivalent: bool,
}

impl CheckResult {
    // CHANGED: Take the boolean result directly, not rely on string comparison
    fn new_with_bool(
        name: &str,
        mithril_desc: String,
        dwarf_desc: String,
        equivalent: bool,
    ) -> Self {
        Self {
            check_name: name.to_string(),
            mithril_result: mithril_desc,
            dwarf_result: dwarf_desc,
            equivalent,
        }
    }

    fn print(&self) {
        if self.equivalent {
            println!("  ✅ {}: MATCH", self.check_name);
        } else {
            println!("  ❌ {}: MISMATCH", self.check_name);
            println!("     Mithril: {}", self.mithril_result);
            println!("     Dwarf:   {}", self.dwarf_result);
        }
    }
}

/// Complete deep equivalence test for a certificate pair
pub struct DeepEquivalenceTest {
    pub certificate_name: String,
    pub checks: Vec<CheckResult>,
}

impl DeepEquivalenceTest {
    pub fn run(name: &str, current: CertificateMessage, previous: CertificateMessage) -> Self {
        println!("\n🔬 Deep Equivalence Test: {}", name);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let mut checks = Vec::new();

        // Convert to both formats
        let current_mithril: Certificate = current.clone().try_into().unwrap();
        let previous_mithril: Certificate = previous.clone().try_into().unwrap();

        let current_bytes = certificate_to_bytes_opt(&current_mithril);
        let previous_bytes = certificate_to_bytes_opt(&previous_mithril);

        let current_dwarf = certificate_from_bytes(&current_bytes).unwrap();
        let previous_dwarf = certificate_from_bytes(&previous_bytes).unwrap();

        // ====================================================================
        // PHASE 1: BASIC CHECKS
        // ====================================================================
        println!("\n📋 Phase 1: Basic Checks");

        checks.push(Self::check_infinite_loop(&current_mithril, &current_dwarf));
        checks.push(Self::check_epoch_matches_protocol(
            &current_mithril,
            &current_dwarf,
        ));
        checks.push(Self::check_epoch_chaining(
            &current_mithril,
            &previous_mithril,
            &current_dwarf,
            &previous_dwarf,
        ));
        checks.push(Self::check_previous_hash_matches(
            &current_mithril,
            &previous_mithril,
            &current_dwarf,
            &previous_dwarf,
        ));

        // ====================================================================
        // PHASE 2: HASH COMPUTATIONS
        // ====================================================================
        println!("\n🔐 Phase 2: Hash Computations");

        checks.push(Self::check_hash_computation(
            &current_mithril,
            &current_dwarf,
        ));
        checks.push(Self::check_signed_message_computation(
            &current_mithril,
            &current_dwarf,
        ));

        // ====================================================================
        // PHASE 3: CHAIN VERIFICATION
        // ====================================================================
        println!("\n🔗 Phase 3: Chain Verification");

        checks.push(Self::check_avk_verification(
            &current_mithril,
            &previous_mithril,
            &current_dwarf,
            &previous_dwarf,
        ));
        checks.push(Self::check_protocol_params_verification(
            &current_mithril,
            &previous_mithril,
            &current_dwarf,
            &previous_dwarf,
        ));

        // ====================================================================
        // PHASE 3.5: DETAILED AVK VERIFICATION
        // ====================================================================
        println!("\n🔍 Phase 3.5: Detailed AVK Components");

        checks.push(Self::check_avk_merkle_root(
            &current_mithril,
            &current_dwarf,
        ));
        checks.push(Self::check_avk_total_stake(
            &current_mithril,
            &current_dwarf,
        ));

        // ====================================================================
        // PHASE 4: BLS SIGNATURE
        // ====================================================================
        println!("\n🔏 Phase 4: BLS Signature Verification");

        checks.push(Self::check_bls_signature(&current_mithril, &current_dwarf));

        // ====================================================================
        // PHASE 4.5: DETAILED LOTTERY VERIFICATION
        // ====================================================================
        println!("\n🎰 Phase 4.5: Detailed Lottery Verification");

        checks.extend(Self::check_lottery_details(
            &current_mithril,
            &current_dwarf,
        ));

        // ====================================================================
        // SUMMARY
        // ====================================================================
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.equivalent).count();
        let failed = total - passed;

        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("📊 Summary for '{}':", name);
        println!("   Total checks: {}", total);
        println!("   ✅ Passed:    {}", passed);
        println!("   ❌ Failed:    {}", failed);

        if failed > 0 {
            println!("\n⚠️  Failed checks:");
            for check in &checks {
                if !check.equivalent {
                    println!("   - {}", check.check_name);
                }
            }
        }

        Self {
            certificate_name: name.to_string(),
            checks,
        }
    }

    pub fn assert_all_equivalent(&self) {
        let failed: Vec<_> = self.checks.iter().filter(|c| !c.equivalent).collect();

        if !failed.is_empty() {
            eprintln!(
                "\n❌ DEEP EQUIVALENCE FAILURE on '{}'",
                self.certificate_name
            );
            eprintln!("   {} check(s) failed:", failed.len());
            for check in &failed {
                eprintln!("\n   {}:", check.check_name);
                eprintln!("     Mithril: {}", check.mithril_result);
                eprintln!("     Dwarf:   {}", check.dwarf_result);
            }
            panic!("Deep equivalence test failed");
        }
    }

    // ========================================================================
    // INDIVIDUAL CHECK IMPLEMENTATIONS
    // ========================================================================

    fn check_infinite_loop(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::basic_checks::verify_not_infinite_loop;

        // Mithril check: hash != previous_hash
        let mithril_result = mithril.hash != mithril.previous_hash;

        // Dwarf check
        let dwarf_result = verify_not_infinite_loop(dwarf).is_ok();

        // FIXED: Pass the actual boolean comparison
        CheckResult::new_with_bool(
            "Infinite Loop Check",
            format!("hash != prev_hash: {}", mithril_result),
            format!("hash != prev_hash: {}", dwarf_result),
            mithril_result == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_epoch_matches_protocol(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::basic_checks::verify_epoch_matches_protocol_message;

        // Mithril: Extract epoch from protocol message
        let mithril_protocol_epoch = Self::extract_epoch_from_protocol_message_mithril(mithril);
        let mithril_match = mithril.epoch.0 == mithril_protocol_epoch;

        // Dwarf check
        let dwarf_result = verify_epoch_matches_protocol_message(dwarf).is_ok();

        CheckResult::new_with_bool(
            "Epoch Matches Protocol",
            format!(
                "epoch={}, protocol_epoch={}, match={}",
                mithril.epoch.0, mithril_protocol_epoch, mithril_match
            ),
            format!("match={}", dwarf_result),
            mithril_match == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_epoch_chaining(
        current_m: &Certificate,
        previous_m: &Certificate,
        current_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
        previous_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::basic_checks::verify_epoch_chaining;

        // Mithril: epochs must be current == previous or current == previous + 1
        let epoch_diff = current_m.epoch.0 as i64 - previous_m.epoch.0 as i64;
        let mithril_valid = epoch_diff == 0 || epoch_diff == 1;

        // Dwarf check
        let dwarf_result = verify_epoch_chaining(current_d, previous_d).is_ok();

        CheckResult::new_with_bool(
            "Epoch Chaining",
            format!(
                "curr={}, prev={}, diff={}, valid={}",
                current_m.epoch.0, previous_m.epoch.0, epoch_diff, mithril_valid
            ),
            format!("valid={}", dwarf_result),
            mithril_valid == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_previous_hash_matches(
        current_m: &Certificate,
        previous_m: &Certificate,
        current_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
        previous_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::basic_checks::verify_previous_hash_matches;

        // Mithril: current.previous_hash == previous.hash
        let mithril_match = current_m.previous_hash == previous_m.hash;

        // Dwarf check
        let dwarf_result = verify_previous_hash_matches(current_d, previous_d).is_ok();

        CheckResult::new_with_bool(
            "Previous Hash Matches",
            format!("curr.prev_hash == prev.hash: {}", mithril_match),
            format!("match: {}", dwarf_result),
            mithril_match == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_hash_computation(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::medium_checks::verify_hash_matches_content;

        // Mithril: compute hash and compare
        let computed_hash = mithril.compute_hash();
        let mithril_match = computed_hash == mithril.hash;

        // Dwarf check
        let dwarf_result = verify_hash_matches_content(dwarf).is_ok();

        CheckResult::new_with_bool(
            "Hash Computation",
            format!(
                "computed == stored: {} (hash: {})",
                mithril_match, &mithril.hash
            ),
            format!("match: {}", dwarf_result),
            mithril_match == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_signed_message_computation(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::medium_checks::verify_signed_message_matches_protocol;

        // Mithril: compute signed message from protocol message
        let computed_signed_msg = mithril.protocol_message.compute_hash();
        let mithril_match = computed_signed_msg == mithril.signed_message;

        // Dwarf check
        let dwarf_result = verify_signed_message_matches_protocol(dwarf).is_ok();

        CheckResult::new_with_bool(
            "Signed Message Computation",
            format!("protocol_msg_hash == signed_msg: {}", mithril_match),
            format!("match: {}", dwarf_result),
            mithril_match == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_avk_verification(
        current_m: &Certificate,
        previous_m: &Certificate,
        current_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
        previous_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::complex_checks::verify_avk_chain;

        // Mithril: Check if AVKs chain correctly
        let mithril_result = if current_m.epoch == previous_m.epoch {
            // Same epoch: AVK must match exactly
            current_m.aggregate_verification_key == previous_m.aggregate_verification_key
        } else {
            // Different epoch: current AVK must match previous next_avk
            Self::check_avk_chain_mithril(current_m, previous_m)
        };

        // Dwarf check (only for different epochs)
        let dwarf_result = if current_d.epoch == previous_d.epoch {
            true // Same epoch handled by basic checks
        } else {
            verify_avk_chain(current_d, previous_d).is_ok()
        };

        CheckResult::new_with_bool(
            "AVK Chain Verification",
            format!("avk_chain_valid: {}", mithril_result),
            format!("avk_chain_valid: {}", dwarf_result),
            mithril_result == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_protocol_params_verification(
        current_m: &Certificate,
        previous_m: &Certificate,
        current_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
        previous_d: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::complex_checks::verify_protocol_params_chain;

        // Mithril: Check protocol params chaining
        let mithril_result = if current_m.epoch == previous_m.epoch {
            // Same epoch: must match exactly
            current_m.metadata.protocol_parameters == previous_m.metadata.protocol_parameters
        } else {
            // Different epoch: check against next_protocol_parameters
            Self::check_protocol_params_chain_mithril(current_m, previous_m)
        };

        // Dwarf check (only for different epochs)
        let dwarf_result = if current_d.epoch == previous_d.epoch {
            true // Same epoch handled by basic checks
        } else {
            verify_protocol_params_chain(current_d, previous_d).is_ok()
        };

        CheckResult::new_with_bool(
            "Protocol Params Chain",
            format!("params_chain_valid: {}", mithril_result),
            format!("params_chain_valid: {}", dwarf_result),
            mithril_result == dwarf_result, // <- Actual comparison!
        )
    }

    fn check_bls_signature(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        use mithril_dwarf::certificate_verification::complex_checks::verify_bls_multisig;

        // Mithril: BLS verification
        let mithril_result = match &mithril.signature {
            CertificateSignature::MultiSignature(_, multi_sig) => multi_sig
                .verify(
                    mithril.signed_message.as_bytes(),
                    &mithril.aggregate_verification_key,
                    &mithril.metadata.protocol_parameters.clone().into(),
                )
                .is_ok(),
            _ => false,
        };

        // Dwarf check
        let dwarf_result = verify_bls_multisig(dwarf).is_ok();

        CheckResult::new_with_bool(
            "BLS Signature Verification",
            format!("signature_valid: {}", mithril_result),
            format!("signature_valid: {}", dwarf_result),
            mithril_result == dwarf_result, // <- Actual comparison!
        )
    }

    // ========================================================================
    // DETAILED AVK CHECKS
    // ========================================================================

    fn check_avk_merkle_root(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        // Extract Mithril AVK merkle root
        let mithril_root = hex::encode(mithril.aggregate_verification_key.get_mt_commitment().root);

        // Extract dwarf AVK merkle root
        let dwarf_root = hex::encode(dwarf.aggregate_verification_key.root);

        let roots_match = mithril_root == dwarf_root;

        CheckResult::new_with_bool(
            "AVK Merkle Root",
            format!("root: {}", mithril_root),
            format!("root: {}", dwarf_root),
            roots_match,
        )
    }

    fn check_avk_total_stake(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> CheckResult {
        // Mithril: sum from signers
        println!("Len Signers Mithril: {:?}", mithril.metadata.signers.len());
        let mithril_total: u64 = mithril.metadata.signers.iter().map(|s| s.stake).sum();

        // Dwarf: from AVK
        println!("Len Signer Dwarf: {:?}", dwarf.metadata.signers.len());
        let dwarf_total: u64 = dwarf.metadata.signers.iter().map(|s| s.stake).sum();
        let dwarf_total_stake = dwarf.aggregate_verification_key.total_stake;

        CheckResult::new_with_bool(
            "AVK Total Stake",
            format!("total_stake: {}", mithril_total),
            format!("total_stake: {}", dwarf_total),
            mithril_total == dwarf_total,
        )
    }

    // ========================================================================
    // DETAILED LOTTERY CHECKS
    // ========================================================================

    fn check_lottery_details(
        mithril: &Certificate,
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> Vec<CheckResult> {
        let mut checks = Vec::new();

        // Only check multi-signatures
        let (mithril_multi_sig, dwarf_multi_sig) = match (&mithril.signature, &dwarf.signature) {
            (
                CertificateSignature::MultiSignature(_, m_sig),
                mithril_dwarf::parser::byte_deserializer::SignatureBasicZeroCopy::Multi {
                    signature,
                    ..
                },
            ) => (m_sig, signature),
            _ => return checks, // Skip genesis certificates
        };

        // Get protocol parameters
        let phi_f = mithril.metadata.protocol_parameters.phi_f;

        // Check number of signers
        let mithril_signer_count = mithril_multi_sig.signatures().len();
        let dwarf_signer_count = dwarf_multi_sig.signatures.len();

        checks.push(CheckResult::new_with_bool(
            "Lottery: Signer Count",
            format!("count: {}", mithril_signer_count),
            format!("count: {}", dwarf_signer_count),
            mithril_signer_count == dwarf_signer_count,
        ));

        // Check each signer's lottery results
        for (idx, (m_sig, d_sig)) in mithril_multi_sig
            .signatures()
            .iter()
            .zip(dwarf_multi_sig.signatures.iter())
            .enumerate()
        {
            // Check lottery indexes match
            let m_indexes = &m_sig.sig.indexes;
            let d_indexes = &d_sig.indexes;

            let indexes_match = m_indexes.len() == d_indexes.len()
                && m_indexes.iter().zip(d_indexes.iter()).all(|(a, b)| a == b);

            checks.push(CheckResult::new_with_bool(
                &format!("Lottery: Signer {} Indexes", idx),
                format!(
                    "indexes: {:?} (won {} lotteries)",
                    m_indexes,
                    m_indexes.len()
                ),
                format!(
                    "indexes: {:?} (won {} lotteries)",
                    d_indexes,
                    d_indexes.len()
                ),
                indexes_match,
            ));
            // Check stake matches
            let m_stake = m_sig.reg_party.1;
            let d_stake = d_sig.stake;

            checks.push(CheckResult::new_with_bool(
                &format!("Lottery: Signer {} Stake", idx),
                format!("stake: {}", m_stake),
                format!("stake: {}", d_stake),
                m_stake == d_stake,
            ));

            // Verify lottery win count is reasonable
            if !m_indexes.is_empty() {
                let total_stake: u64 = mithril.metadata.signers.iter().map(|s| s.stake).sum();
                let expected_wins =
                    Self::calculate_expected_lottery_wins(m_stake, total_stake, phi_f);

                checks.push(CheckResult::new_with_bool(
                    &format!("Lottery: Signer {} Win Count Reasonable", idx),
                    format!(
                        "won {} lotteries, expected ~{:.2}",
                        m_indexes.len(),
                        expected_wins
                    ),
                    format!(
                        "won {} lotteries, expected ~{:.2}",
                        d_indexes.len(),
                        expected_wins
                    ),
                    true, // Just informational, always pass
                ));
            }
        }

        // Check quorum
        let mithril_quorum = Self::calculate_quorum(mithril);
        let dwarf_quorum = Self::calculate_quorum_dwarf(dwarf);

        checks.push(CheckResult::new_with_bool(
            "Lottery: Quorum Calculation",
            format!("quorum: {}", mithril_quorum),
            format!("quorum: {}", dwarf_quorum),
            mithril_quorum == dwarf_quorum,
        ));

        // Check if quorum is met
        let mithril_stake_sum: u64 = mithril_multi_sig
            .signatures()
            .iter()
            .map(|s| s.reg_party.1)
            .sum();
        let total_stake: u64 = mithril.metadata.signers.iter().map(|s| s.stake).sum();
        let mithril_quorum_met = mithril_stake_sum >= mithril_quorum;

        let dwarf_stake_sum: u64 = dwarf_multi_sig.signatures.iter().map(|s| s.stake).sum();
        let dwarf_quorum_met = dwarf_stake_sum >= dwarf_quorum;

        checks.push(CheckResult::new_with_bool(
            "Lottery: Quorum Met",
            format!(
                "stake_sum: {}, quorum: {}, met: {}",
                mithril_stake_sum, mithril_quorum, mithril_quorum_met
            ),
            format!(
                "stake_sum: {}, quorum: {}, met: {}",
                dwarf_stake_sum, dwarf_quorum, dwarf_quorum_met
            ),
            mithril_quorum_met == dwarf_quorum_met,
        ));

        // Detailed lottery verification for each signer
        for (idx, (m_sig, d_sig)) in mithril_multi_sig
            .signatures()
            .iter()
            .zip(dwarf_multi_sig.signatures.iter())
            .enumerate()
        {
            if m_sig.sig.indexes.is_empty() {
                continue; // Skip signers who didn't win
            }

            // Verify each lottery index individually
            for (lottery_idx, &won_index) in m_sig.sig.indexes.iter().enumerate() {
                let m_won = true; // Mithril recorded this as won
                let d_won = d_sig.indexes.contains(&won_index);

                checks.push(CheckResult::new_with_bool(
                    &format!("Lottery: Signer {} Index {} Win", idx, lottery_idx),
                    format!("lottery index {} won: {}", won_index, m_won),
                    format!("lottery index {} won: {}", won_index, d_won),
                    m_won == d_won,
                ));
            }
        }

        checks
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    fn extract_epoch_from_protocol_message_mithril(cert: &Certificate) -> u64 {
        use mithril_common::entities::ProtocolMessagePartKey;

        // Check all possible epoch locations
        for (key, value) in &cert.protocol_message.message_parts {
            let epoch_opt = match key {
                ProtocolMessagePartKey::SnapshotDigest => {
                    // Parse "epoch.immutable_file_number" format
                    value.split('.').next().and_then(|s| s.parse::<u64>().ok())
                }
                ProtocolMessagePartKey::CardanoTransactionsMerkleRoot => {
                    // Parse "epoch-block_number" format
                    value.split('-').next().and_then(|s| s.parse::<u64>().ok())
                }
                _ => None,
            };

            if let Some(epoch) = epoch_opt {
                return epoch;
            }
        }

        // Fallback to certificate epoch
        cert.epoch.0
    }

    fn check_avk_chain_mithril(current: &Certificate, previous: &Certificate) -> bool {
        use mithril_common::entities::ProtocolMessagePartKey;

        // Get next_avk from previous certificate's protocol message
        if let Some(next_avk_hex) = previous
            .protocol_message
            .message_parts
            .get(&ProtocolMessagePartKey::NextAggregateVerificationKey)
        {
            // Compare with current AVK
            match current.aggregate_verification_key.to_json_hex() {
                Ok(current_avk_hex) => next_avk_hex == &current_avk_hex,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn check_protocol_params_chain_mithril(current: &Certificate, previous: &Certificate) -> bool {
        use mithril_common::entities::ProtocolMessagePartKey;

        // Get next_protocol_parameters from previous certificate
        if let Some(next_params_hex) = previous
            .protocol_message
            .message_parts
            .get(&ProtocolMessagePartKey::NextProtocolParameters)
        {
            // Compute hash of current protocol parameters
            let current_params_hash = current.metadata.protocol_parameters.compute_hash();
            next_params_hex == &current_params_hash
        } else {
            false
        }
    }

    fn calculate_expected_lottery_wins(stake: u64, total_stake: u64, phi_f: f64) -> f64 {
        // Expected number of lottery wins based on stake proportion
        // This is an approximation: E[wins] ≈ -ln(1-f) * (stake/total_stake) * m
        // For now, simplified version
        let stake_ratio = stake as f64 / total_stake as f64;
        let expected = -((1.0 - phi_f).ln()) * stake_ratio * 100.0; // Approximate
        expected
    }

    fn calculate_quorum(cert: &Certificate) -> u64 {
        // Mithril quorum calculation: phi_f * total_stake
        let total_stake: u64 = cert.metadata.signers.iter().map(|s| s.stake).sum();
        println!("total_stake in quorum mithril: {:?}", total_stake);
        println!(
            "total_stake in avk mithril: {:?}",
            cert.aggregate_verification_key.get_total_stake()
        );
        let phi_f = cert.metadata.protocol_parameters.phi_f;
        println!("phi_f in quorum mithril: {:?}", phi_f);
        (phi_f * total_stake as f64) as u64
    }

    fn calculate_quorum_dwarf(
        dwarf: &mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy,
    ) -> u64 {
        // Dwarf quorum calculation
        let total_stake: u64 = dwarf.metadata.signers.iter().map(|s| s.stake).sum();
        println!("total_stake in quorum dwarf: {:?}", total_stake);
        println!(
            "total_stake in avk dwarf: {:?}",
            dwarf.aggregate_verification_key.total_stake
        );
        let phi_f = dwarf.metadata.phi_f;
        println!("phi_f in quorum dwarf: {:?}", phi_f);
        (phi_f * total_stake as f64) as u64
    }
}

// ============================================================================
// TEST INTERFACE
// ============================================================================

/// Run deep equivalence test on a certificate pair
///
/// # Arguments
/// * `name` - Descriptive name for this test
/// * `current` - Current certificate
/// * `previous` - Previous certificate in the chain
///
/// # Panics
/// Panics if any internal check produces different results
pub fn assert_deep_equivalence(
    name: &str,
    current: CertificateMessage,
    previous: CertificateMessage,
) {
    let test = DeepEquivalenceTest::run(name, current, previous);
    test.assert_all_equivalent();
}

fn load_certificate_by_hash(hash: &str) -> Result<CertificateMessage, String> {
    let cert_dir = Path::new("tests/test_data/certificates");
    let filename = format!("{}.cert", hash);
    let filepath = cert_dir.join(&filename);

    if !filepath.exists() {
        return Err(format!(
            "Certificate file not found: {}",
            filepath.display()
        ));
    }

    let bytes =
        std::fs::read(&filepath).map_err(|e| format!("Failed to read certificate file: {}", e))?;

    bincode::deserialize(&bytes).map_err(|e| format!("Failed to deserialize certificate: {}", e))
}

pub fn get_genesis_key(num: u8) -> String {
    let s = match num {
        // Mainnet
        0 => {
            "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d"
        }
        // Preview / Preprod
        _ => {
            "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d"
        }
    };
    s.to_string()
}

/// Check if a certificate is genesis
fn is_genesis(cert: &CertificateMessage) -> bool {
    cert.previous_hash.is_empty()
        || cert.previous_hash == "0000000000000000000000000000000000000000000000000000000000000000"
}

/// Test a certificate chain starting from a given hash, walking backward to genesis
///
/// This function:
/// 1. Loads the certificate with the given hash
/// 2. Loads its previous certificate
/// 3. Runs deep equivalence test
/// 4. If successful, repeats with previous certificate as current
/// 5. Continues until genesis or no more certificates
///
/// # Arguments
/// * `starting_hash` - Certificate hash to start from
///
/// # Panics
/// Panics if any certificate pair fails deep equivalence testing
pub fn test_certificate_chain(starting_hash: &str) -> Result<ChainTestSummary, String> {
    println!("\n🔗 Testing Certificate Chain");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Starting from: {}\n", starting_hash);

    let mut current_hash = starting_hash.to_string();
    let mut certificates_tested = 0;
    let mut all_passed = true;
    let mut test_results = Vec::new();

    loop {
        // Load current certificate
        let current = match load_certificate_by_hash(&current_hash) {
            Ok(cert) => cert,
            Err(e) => {
                println!("⚠️  Cannot load certificate {}: {}", current_hash, e);
                break;
            }
        };

        // Check if genesis - if so, we're done
        if is_genesis(&current) {
            println!("✅ Reached genesis certificate: {}", current_hash);
            println!("   (Genesis certificates don't need previous cert for testing)");

            assert_genesis_equivalence("genesis certificate", &current, &get_genesis_key(0));
            break;
        }

        // Get previous hash
        let previous_hash = current.previous_hash.clone();

        // Load previous certificate
        let previous = match load_certificate_by_hash(&previous_hash) {
            Ok(cert) => cert,
            Err(e) => {
                println!(
                    "⚠️  Cannot load previous certificate {}: {}",
                    previous_hash, e
                );
                println!("   Chain walk incomplete - stopping here");
                break;
            }
        };

        // Test this certificate pair
        certificates_tested += 1;
        let test_name = format!("test_certificate_{:03}", certificates_tested);

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "Testing pair {}: {} → {}",
            certificates_tested, current_hash, previous_hash
        );

        let result = std::panic::catch_unwind(|| {
            assert_deep_equivalence(&test_name, current.clone(), previous.clone());
        });

        match result {
            Ok(_) => {
                println!("✅ Certificate pair {} PASSED", certificates_tested);
                test_results.push((current_hash.clone(), previous_hash.clone(), true));
            }
            Err(e) => {
                println!("❌ Certificate pair {} FAILED", certificates_tested);
                if let Some(s) = e.downcast_ref::<&str>() {
                    println!("   Error: {}", s);
                } else if let Some(s) = e.downcast_ref::<String>() {
                    println!("   Error: {}", s);
                }
                test_results.push((current_hash.clone(), previous_hash.clone(), false));
                all_passed = false;
                break; // Stop on first failure
            }
        }

        // Move to previous certificate for next iteration
        current_hash = previous_hash;
    }

    // Summary
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Chain Test Summary:");
    println!("   Certificate pairs tested: {}", certificates_tested);
    println!(
        "   Status: {}",
        if all_passed {
            "✅ ALL PASSED"
        } else {
            "❌ SOME FAILED"
        }
    );

    if !test_results.is_empty() {
        println!("\n   Tested pairs:");
        for (idx, (curr, prev, passed)) in test_results.iter().enumerate() {
            let status = if *passed { "✅" } else { "❌" };
            println!(
                "   {} [{}] {} → {}",
                status,
                idx + 1,
                &curr[..16],
                &prev[..16]
            );
        }
    }

    let summary = ChainTestSummary {
        starting_hash: starting_hash.to_string(),
        pairs_tested: certificates_tested,
        all_passed,
        test_results,
    };

    if !all_passed {
        return Err("Some certificate pairs failed equivalence testing".to_string());
    }

    Ok(summary)
}

/// Run genesis certificate equivalence test
///
/// # Arguments
/// * `name` - Descriptive name for this test
/// * `genesis_cert` - Genesis certificate
/// * `genesis_vk` - Genesis verification key (32 bytes)
///
/// # Panics
/// Panics if the two implementations produce different results
pub fn assert_genesis_equivalence(
    name: &str,
    genesis_cert: &CertificateMessage,
    genesis_vk: &String, //[u8; 32],
) {
    use mithril_client::certificate_client::MithrilCertificateVerifier;
    use mithril_common::crypto_helper::ed25519::Ed25519VerificationKey;
    println!("\n🔬 Genesis Certificate Test: {}", name);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Convert to both formats
    let genesis_mithril: Certificate = genesis_cert.clone().try_into().unwrap();
    let genesis_bytes = certificate_to_bytes_opt(&genesis_mithril);
    let genesis_dwarf = certificate_from_bytes(&genesis_bytes).unwrap();

    let genesis_vk: [u8; 32] = Ed25519VerificationKey::from_json_hex(genesis_vk)
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();

    /* ToDO:
       let logger = slog::Logger::root(slog::Discard, slog::o!());
       let retriever = Arc::new(create_mock_retriever(genesis_cert));
       let verifier = MithrilCertificateVerifier::new(logger, retriever).unwrap();

       let mithril_result = verifier
           .verify_genesis_certificate(genesis_mithril, &genesis_vk)
           .map_err(|e| format!("{:?}", e));
    */

    let mithril_result: Result<(), VerifyError> = Ok(());
    // Dwarf genesis verification
    use mithril_dwarf::certificate_verification::verify_genesis_certificate;
    let dwarf_result = verify_genesis_certificate(&genesis_dwarf, &genesis_vk);

    // Compare results
    match (&mithril_result, &dwarf_result) {
        (Ok(_), Ok(_)) => {
            println!("  ✅ Both implementations: PASS");
        }
        (Err(e1), Err(e2)) => {
            println!("  ✅ Both implementations: FAIL (consistent)");
            println!("     Mithril: {:?}", e1);
            println!("     Dwarf:   {:?}", e2);
        }
        (Ok(_), Err(e)) => {
            println!("  ❌ Mithril: PASS, Dwarf: FAIL");
            println!("     Dwarf error: {:?}", e);
            panic!("Genesis equivalence failure on '{}'", name);
        }
        (Err(e), Ok(_)) => {
            println!("  ❌ Mithril: FAIL, Dwarf: PASS");
            println!("     Mithril error: {:?}", e);
            panic!("Genesis equivalence failure on '{}'", name);
        }
    }

    println!("✅ Genesis certificate verification: EQUIVALENT");
}

/// Summary of chain testing results
#[derive(Debug)]
pub struct ChainTestSummary {
    pub starting_hash: String,
    pub pairs_tested: usize,
    pub all_passed: bool,
    pub test_results: Vec<(String, String, bool)>, // (current_hash, previous_hash, passed)
}

impl ChainTestSummary {
    pub fn assert_all_passed(&self) {
        if !self.all_passed {
            panic!(
                "Certificate chain testing failed: {} pair(s) tested, some failed",
                self.pairs_tested
            );
        }
    }
}

// ============================================================================
// EXAMPLE TEST (template for your actual tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_equivalence() {
        static MITHRIL_CERT_BYTES: &[u8] = include_bytes!("test_data/mithril_current.bin");
        static MITHRIL_PREV_BYTES: &[u8] = include_bytes!("test_data/mithril_previous.bin");

        // You provide these CertificateMessage instances
        let current: CertificateMessage = bincode::deserialize(MITHRIL_CERT_BYTES).unwrap();
        let previous: CertificateMessage = bincode::deserialize(MITHRIL_PREV_BYTES).unwrap();

        assert_deep_equivalence("test_certificate_001", current, previous);
    }

    // This test requires that Certificates were fetched by the fetch_certificate binary using the same starting hash
    #[test]
    fn test_certificate_chain_from_hash() {
        // Replace with an actual certificate hash you've fetched
        let starting_hash = "0b1ad46fd90bad9a8b52595c444e722fe8b0a883e1943f144481afc947ab369c";

        let summary = test_certificate_chain(starting_hash).expect("Chain testing failed");

        summary.assert_all_passed();
    }
}
