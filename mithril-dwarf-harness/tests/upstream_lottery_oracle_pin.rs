//! Mechanical fidelity pin for the lottery differential oracle.
//!
//! The differential fuzz in `mithril-dwarf`'s `complex_checks::upstream_differential`
//! diffs dwarf's bounded-width lottery against a re-port of upstream `mithril-stm`'s
//! exact `taylor_comparison` / `is_lottery_won`. That re-port is hand-copied — if a
//! future rev bump changes upstream's algorithm and the re-port is not re-synced, the
//! fuzz would compare dwarf against a *stale* oracle and its "0 unsafe disagreements"
//! result would be meaningless. This test removes that risk: it reads the live pinned
//! upstream source and asserts dwarf's re-port has not drifted from it.
//!
//! Local-only (needs the pinned mithril-stm source in the cargo git checkout, present
//! whenever the `host`-feature deps have been fetched). On a rev bump that changes the
//! lottery, this fails loudly — re-sync `upstream_taylor` / `upstream_won` and the
//! snapshot here, then re-review.

use std::path::PathBuf;

const DWARF_SRC: &str = "../src/certificate_verification/complex_checks.rs";
const DWARF_CARGO: &str = "../Cargo.toml";

/// Strip `//` line comments and all whitespace so only the token stream remains.
fn normalize(s: &str) -> String {
    let mut out = String::new();
    for line in s.lines() {
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        out.extend(code.split_whitespace());
    }
    out
}

/// Return the brace-balanced body of the first `fn` whose declaration contains
/// `needle`, excluding the outer braces.
fn fn_body(src: &str, needle: &str) -> String {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` not found in source"));
    let open = start
        + src[start..]
            .find('{')
            .unwrap_or_else(|| panic!("no body brace after `{needle}`"));
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    for i in open..bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in body of `{needle}`");
}

/// Pinned mithril-stm rev, read from dwarf's Cargo.toml (the single source of truth).
fn pinned_rev() -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DWARF_CARGO);
    let toml = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
    for line in toml.lines() {
        if line.contains("mithril-stm") && line.contains("rev =") {
            let after = line.split("rev =").nth(1).expect("rev = value");
            let rev: String = after
                .trim()
                .trim_start_matches('"')
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert!(rev.len() >= 7, "mithril-stm rev too short: {rev:?}");
            return rev;
        }
    }
    panic!("mithril-stm rev not found in {}", manifest.display());
}

/// Locate the pinned upstream `concatenation/eligibility.rs` in the cargo git checkout.
fn upstream_eligibility_src(rev: &str) -> String {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap()).join(".cargo"));
    let checkouts = cargo_home.join("git/checkouts");
    let rel = "mithril-stm/src/proof_system/concatenation/eligibility.rs";
    // checkouts/mithril-<hash>/<rev-prefix>/<rel>
    let mut found = Vec::new();
    if let Ok(repos) = std::fs::read_dir(&checkouts) {
        for repo in repos.flatten() {
            if !repo.file_name().to_string_lossy().starts_with("mithril-") {
                continue;
            }
            if let Ok(revs) = std::fs::read_dir(repo.path()) {
                for r in revs.flatten() {
                    if rev.starts_with(&*r.file_name().to_string_lossy())
                        || r.file_name().to_string_lossy().starts_with(&rev[..7])
                    {
                        let p = r.path().join(rel);
                        if p.is_file() {
                            found.push(p);
                        }
                    }
                }
            }
        }
    }
    assert!(
        !found.is_empty(),
        "pinned upstream eligibility.rs (rev {}) not found under {}. \
         Fetch the host deps (cargo build --features host) so the source is present.",
        &rev[..7],
        checkouts.display()
    );
    std::fs::read_to_string(&found[0]).unwrap()
}

#[test]
fn dwarf_lottery_oracle_matches_pinned_upstream() {
    let rev = pinned_rev();
    let upstream = upstream_eligibility_src(&rev);
    let dwarf = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DWARF_SRC),
    )
    .expect("read dwarf complex_checks.rs");

    // 1. The Taylor series is the load-bearing approximation. dwarf's
    //    `upstream_taylor` body must be byte-identical (modulo comments and
    //    whitespace) to upstream's `taylor_comparison`.
    let up_taylor = normalize(&fn_body(&upstream, "fn taylor_comparison"));
    let dwarf_taylor = normalize(&fn_body(&dwarf, "fn upstream_taylor"));
    assert_eq!(
        dwarf_taylor, up_taylor,
        "\ndwarf's `upstream_taylor` oracle has DRIFTED from upstream \
         `taylor_comparison` (rev {}).\n  upstream: {up_taylor}\n  dwarf:    {dwarf_taylor}\n\
         Re-sync the re-port in complex_checks.rs and re-run the differential fuzz.",
        &rev[..7]
    );

    // Non-vacuity guard: a degenerate extraction (empty body) would make the
    // assert_eq above pass `"" == ""`. Require the proven body to be substantial
    // and contain the recurrence's defining tokens.
    for token in ["new_x=(new_x.clone()*x.clone())/divisor.clone()", "error_term", "phi"] {
        assert!(
            up_taylor.contains(&normalize(token)) && up_taylor.len() > 100,
            "taylor_comparison extraction looks degenerate (missing `{token}`) — the \
             fn_body parser or the source layout changed; the pin would be vacuous."
        );
    }

    // 2. `is_lottery_won`'s construction (q, c, w, x, the 1000-term call) is what
    //    dwarf's production `lottery_q` + per-signer `x` mirror. dwarf's `upstream_won`
    //    re-port intentionally takes `ev` as BigInt for boundary probing, so it is not
    //    body-identical; instead pin the construction invariants on BOTH sides — the
    //    live upstream `is_lottery_won` AND dwarf's `upstream_won` re-port — so a change
    //    upstream OR a drift in the re-port's q/c/w/x build both trip here.
    let up_won = normalize(&fn_body(&upstream, "fn is_lottery_won"));
    let dwarf_won = normalize(&fn_body(&dwarf, "fn upstream_won"));
    for needle in [
        "BigInt::from(2u8).pow(512)",          // ev_max = 2^512
        "Ratio::new_raw(ev_max.clone(),",      // q = ev_max / (ev_max - ev)
        "Ratio::from_float((1.0-phi_f).ln())", // c = ln(1 - phi_f)
        "(w*c).neg()",                         // x = -(w * c)
    ] {
        let n = normalize(needle);
        assert!(
            up_won.contains(&n),
            "upstream `is_lottery_won` no longer contains `{needle}` (rev {}). The lottery \
             construction changed — re-review dwarf's lottery_q / x build and the re-port.",
            &rev[..7]
        );
        assert!(
            dwarf_won.contains(&n),
            "dwarf's `upstream_won` re-port no longer contains `{needle}` — the fuzz oracle's \
             q/c/w/x construction has DRIFTED from upstream `is_lottery_won`. The differential \
             fuzz would be validating production against a stale construction. Re-sync it."
        );
    }
    // Each side invokes the same 1000-term Taylor (named per side).
    assert!(
        up_won.contains(&normalize("taylor_comparison(1000,")),
        "upstream `is_lottery_won` no longer calls `taylor_comparison(1000, ...)` (rev {}).",
        &rev[..7]
    );
    assert!(
        dwarf_won.contains(&normalize("upstream_taylor(1000,")),
        "dwarf's `upstream_won` re-port no longer calls `upstream_taylor(1000, ...)`."
    );

    eprintln!(
        "oracle pin OK: dwarf lottery re-port (taylor + construction) matches upstream \
         eligibility.rs @ {}",
        &rev[..7]
    );
}
