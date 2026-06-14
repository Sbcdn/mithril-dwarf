# Harness binaries

Developer tooling for the equivalence harness. The sub-crate already builds with
the `host`, `tx-inclusion`, `tx-parsing`, and `tx-components` features enabled, so
no extra flags are needed.

| Binary | Purpose |
|--------|---------|
| `fetch_certificates` | Walk a Mithril aggregator from a certificate hash back to genesis and store each certificate as a bincode fixture under `tests/test_data/certificates/`. |
| `audit` | Bitwise-equivalence report of mithril-dwarf against upstream Mithril over the corpus and mutation suite. |
| `fetch_tx_proof` | Fetch a real v1 (`CardanoTransactions`) inclusion proof and its certified Merkle root for the tx-inclusion vectors. |
| `fetch_tx_proof_v2` | Fetch a real v2 (`CardanoBlocksTransactions`) inclusion proof and root from the preview aggregator. |

Run any binary with:

```bash
cargo run -p mithril-dwarf-harness --bin <name> -- [args]
```

`fetch_certificates` takes `--network <mainnet|preprod|preview>` and
`--certificate-hash <hash>`, with optional `--output-dir <dir>` and
`--max-certificates <n>`:

```bash
cargo run -p mithril-dwarf-harness --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash 0b1ad46fd90bad9a8b52595c444e722fe8b0a883e1943f144481afc947ab369c
```
