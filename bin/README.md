```
cargo run -F tests --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash 0b1ad46fd90bad9a8b52595c444e722fe8b0a883e1943f144481afc947ab369c
```
```
cargo run -F tests --bin fetch_certificates -- \
    --network preprod \
    --certificate-hash <hash> \
    --output-dir tests/test_data/preprod_certificates
```

```
cargo run -F tests --bin fetch_certificates -- \
    --network mainnet \
    --certificate-hash <hash> \
    --max-certificates 50
```