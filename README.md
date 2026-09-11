# bolt12-cli

Minimal Rust/LDK Swiss knife for BOLT 12. Decode offers, invoices, and payer
proofs to curated JSON. Verify official `lnp1` payer proofs and the
offer + invoice + preimage triple.

Logic lives in `bolt12-common`. `bolt12-cli` is clap + JSON on stdout.

## Build

```sh
cargo build --release
```

The binary is `bolt12`.

## Decode

HRP is auto-detected (`lno` / `lni` / `lnp`).

```sh
bolt12 decode lno1...
bolt12 decode lni1...
bolt12 decode lnp1...
```

`decode lnp1` parses through LDK, which also verifies the proof. Invalid proofs
cannot be decoded.

## Verify

Official payer proof:

```sh
bolt12 verify lnp1...
```

Ocean-style payment triple:

```sh
bolt12 verify --offer lno1... --invoice lni1... --preimage <64 hex chars>
```

Success is `{ "valid": true, "checks": [...] }` and exit 0. A failed check is
the same shape with `"valid": false` and exit 1. Argument/decode errors are
`{ "error": "...", "message": "..." }` and exit 1.

## Tests

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```
