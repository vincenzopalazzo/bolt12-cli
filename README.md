# bolt12-cli

Minimal Rust/LDK Swiss army knife for BOLT 12. Decode offers, invoices, and payer
proofs to curated JSON. Verify official `lnp1` payer proofs and the
offer + invoice + preimage triple.

Logic lives in `bolt12-common`. `bolt12-cli` is clap + JSON on stdout.

## Install

```sh
cargo install bolt12-cli
```

The binary is `bolt12`.

## Build

```sh
cargo build --release
```

## Decode

HRP is auto-detected (`lno` / `lni` / `lnp`).

```sh
bolt12 decode lno1...
bolt12 decode lni1...
bolt12 decode lnp1...
```

`decode lnp1` parses through LDK, which also verifies the proof. Invalid proofs
cannot be decoded.

Invoice JSON includes `unknown_invoice_tlvs` when any TLV type in 160–239 is
not a BOLT 12 invoice field. The key is omitted when the list is empty.

## Verify

Official payer proof: LDK cryptographic checks plus `pays_offers_recipient`
(invoice issuer can sign for this offer's recipient, not "this paid this
exact offer"):

```sh
bolt12 verify lnp1... --offer lno1...
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
