## Clarified Problem Statement

**Goal:** Ship a minimal Rust/LDK Swiss-knife CLI that decodes BOLT12 offers (`lno1`), invoices (`lni1`), and payer proofs (`lnp1`) to curated JSON, and verifies both official `lnp1` payer proofs and the Ocean-style offer+invoice+preimage triple.

**Constraints:**
- Rust + LDK (`lightning` crate). Pin git/main (or a post-#4297 release) so `PayerProof` exists; crates.io may be too old.
- Logic lives in `bolt12-common`; `bolt12-cli` is clap + JSON print only.
- CLI stdout is JSON only. Errors are JSON objects + non-zero exit.
- Super minimal: no network, no node, no paying, no encode/create in v1.
- Greenfield repo (`vincenzopalazzo/bolt12-cli`), empty `main`.
- `decode` auto-detects HRP (`lno` / `lni` / `lnp`). `verify` covers both proof kinds.

**Non-goals:**
- Creating / encoding payer proofs, invoices, or invoice requests.
- Drop-in replacement for C `ocean-ln/ocean-offer-cli` (exit-code / argp contract).
- CLN-style full TLV dump or raw LDK serde.
- BIP353, onion messages, refunds, `lnr` invoice requests (later).
- Wiring into `ocean-ln` SubmitProofs / TIDES in v1.

**Success criteria:**
- `bolt12 decode lno1...` / `lni1...` / `lnp1...` prints curated JSON with a `type` discriminant.
- `bolt12 verify lnp1...` checks merkle reconstruction, invoice-node sig, payer sig, `SHA256(preimage)==payment_hash`.
- `bolt12 verify --offer lno1 --invoice lni1 --preimage <hex>` checks the five Ocean steps: decode, signing pubkey == `invoice_node_id`, `offer_id` match, invoice BIP-340 sig, preimage/hash.
- Invalid input → JSON error, exit ≠ 0. Valid verify → JSON `{ "valid": true, "checks": [...] }`.
- `bolt12-common` has no clap / CLI deps; unit tests cover bolts `payer-proof-test.json` vectors plus the known-good / Phoenix-fail fixtures from `ocean-offer-cli/tests`.

## Approaches Considered

### Approach A: Thin two-crate prefix router
- Sketch: Cargo workspace with `bolt12-common` (`decode`, `verify_payer_proof`, `verify_payment`) and `bolt12-cli` (clap → call → `serde_json::to_string_pretty`). HRP router in `decode.rs`. Two explicit verify fns, curated DTOs in `model.rs`.
- Affected files: `Cargo.toml`, `bolt12-common/{Cargo.toml,src/lib.rs,src/decode.rs,src/verify.rs,src/model.rs}`, `bolt12-cli/{Cargo.toml,src/main.rs}`
- Tradeoffs: Smallest surface, matches “super minimal”. Two verify entry points stay obvious. Does not help a second consumer beyond calling the two fns.
- Effort: S

### Approach B: Unified `VerifyInput` enum
- Sketch: Same crate split, but common exposes `enum Bolt12Message { Offer, Invoice, PayerProof }` and `enum VerifyInput { PayerProof(String), Payment { offer, invoice, preimage } }` with one `verify() -> VerifyReport`. CLI becomes a JSON printer over that enum.
- Affected files: same as A, plus thicker `verify.rs` / `model.rs`
- Tradeoffs: Nicely typed for a future library consumer. Extra abstraction for two input shapes that do not share much. Easy to overbuild.
- Effort: S / M

### Approach C: Command-handler library
- Sketch: `bolt12-common` exposes `enum Command { Decode(String), Verify(...) }` and `fn run(cmd) -> JsonValue`. CLI and a future `ocean-ln` httpd share the same handlers and JSON schema.
- Affected files: `bolt12-common/src/command.rs` in addition to A; CLI `main.rs` even thinner
- Tradeoffs: Best if Ocean adoption is imminent. Couples the library to CLI JSON/exit semantics. Against “general Swiss knife, Ocean later” and against minimal.
- Effort: M

## Recommendation

Approach A. The user asked for a super-minimal LDK CLI with a reusable common crate, not a command bus. Two verify functions match the two proof kinds (1C) without forcing a fake shared type. Pin LDK from git until payer proofs are on crates.io. Revisit B only if a second Rust consumer appears.

## Open questions

- Exact curated field list (start from LDK getters + Ocean verify needs: `offer_id`, `node_id` / `issuer_id`, `amount_msat`, `description`, `payment_hash`, `payment_preimage`, `created_at`; add fields only when a decode looks empty).
- Binary name: `bolt12` vs `bolt12-cli`.
- Whether `decode lnp1` should also run verification or only parse (recommend parse-only; `verify` is the check).
