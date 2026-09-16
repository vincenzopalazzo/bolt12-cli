## Clarified Problem Statement

**Goal:** When decoding BOLT12 offers (`lno1`), invoices (`lni1`), or payer proofs (`lnp1`), include a human-readable date representation alongside each existing unix timestamp field in the curated JSON output.

**Constraints:**
- Must not break existing consumers; unix timestamp fields must remain present.
- Decoding logic lives in `bolt12-common`; CLI in `bolt12-cli` prints JSON via serde.
- Human dates should be UTC to avoid ambiguity.
- Minimal dependency addition preferred.

**Non-goals:**
- Changing timestamp semantics or removing unix fields.
- Humanizing non-timestamp fields (amounts, ids).
- Adding network fetching or timezone conversion to local time.

**Success criteria:**
- `bolt12 decode <...> ` JSON contains for each unix timestamp field a new sibling field with ISO 8601 UTC date.
- Existing tests pass; output remains valid JSON with both fields.
- Field naming is consistent across Offer, Invoice, PayerProof.

## Approaches Considered

### Approach A: Model extension with chrono
- Sketch: Add optional human-readable fields to `model.rs` structs (e.g., `created_at_human: Option<String>`). Compute in `curated_offer/invoice/payer_proof` using `chrono::DateTime<Utc>`. Add `chrono` to `bolt12-common`.
- Affected files: `bolt12-common/src/model.rs`, `bolt12-common/src/decode.rs`, `bolt12-common/Cargo.toml`
- Tradeoffs: Clean for library consumers; adds dependency to common; requires model changes.
- Effort: M

### Approach B: CLI post-process JSON
- Sketch: Keep models unchanged. After `serde_json::to_value`, walk the value tree in `bolt12-cli/src/main.rs` and inject `*_human` fields for known timestamp keys by converting u64 seconds to ISO 8601.
- Affected files: `bolt12-cli/src/main.rs` only
- Tradeoffs: No change to `bolt12-common`; human dates invisible to library users; duplication of field knowledge in CLI.
- Effort: S

### Approach C: Serde custom serializer
- Sketch: Create a newtype `UnixTimestamp(u64)` with a custom serializer that emits both `value` and `value_human` via serde's `serialize_struct` pattern, or use `serde_aux`. Keep model fields typed as the newtype.
- Affected files: `bolt12-common/src/model.rs`, `bolt12-common/src/decode.rs`
- Tradeoffs: Elegant but invasive; changes public model shape; more complex to implement correctly.
- Effort: M

## Recommendation

Approach A is most consistent with existing curated DTOs and makes the human dates available to all consumers. Accept chrono dependency. If dependency aversion is high, fall back to Approach B.

## Open questions

- Which timestamp fields exactly need humanization? Current decode outputs: Offer `absolute_expiry`, Invoice `created_at`, `relative_expiry`, `absolute_expiry`, PayerProof `created_at`. Should `relative_expiry` (a duration) be humanized? Yes/No.
- Desired field naming: `created_at_human`, `created_at_iso`, or `created_at` keep and add `created_at_unix`? 
- Formatting: ISO 8601 UTC `YYYY-MM-DDTHH:MM:SSZ`? Include milliseconds?
- Scope: Library-wide serialization, or CLI-only?
