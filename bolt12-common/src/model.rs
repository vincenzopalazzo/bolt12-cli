use serde::Serialize;

/// Curated decode of a BOLT 12 string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Decoded {
    Offer(Offer),
    Invoice(Invoice),
    PayerProof(PayerProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offer {
    pub offer_id: String,
    pub chains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_expiry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_expiry_iso: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<BlindedPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity_max: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invoice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_chains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_amount: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_expiry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_expiry_iso: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub offer_paths: Vec<BlindedPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity_max: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,
    pub chain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_request_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<u64>,
    pub payer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub payment_paths: Vec<BlindedPath>,
    pub created_at: u64,
    pub created_at_iso: String,
    pub relative_expiry: u64,
    pub payment_hash: String,
    pub amount_msat: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_features: Option<String>,
    pub node_id: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_offer_tlvs: Vec<UnknownTlv>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_invoice_request_tlvs: Vec<UnknownTlv>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_invoice_tlvs: Vec<UnknownTlv>,
}

/// Unknown TLV in a BOLT 12 stream, bucketed by the section it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownTlv {
    #[serde(rename = "type")]
    pub type_id: u64,
    pub length: u64,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayerProof {
    pub payer_id: String,
    pub issuer_id: String,
    pub payment_hash: String,
    pub payment_preimage: String,
    pub merkle_root: String,
    pub invoice_signature: String,
    pub proof_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_iso: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_note: Option<String>,
}

/// Blinded message or payment path without onion ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlindedPath {
    pub introduction_node: IntroductionNode,
    pub blinding_point: String,
    pub hops: Vec<BlindedHop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payinfo: Option<BlindedPayInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntroductionNode {
    Node {
        node_id: String,
    },
    ShortChannelId {
        short_channel_id: String,
        direction: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlindedHop {
    pub blinded_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlindedPayInfo {
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
    pub htlc_minimum_msat: u64,
    pub htlc_maximum_msat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Amount {
    Bitcoin { msat: u64 },
    Currency { currency: String, amount: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyKind {
    PayerProof,
    Payment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub valid: bool,
    pub kind: VerifyKind,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Check {
    pub fn pass(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: None,
        }
    }

    pub fn fail(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: Some(message.into()),
        }
    }
}

impl VerifyReport {
    pub fn new(kind: VerifyKind, checks: Vec<Check>) -> Self {
        let valid = !checks.is_empty() && checks.iter().all(|check| check.passed);
        Self {
            valid,
            kind,
            checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_is_not_valid() {
        let report = VerifyReport::new(VerifyKind::PayerProof, Vec::new());
        assert!(!report.valid);
    }
}
