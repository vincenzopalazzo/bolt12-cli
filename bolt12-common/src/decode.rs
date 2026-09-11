use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::NoChecksum;
use lightning::blinded_path::message::BlindedMessagePath;
use lightning::blinded_path::payment::BlindedPaymentPath;
use lightning::blinded_path::{Direction, IntroductionNode as LdkIntroductionNode};
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::offer::{Amount as LdkAmount, Offer as LdkOffer, Quantity};
use lightning::offers::payer_proof::PayerProof as LdkPayerProof;

use crate::error::{Error, ErrorKind};
use crate::hex;
use crate::model::{
    Amount, BlindedHop, BlindedPath, BlindedPayInfo, Decoded, IntroductionNode, Invoice, Offer,
    PayerProof,
};

/// Decode a BOLT 12 bech32 string by HRP (`lno` / `lni` / `lnp`).
///
/// `lnp` parsing also runs LDK's payer-proof verification (merkle reconstruction,
/// invoice signature, payer signature, preimage/hash). Invalid proofs cannot be
/// decoded.
pub fn decode(encoded: &str) -> Result<Decoded, Error> {
    let encoded = encoded.trim();
    match hrp(encoded).map(str::to_ascii_lowercase).as_deref() {
        Some("lno") => decode_offer(encoded).map(Decoded::Offer),
        Some("lni") => decode_invoice(encoded).map(Decoded::Invoice),
        Some("lnp") => decode_payer_proof(encoded).map(Decoded::PayerProof),
        Some(other) => Err(Error::new(
            ErrorKind::UnknownHrp,
            format!("unsupported BOLT12 HRP `{other}`"),
        )),
        None => Err(Error::new(
            ErrorKind::UnknownHrp,
            "missing bech32 separator; expected lno1 / lni1 / lnp1",
        )),
    }
}

pub(crate) fn decode_offer(encoded: &str) -> Result<Offer, Error> {
    let offer = LdkOffer::from_str(encoded).map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("offer decode failed: {err:?}"),
        )
    })?;
    Ok(curated_offer(&offer))
}

pub(crate) fn decode_invoice(encoded: &str) -> Result<Invoice, Error> {
    let invoice = parse_invoice(encoded)?;
    Ok(curated_invoice(&invoice))
}

pub(crate) fn parse_invoice(encoded: &str) -> Result<Bolt12Invoice, Error> {
    // Offer and payer proof already have `FromStr`. Invoice is still TLV-only
    // on the public API, so decode `lni` the same way LDK's `from_bech32_str`
    // does: flatten `+` continuations, then `TryFrom<Vec<u8>>`.
    let bytes = bech32_no_checksum(encoded)?;
    Bolt12Invoice::try_from(bytes).map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("invoice decode failed: {err:?}"),
        )
    })
}

fn bech32_no_checksum(encoded: &str) -> Result<Vec<u8>, Error> {
    let compact: String = encoded
        .chars()
        .filter(|c| *c != '+' && !c.is_whitespace())
        .collect();
    let parsed = CheckedHrpstring::new::<NoChecksum>(&compact).map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("bech32 decode failed: {err:?}"),
        )
    })?;
    parsed.validate_segwit_padding().map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("invalid bech32 padding: {err:?}"),
        )
    })?;
    Ok(parsed.byte_iter().collect())
}

pub(crate) fn decode_payer_proof(encoded: &str) -> Result<PayerProof, Error> {
    let proof = parse_payer_proof(encoded)?;
    Ok(curated_payer_proof(&proof))
}

pub(crate) fn parse_payer_proof(encoded: &str) -> Result<LdkPayerProof, Error> {
    LdkPayerProof::from_str(encoded).map_err(|err| {
        Error::new(
            ErrorKind::DecodeFailed,
            format!("payer proof decode failed: {err:?}"),
        )
    })
}

pub(crate) fn curated_offer(offer: &LdkOffer) -> Offer {
    Offer {
        offer_id: hex::encode(&offer.id().0),
        chains: offer
            .chains()
            .iter()
            .map(|chain| hex::encode(chain.as_bytes()))
            .collect(),
        metadata: offer
            .metadata()
            .filter(|m| !m.is_empty())
            .map(|m| hex::encode(m)),
        amount: offer.amount().map(map_amount),
        description: offer.description().map(|s| s.to_string()),
        features: features_hex(offer.offer_features().le_flags()),
        absolute_expiry: offer.absolute_expiry().map(|d| d.as_secs()),
        paths: offer.paths().iter().map(map_message_path).collect(),
        issuer: offer.issuer().map(|s| s.to_string()),
        quantity_max: quantity_max(offer.supported_quantity()),
        issuer_id: offer.issuer_signing_pubkey().map(|pk| pk.to_string()),
    }
}

pub(crate) fn curated_invoice(invoice: &Bolt12Invoice) -> Invoice {
    Invoice {
        offer_id: invoice.offer_id().map(|id| hex::encode(&id.0)),
        offer_chains: invoice.offer_chains().map(|chains| {
            chains
                .iter()
                .map(|chain| hex::encode(chain.as_bytes()))
                .collect()
        }),
        metadata: invoice
            .metadata()
            .filter(|m| !m.is_empty())
            .map(|m| hex::encode(m)),
        offer_amount: invoice.amount().map(map_amount),
        description: invoice.description().map(|s| s.to_string()),
        offer_features: invoice
            .offer_features()
            .and_then(|features| features_hex(features.le_flags())),
        absolute_expiry: invoice.absolute_expiry().map(|d| d.as_secs()),
        offer_paths: invoice
            .message_paths()
            .iter()
            .map(map_message_path)
            .collect(),
        issuer: invoice.issuer().map(|s| s.to_string()),
        quantity_max: invoice.supported_quantity().and_then(quantity_max),
        issuer_id: invoice.issuer_signing_pubkey().map(|pk| pk.to_string()),
        chain: hex::encode(invoice.chain().as_bytes()),
        payer_metadata: {
            let meta = invoice.payer_metadata();
            if meta.is_empty() {
                None
            } else {
                Some(hex::encode(meta))
            }
        },
        invoice_request_features: features_hex(invoice.invoice_request_features().le_flags()),
        quantity: invoice.quantity(),
        payer_id: invoice.payer_signing_pubkey().to_string(),
        payer_note: invoice.payer_note().map(|s| s.to_string()),
        payment_paths: invoice
            .payment_paths()
            .iter()
            .map(map_payment_path)
            .collect(),
        created_at: invoice.created_at().as_secs(),
        relative_expiry: invoice.relative_expiry().as_secs(),
        payment_hash: hex::encode(&invoice.payment_hash().0),
        amount_msat: invoice.amount_msats(),
        fallbacks: invoice
            .fallbacks()
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
        invoice_features: features_hex(invoice.invoice_features().le_flags()),
        node_id: invoice.signing_pubkey().to_string(),
        signature: hex::encode(invoice.signature().as_ref()),
    }
}

pub(crate) fn curated_payer_proof(proof: &LdkPayerProof) -> PayerProof {
    PayerProof {
        payer_id: proof.payer_signing_pubkey().to_string(),
        issuer_id: proof.issuer_signing_pubkey().to_string(),
        payment_hash: hex::encode(&proof.payment_hash().0),
        payment_preimage: hex::encode(&proof.payment_preimage().0),
        merkle_root: hex::encode(proof.merkle_root().as_ref()),
        invoice_signature: hex::encode(proof.invoice_signature().as_ref()),
        proof_signature: hex::encode(proof.proof_signature().as_ref()),
        amount_msat: proof.invoice_amount_msats(),
        description: proof.offer_description().map(|s| s.to_string()),
        issuer: proof.offer_issuer().map(|s| s.to_string()),
        created_at: proof.invoice_created_at().map(|d| d.as_secs()),
        proof_note: proof.proof_note().map(|s| s.to_string()),
    }
}

fn map_message_path(path: &BlindedMessagePath) -> BlindedPath {
    BlindedPath {
        introduction_node: map_introduction(path.introduction_node()),
        blinding_point: path.blinding_point().to_string(),
        hops: path.blinded_hops().iter().map(map_hop).collect(),
        payinfo: None,
    }
}

fn map_payment_path(path: &BlindedPaymentPath) -> BlindedPath {
    BlindedPath {
        introduction_node: map_introduction(path.introduction_node()),
        blinding_point: path.blinding_point().to_string(),
        hops: path.blinded_hops().iter().map(map_hop).collect(),
        payinfo: Some(map_payinfo(&path.payinfo)),
    }
}

fn map_introduction(node: &LdkIntroductionNode) -> IntroductionNode {
    match node {
        LdkIntroductionNode::NodeId(pk) => IntroductionNode::Node {
            node_id: pk.to_string(),
        },
        LdkIntroductionNode::DirectedShortChannelId(direction, scid) => {
            IntroductionNode::ShortChannelId {
                short_channel_id: hex::encode(&scid.to_be_bytes()),
                direction: match direction {
                    Direction::NodeOne => "node_one".to_owned(),
                    Direction::NodeTwo => "node_two".to_owned(),
                },
            }
        }
    }
}

fn map_hop(hop: &lightning::blinded_path::BlindedHop) -> BlindedHop {
    BlindedHop {
        blinded_node_id: hop.blinded_node_id.to_string(),
    }
}

fn map_payinfo(info: &lightning::blinded_path::payment::BlindedPayInfo) -> BlindedPayInfo {
    BlindedPayInfo {
        fee_base_msat: info.fee_base_msat,
        fee_proportional_millionths: info.fee_proportional_millionths,
        cltv_expiry_delta: info.cltv_expiry_delta,
        htlc_minimum_msat: info.htlc_minimum_msat,
        htlc_maximum_msat: info.htlc_maximum_msat,
        features: features_hex(info.features.le_flags()),
    }
}

/// Wire-order (big-endian) feature hex. Omits an all-zero / empty bitmap.
fn features_hex(le_flags: &[u8]) -> Option<String> {
    if le_flags.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut be = le_flags.to_vec();
    be.reverse();
    Some(hex::encode(&be))
}

/// `offer_quantity_max` encoding: omitted for one item, `0` unbounded, else the max.
fn quantity_max(quantity: Quantity) -> Option<u64> {
    match quantity {
        Quantity::One => None,
        Quantity::Unbounded => Some(0),
        Quantity::Bounded(max) => Some(max.get()),
    }
}

fn map_amount(amount: LdkAmount) -> Amount {
    match amount {
        LdkAmount::Bitcoin { amount_msats } => Amount::Bitcoin { msat: amount_msats },
        LdkAmount::Currency {
            iso4217_code,
            amount,
        } => Amount::Currency {
            currency: iso4217_code.as_str().to_owned(),
            amount,
        },
    }
}

fn hrp(encoded: &str) -> Option<&str> {
    let sep = encoded.find('1')?;
    if sep == 0 {
        return None;
    }
    Some(&encoded[..sep])
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_OFFER: &str = "lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq";

    #[test]
    fn decodes_offer_by_hrp() {
        let decoded = decode(GOOD_OFFER).unwrap();
        match decoded {
            Decoded::Offer(offer) => {
                assert_eq!(offer.offer_id.len(), 64);
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_hrp() {
        let err = decode("lnbcrt1qq").unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnknownHrp);
    }

    #[test]
    fn decodes_uppercase_offer_hrp() {
        let decoded = decode(&GOOD_OFFER.to_ascii_uppercase()).unwrap();
        assert!(matches!(decoded, Decoded::Offer(_)));
    }

    #[test]
    fn offer_includes_spec_issuer_id() {
        let decoded = decode(GOOD_OFFER).unwrap();
        match decoded {
            Decoded::Offer(offer) => {
                assert_eq!(offer.issuer_id.as_deref().map(str::len), Some(66));
                assert!(offer.paths.is_empty());
                assert!(offer.features.is_none());
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }
}
