use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::NoChecksum;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::offer::{Amount as LdkAmount, Offer as LdkOffer};
use lightning::offers::payer_proof::PayerProof as LdkPayerProof;

use crate::error::{Error, ErrorKind};
use crate::hex;
use crate::model::{Amount, Decoded, Invoice, Offer, PayerProof};

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
    Ok(Offer {
        offer_id: hex::encode(&offer.id().0),
        description: offer.description().map(|s| s.to_string()),
        issuer: offer.issuer().map(|s| s.to_string()),
        issuer_id: offer.issuer_signing_pubkey().map(|pk| pk.to_string()),
        amount: offer.amount().map(map_amount),
        absolute_expiry: offer.absolute_expiry().map(|d| d.as_secs()),
        chains: offer
            .chains()
            .iter()
            .map(|chain| hex::encode(chain.as_bytes()))
            .collect(),
    })
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

pub(crate) fn curated_invoice(invoice: &Bolt12Invoice) -> Invoice {
    Invoice {
        offer_id: invoice.offer_id().map(|id| hex::encode(&id.0)),
        description: invoice.description().map(|s| s.to_string()),
        issuer: invoice.issuer().map(|s| s.to_string()),
        amount_msat: invoice.amount_msats(),
        payment_hash: hex::encode(&invoice.payment_hash().0),
        node_id: invoice.signing_pubkey().to_string(),
        created_at: invoice.created_at().as_secs(),
        relative_expiry: invoice.relative_expiry().as_secs(),
    }
}

pub(crate) fn curated_payer_proof(proof: &LdkPayerProof) -> PayerProof {
    PayerProof {
        payer_id: proof.payer_signing_pubkey().to_string(),
        issuer_id: proof.issuer_signing_pubkey().to_string(),
        payment_hash: hex::encode(&proof.payment_hash().0),
        payment_preimage: hex::encode(&proof.payment_preimage().0),
        merkle_root: hex::encode(proof.merkle_root().as_ref()),
        amount_msat: proof.invoice_amount_msats(),
        description: proof.offer_description().map(|s| s.to_string()),
        issuer: proof.offer_issuer().map(|s| s.to_string()),
        created_at: proof.invoice_created_at().map(|d| d.as_secs()),
        proof_note: proof.proof_note().map(|s| s.to_string()),
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
}
