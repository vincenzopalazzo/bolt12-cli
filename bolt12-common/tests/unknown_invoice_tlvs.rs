//! Decode snapshots for invoices with and without unknown invoice-range TLVs.

use bolt12_common::{decode, Decoded, UnknownTlv};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DecodePair {
    name: String,
    valid: bool,
    offer: String,
    invoice: String,
    #[serde(default)]
    unknown_offer_tlvs: Vec<ExpectedTlv>,
    #[serde(default)]
    unknown_invoice_request_tlvs: Vec<ExpectedTlv>,
    unknown_invoice_tlvs: Vec<ExpectedTlv>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTlv {
    #[serde(rename = "type")]
    type_id: u64,
    length: u64,
    value: String,
}

fn fixtures() -> Vec<DecodePair> {
    serde_json::from_str(include_str!("fixtures/unknown_invoice_tlvs.json"))
        .expect("unknown_invoice_tlvs.json")
}

fn expected_unknown(pair: &DecodePair) -> Vec<UnknownTlv> {
    pair.unknown_invoice_tlvs
        .iter()
        .map(|tlv| UnknownTlv {
            type_id: tlv.type_id,
            length: tlv.length,
            value: tlv.value.clone(),
        })
        .collect()
}

#[test]
fn decodes_unknown_invoice_tlv_pairs() {
    for pair in fixtures() {
        let offer = match decode(&pair.offer)
            .unwrap_or_else(|err| panic!("{}: offer decode failed: {err}", pair.name))
        {
            Decoded::Offer(offer) => offer,
            other => panic!("{}: expected offer, got {other:?}", pair.name),
        };
        let invoice = match decode(&pair.invoice)
            .unwrap_or_else(|err| panic!("{}: invoice decode failed: {err}", pair.name))
        {
            Decoded::Invoice(invoice) => invoice,
            other => panic!("{}: expected invoice, got {other:?}", pair.name),
        };

        assert_eq!(
            invoice.unknown_invoice_tlvs,
            expected_unknown(&pair),
            "{}",
            pair.name
        );
        assert!(
            pair.unknown_offer_tlvs.is_empty()
                && pair.unknown_invoice_request_tlvs.is_empty(),
            "{}: fixture carries embedded-section unknowns; extend this test",
            pair.name
        );
        assert!(
            invoice.unknown_offer_tlvs.is_empty()
                && invoice.unknown_invoice_request_tlvs.is_empty(),
            "{}: unexpected embedded-section unknowns: offer={:?} invoice_request={:?}",
            pair.name,
            invoice.unknown_offer_tlvs,
            invoice.unknown_invoice_request_tlvs
        );
        assert_eq!(
            invoice.offer_id.as_deref(),
            Some(offer.offer_id.as_str()),
            "{}: offer_id mismatch",
            pair.name
        );
        assert_eq!(
            pair.valid,
            invoice.unknown_invoice_tlvs.is_empty(),
            "{}: valid={} but unknown_invoice_tlvs={:?}",
            pair.name,
            pair.valid,
            invoice.unknown_invoice_tlvs
        );
    }
}

#[test]
fn invoice_without_unknown_tlvs_omits_the_list() {
    let pair = fixtures()
        .into_iter()
        .find(|pair| pair.name == "no_unknown_invoice_tlvs")
        .expect("clean pair");
    match decode(&pair.invoice).unwrap() {
        Decoded::Invoice(invoice) => {
            assert!(invoice.unknown_invoice_tlvs.is_empty(), "{invoice:?}");
            assert!(
                invoice.unknown_offer_tlvs.is_empty()
                    && invoice.unknown_invoice_request_tlvs.is_empty(),
                "{invoice:?}"
            );
            assert!(pair.valid);
        }
        other => panic!("expected invoice, got {other:?}"),
    }
}

#[test]
fn invoice_with_empty_tlv_161_is_reported() {
    let pair = fixtures()
        .into_iter()
        .find(|pair| pair.name == "unknown_invoice_tlv_161_empty")
        .expect("unknown TLV pair");
    match decode(&pair.invoice).unwrap() {
        Decoded::Invoice(invoice) => {
            assert_eq!(
                invoice.unknown_invoice_tlvs,
                vec![UnknownTlv {
                    type_id: 161,
                    length: 0,
                    value: String::new(),
                }]
            );
        }
        other => panic!("expected invoice, got {other:?}"),
    }
}
