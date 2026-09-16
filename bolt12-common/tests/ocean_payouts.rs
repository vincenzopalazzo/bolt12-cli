//! Live Ocean lightning payouts scraped from public
//! `https://ocean.xyz/info/tx/lightning/{payment_hash}` pages.
//!
//! These exercise `parse_invoice` on real `lni1` encodings (Lexe-length and
//! shorter CLN-style) and the offer + invoice + preimage verify path.

use bolt12_common::{decode, verify_payment, Decoded};
use chrono::DateTime as ChronoDateTime;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OceanPayout {
    source: String,
    payment_hash: String,
    preimage: String,
    amount_msat: u64,
    offer: String,
    invoice: String,
}

fn fixtures() -> Vec<OceanPayout> {
    let payouts: Vec<OceanPayout> =
        serde_json::from_str(include_str!("fixtures/ocean_payouts.json"))
            .expect("ocean_payouts.json");
    assert!(
        !payouts.is_empty(),
        "ocean_payouts.json must contain at least one payout"
    );
    payouts
}

#[test]
fn decodes_ocean_invoices() {
    for payout in fixtures() {
        match decode(&payout.invoice)
            .unwrap_or_else(|err| panic!("{}: invoice decode failed: {err}", payout.source))
        {
            Decoded::Invoice(invoice) => {
                assert_eq!(
                    invoice.payment_hash, payout.payment_hash,
                    "{}",
                    payout.source
                );
                assert_eq!(invoice.amount_msat, payout.amount_msat, "{}", payout.source);
                assert_eq!(invoice.offer_id.as_deref().map(str::len), Some(64));
                assert_eq!(invoice.signature.len(), 128, "{}", payout.source);
                assert!(!invoice.payment_paths.is_empty(), "{}", payout.source);
                assert!(
                    invoice
                        .payment_paths
                        .iter()
                        .all(|path| path.payinfo.is_some()),
                    "{}",
                    payout.source
                );
                let created_at_iso = ChronoDateTime::parse_from_rfc3339(&invoice.created_at_iso)
                    .unwrap_or_else(|err| {
                        panic!(
                            "{}: invalid created_at_iso `{}`: {err}",
                            payout.source, invoice.created_at_iso
                        )
                    });
                assert_eq!(
                    created_at_iso.timestamp() as u64,
                    invoice.created_at,
                    "{}",
                    payout.source
                );
            }
            other => panic!("{}: expected invoice, got {other:?}", payout.source),
        }
    }
}

#[test]
fn decodes_ocean_offers() {
    for payout in fixtures() {
        match decode(&payout.offer)
            .unwrap_or_else(|err| panic!("{}: offer decode failed: {err}", payout.source))
        {
            Decoded::Offer(offer) => {
                assert_eq!(offer.offer_id.len(), 64, "{}", payout.source);
                assert!(
                    offer.issuer_id.is_some() || !offer.paths.is_empty(),
                    "{}: offer needs issuer_id or paths",
                    payout.source
                );
            }
            other => panic!("{}: expected offer, got {other:?}", payout.source),
        }
    }
}

#[test]
fn verifies_ocean_payouts() {
    for payout in fixtures() {
        let report = verify_payment(&payout.offer, &payout.invoice, &payout.preimage)
            .unwrap_or_else(|err| panic!("{}: verify error: {err}", payout.source));
        assert!(report.valid, "{}: {:?}", payout.source, report.checks);
    }
}

#[test]
fn rejects_wrong_preimage_on_ocean_payout() {
    let payout = &fixtures()[0];
    let report = verify_payment(
        &payout.offer,
        &payout.invoice,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(!report.valid);
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "preimage" && !check.passed));
}
