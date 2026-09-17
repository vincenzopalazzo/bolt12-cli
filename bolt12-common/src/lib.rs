//! Decode and verify BOLT 12 offers, invoices, and payer proofs.

mod decode;
mod error;
mod hex;
mod model;
mod verify;

mod capi;

pub use decode::{decode, tides_unsafe_invoice};
pub use error::{Error, ErrorKind};
pub use model::{
    Amount, BlindedHop, BlindedPath, BlindedPayInfo, Check, Decoded, IntroductionNode, Invoice,
    Offer, PayerProof, UnknownTlv, VerifyKind, VerifyReport,
};
pub use verify::{verify_payer_proof, verify_payment};
