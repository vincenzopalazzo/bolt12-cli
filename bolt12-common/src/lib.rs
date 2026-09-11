//! Decode and verify BOLT 12 offers, invoices, and payer proofs.

mod bech32;
mod decode;
mod error;
mod hex;
mod model;
mod verify;

pub use decode::decode;
pub use error::{Error, ErrorKind};
pub use model::{Amount, Check, Decoded, Invoice, Offer, PayerProof, VerifyKind, VerifyReport};
pub use verify::{verify_payer_proof, verify_payment};
