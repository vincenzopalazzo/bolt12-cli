use std::io::{self, Write};
use std::process::ExitCode;

use clap::error::ErrorKind as ClapErrorKind;
use clap::{Parser, Subcommand};
use serde_json::Value;

use bolt12_common::{decode, verify_payer_proof, verify_payment, Error, ErrorKind};

#[derive(Debug, Parser)]
#[command(
    name = "bolt12",
    about = "Swiss army knife for BOLT12 offers, invoices, and payer proofs"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode a BOLT12 offer (`lno1`), invoice (`lni1`), or payer proof (`lnp1`).
    Decode {
        /// Bech32-encoded BOLT12 string.
        encoded: String,
    },
    /// Verify a payer proof or an offer+invoice+preimage triple.
    Verify {
        /// Official BOLT12 payer proof (`lnp1...`). Requires `--offer`.
        proof: Option<String>,
        /// BOLT12 offer (`lno1...`). Required for both verify paths.
        #[arg(long)]
        offer: Option<String>,
        /// BOLT12 invoice (`lni1...`).
        #[arg(long)]
        invoice: Option<String>,
        /// Payment preimage (64 hex characters).
        #[arg(long)]
        preimage: Option<String>,
    },
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => return handle_clap_error(err),
    };
    match run(args) {
        Ok(RunOutcome { value, valid }) => {
            if print_json(&value).is_err() {
                return ExitCode::from(1);
            }
            if valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            let value = serde_json::to_value(&err).unwrap_or_else(|_| {
                serde_json::json!({
                    "error": "invalid_argument",
                    "message": "failed to serialize error",
                })
            });
            if print_json(&value).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::from(1)
        }
    }
}

fn handle_clap_error(err: clap::Error) -> ExitCode {
    match err.kind() {
        ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion => {
            let _ = err.print();
            ExitCode::SUCCESS
        }
        _ => {
            let value = serde_json::json!({
                "error": "invalid_argument",
                "message": err.to_string(),
            });
            if print_json(&value).is_err() {
                return ExitCode::from(1);
            }
            ExitCode::from(1)
        }
    }
}

struct RunOutcome {
    value: Value,
    valid: bool,
}

fn run(args: Args) -> Result<RunOutcome, Error> {
    match args.command {
        Command::Decode { encoded } => {
            let decoded = decode(&encoded)?;
            Ok(RunOutcome {
                value: to_value(&decoded)?,
                valid: true,
            })
        }
        Command::Verify {
            proof,
            offer,
            invoice,
            preimage,
        } => {
            let report = match (proof, offer, invoice, preimage) {
                (Some(proof), Some(offer), None, None) => {
                    let hrp = proof
                        .trim()
                        .split_once('1')
                        .map(|(hrp, _)| hrp.to_ascii_lowercase());
                    if hrp.as_deref() != Some("lnp") {
                        return Err(Error::new(
                            ErrorKind::InvalidArgument,
                            "positional verify expects a payer proof (`lnp1...`); use `--offer --invoice --preimage` for a payment triple",
                        ));
                    }
                    verify_payer_proof(&proof, &offer)?
                }
                (None, Some(offer), Some(invoice), Some(preimage)) => {
                    verify_payment(&offer, &invoice, &preimage)?
                }
                (Some(_), None, None, None) => {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        "verify a payer proof requires `--offer <lno1...>`",
                    ));
                }
                (Some(_), _, _, _) => {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        "verify a payer proof with `bolt12 verify <lnp1...> --offer <lno1...>` or a payment with `--offer --invoice --preimage`, not both",
                    ));
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        "verify requires `<lnp1...> --offer <lno1...>` or `--offer --invoice --preimage`",
                    ));
                }
            };
            Ok(RunOutcome {
                valid: report.valid,
                value: to_value(&report)?,
            })
        }
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|err| {
        Error::new(
            ErrorKind::InvalidArgument,
            format!("json serialize failed: {err}"),
        )
    })
}

fn print_json(value: &Value) -> io::Result<()> {
    let encoded = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{encoded}")?;
    stdout.flush()
}
