use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::offer::Offer;
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning_payer_proof::{verify, VerifyError};
use std::str::FromStr;

use crate::decode::parse_invoice;
use crate::error::Error;
use crate::hex;
use crate::model::{Check, VerifyKind, VerifyReport};

/// Verify an official BOLT 12 payer proof (`lnp1...`) against an offer.
///
/// [`lightning_payer_proof::verify`] checks bech32, merkle reconstruction,
/// invoice-node signature, payer signature, and
/// `SHA256(preimage) == payment_hash`. Failed cryptographic checks arrive as
/// [`VerifyError::MalformedProof`] and are not distinguished from each other.
///
/// `pays_offers_recipient` then checks that the invoice issuer can sign for
/// `offer`'s recipient. That is a recipient match, not "this paid this exact
/// offer".
pub fn verify_payer_proof(encoded: &str, offer: &str) -> Result<VerifyReport, Error> {
    let mut checks = Vec::new();

    let proof = match verify(encoded.trim()) {
        Ok(proof) => {
            checks.push(Check::pass("decode"));
            checks.push(Check::pass("merkle_root"));
            checks.push(Check::pass("invoice_signature"));
            checks.push(Check::pass("payer_signature"));
            checks.push(Check::pass("preimage"));
            proof
        }
        Err(VerifyError::InvalidBech32) => {
            checks.push(Check::fail("decode", "not a bech32-encoded payer proof"));
            return Ok(VerifyReport::new(VerifyKind::PayerProof, checks));
        }
        Err(err) => {
            checks.push(Check::fail("decode", err.to_string()));
            return Ok(VerifyReport::new(VerifyKind::PayerProof, checks));
        }
    };

    let offer = match Offer::from_str(offer.trim()) {
        Ok(offer) => {
            checks.push(Check::pass("decode_offer"));
            offer
        }
        Err(err) => {
            checks.push(Check::fail(
                "decode_offer",
                format!("offer decode failed: {err:?}"),
            ));
            return Ok(VerifyReport::new(VerifyKind::PayerProof, checks));
        }
    };

    if proof.pays_offers_recipient(&offer) {
        checks.push(Check::pass("pays_offers_recipient"));
    } else {
        checks.push(Check::fail(
            "pays_offers_recipient",
            "invoice issuer cannot sign for this offer's recipient",
        ));
    }

    Ok(VerifyReport::new(VerifyKind::PayerProof, checks))
}

/// Verify an Ocean-style offer + invoice + preimage triple.
///
/// Steps: decode offer, decode invoice (includes invoice BIP-340 signature),
/// signing pubkey match, `offer_id` match, `SHA256(preimage) == payment_hash`.
pub fn verify_payment(
    offer: &str,
    invoice: &str,
    preimage_hex: &str,
) -> Result<VerifyReport, Error> {
    let mut checks = Vec::new();

    let offer = match Offer::from_str(offer.trim()) {
        Ok(offer) => {
            checks.push(Check::pass("decode_offer"));
            offer
        }
        Err(err) => {
            checks.push(Check::fail(
                "decode_offer",
                format!("offer decode failed: {err:?}"),
            ));
            return Ok(VerifyReport::new(VerifyKind::Payment, checks));
        }
    };

    let invoice = match parse_invoice(invoice.trim()) {
        Ok(invoice) => {
            checks.push(Check::pass("decode_invoice"));
            checks.push(Check::pass("invoice_signature"));
            invoice
        }
        Err(err) => {
            checks.push(Check::fail("decode_invoice", err.message));
            return Ok(VerifyReport::new(VerifyKind::Payment, checks));
        }
    };

    if signing_pubkeys_match(&offer, &invoice) {
        checks.push(Check::pass("signing_pubkey"));
    } else {
        checks.push(Check::fail(
            "signing_pubkey",
            "offer signing pubkey does not match invoice node_id",
        ));
    }

    match invoice.offer_id() {
        Some(invoice_offer_id) if invoice_offer_id == offer.id() => {
            checks.push(Check::pass("offer_id"));
        }
        Some(_) => checks.push(Check::fail(
            "offer_id",
            "offer_id does not match invoice offer_id",
        )),
        None => checks.push(Check::fail("offer_id", "invoice has no offer_id")),
    }

    match parse_preimage(preimage_hex) {
        Ok(preimage) => {
            let computed: PaymentHash = preimage.into();
            if computed == invoice.payment_hash() {
                checks.push(Check::pass("preimage"));
            } else {
                checks.push(Check::fail(
                    "preimage",
                    "SHA256(preimage) does not match invoice payment_hash",
                ));
            }
        }
        Err(err) => checks.push(Check::fail("preimage", err.message)),
    }

    Ok(VerifyReport::new(VerifyKind::Payment, checks))
}

fn parse_preimage(hex: &str) -> Result<PaymentPreimage, Error> {
    Ok(PaymentPreimage(hex::decode_32(hex.trim())?))
}

/// Same rule LDK uses when checking `invoice_node_id` against an offer:
/// explicit `issuer_id`, otherwise the last blinded hop of any offer path.
fn signing_pubkeys_match(offer: &Offer, invoice: &Bolt12Invoice) -> bool {
    let invoice_key = invoice.signing_pubkey();
    if let Some(issuer) = offer.issuer_signing_pubkey() {
        return issuer == invoice_key;
    }
    offer
        .paths()
        .iter()
        .filter_map(|path| path.blinded_hops().last())
        .any(|hop| hop.blinded_node_id == invoice_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode;
    use crate::model::Decoded;

    const GOOD_OFFER: &str = concat!(
        "lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejw",
        "qmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0",
        "e3eryszey4234ym2a99vzhq"
    );
    const GOOD_INVOICE: &str = concat!(
        "lni1qqg9sr0tna8ljw0tp9zk9uehh7s8vz3ufap52s2wypgxz7t0w468xgrxdaezqcnr",
        "x9chswp5ds6rwen2x4nhyees8qmnyuphvearscfhxdkhwar3x33hxe3kx3ehgmt9zcss",
        "8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9w2gpsz28qtqssxstn",
        "fpsaqtgdhchfv70shwvganrwuk28gwz9f6v5nlt37s0xh7hp5zvq8cjq3fylqlf0gzp6",
        "gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9wq27sqsf52x7pdt5432aztt8ee3s5l20g",
        "3u0whwudkk5asanadjzz5qgzhgehdw5jyjf6m83awzntjkxykywzxycduph6gp5crv29",
        "qjf9gsasqv394jhcqgta9q4cr975hw4vl5nzekvuzujxv0u7rngsse707e0pq4duexv3",
        "930unvay593kd38t6z8em29zrsqqqqqqqqqqqqqqzgqqqqqqqqqqqqqayjedltzjqqqq",
        "qq9yq359nfhm4qst3qczk7fkkjhhqs6syjuygh3q87t8jsmtg04xvzu6vsys3fggzt92",
        "qvqj3c9wqvpqqq9syyp7ysy2f8c86t6qswj8x3qn3mufuashucu3jgpvj24g6jd4wjjk",
        "pthsgqtas84k74uvj2uvxh32exre34mu4vsc5cnmqpftru4cw0s6wujsk8ggn30v3jll",
        "8rn98r3xmlymy850udw2smfmse0amens93mk6fzt"
    );
    const GOOD_PREIMAGE: &str = "a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc";
    const GOOD_PREIMAGE_2: &str =
        "5160372ae4c10b8202113127c77d1d7665cd43422133a20879423a3d84129d67";

    const PHOENIX_OFFER: &str = concat!(
        "lno1pgd57cm9v9hzqnmxvejhygzrd35jqanpd35kgct5d9hkugqsacpcvnhsyh77376c",
        "0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrczf6ycmt3ftr363p6f3fm08epd84y0",
        "lkz4t5zphpuygjqnwxzklltqyqnv4q7rx9lc4k8zjcyy7jdxaupjyuhfu7j7jkrdszh9",
        "xah04npkysqrxka4j4yxve6j8czdzcr56f5m5hku3uy0zlqn3genn8pszptkms5u6vv6",
        "u7qjej4sg4r00r8lpkeuk9allsgz2gqhm8qmj9cuwcfttex5366yvcma274gtaysskp5",
        "nmxrl9h3gsdsqv38tquert0z9py4uadrnuceanv26ytqw2pwys6909szlpw562u5lw8g",
        "v0ne7jnz52w9903vfv28pdpswrq"
    );
    const PHOENIX_INVOICE: &str = concat!(
        "lni1qqgpllwtmnmv6xspe70m78ptxrr5vzsmfa3k2ctwyp8kven9wgsyxmrfypmxzmrf",
        "v3shg6t0dcsppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878s",
        "yn5f3khzjk8r4zr5nznk70jz602gllv92hgyrwrcg3ypxuv9dl7kqgpxe2puxvtl3tvw",
        "99sgfay6dmcryfewnea9a9vxmq9w2dmwltxrvfqqxddmt92gven4y0sy69s8f5nfhf0d",
        "ercg797p8z3n8xwrqyzhdhpfe5ce4eup9n9tq32x77x07rdnevtmllqsy5sp0kwphyt3",
        "casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qmqqezwkpejxk7y2zfte6688e3nmxc",
        "45gkqu5zufp527tq97zaf54ef7uwscl8na9x9g5u22lzcjc5wz6rqux9yqc0gfq9gqzc",
        "yypaauxsjgg80qzvfrysks88du2s78vme6neec3jt5axdcrj4yj8a99ql5qm2quxfmcz",
        "tl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upfh49ulj5edehzplt3t9fy",
        "w9m2j63x9nmey3r8204yfqpj0y5zzlqzqv5wvsgcqc463wtwd2npxp2t953yqp5vj7j8",
        "29em3apsnt56chhx2qz9rl9mszedhld2xpuzgthfx007d585x4nfxtdefz74f355mua8",
        "wwnnr0weqkgeyj8fa72saljsa0kjzhys9w3dt60k9jxqjddkttw5x50l99smn9grg39v",
        "0up6s83lvf5x3nxs3knpvm7qpz8vtl7gj78q9jv7yt8cw0nqpecrvfcy4a0tq2z7560l",
        "ys4tzp3j2586awqv2pgm66plh4a0q73jw3fq3yzl0tje4u5emck0p3x5p5w9gr74xsht",
        "kplmk9p68qwa6uz4m3ez4gv35ldgnl3zytpnm6fszejm4rk4f8g6vrknh7cuas5qq6tg",
        "t3f0grshlxxzkcyyzm6jp60p9mym870h2nuk9cl2cz3urvd0qksyegf6lq6gquzy0xum",
        "kwge00066l8yyss5wh44hz7vr5nssx0ywst5ju5escm85qwyv4jjs8qdlg2llun2zfym",
        "p4qqu8u30avlt52879nsfwgvskvvv3hrmggelcjysxnegcgfxexeaz2k6zttq9vdf4pw",
        "fy7qfwcnf88j5gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqr6zgqqqq5szxshfd",
        "u6nqxq23sz5zqcu908d9dzgtmzva3vh28mpjz4hggyja3r8d48x6cuhxky628xjp4gps",
        "7sjq4cpsyqqqkqssy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qm",
        "7pqx6pt4td9rrz7ek6gpfzner0dmq9zz92md57cnee4mfv7mktgjj7c3vqn66pdzy80f",
        "zgu9sarhtdgd3sy6fl0pzq2dac6m5p87qd393q"
    );

    // LDK payer-proof vector `minimal_disclosure`.
    const LNP_MINIMAL: &str = "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgq9rxgj9dzm24ehdy5sp90tluyrjcqltmjnl538etvplrngfhc5tp2punsepqktcekqd5p5f09nzeq86qrlj2rxdcngckuyll5w84cce79qva0p96s9zmynmt672hpqq74p0hdag733w3hvq9wcnupgtn0ef8d690svmg6j8vaq0jlyadmq5ru35xnzaf7398gwjawyfd6adn9z4en7s86fqqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyql6ql2qcqsyk26tw5l6qlt5zlcev436mafhnw2k5qmt8uzcew9q6mlgdg5wdlhr9l3lnl2awk5rw2qdaxw2f4x5r2wpvax8mvf4qewx89ejwwluxnmthtjxtfjcq4tekwyfdfmx9cqe8ksuveseep97lccltp0c82kdg6ydppeya8suvtflxps7tpswr8m45flmccwudkdw9p4jytya5fqgz5u6k2uj6zq4jve32ml48r587uahkcd34r0hcadxv6qp0g87v5dekmqppushjwjm07s8mrq7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenlqxgux5qqy364fwxs5xtgnznef0eaazvcy4c30rvnrtlmv48scxn7j2mhh83cgdjs7mxha62tvaf7480n2vm3pvzdae5x45mk29d9ev";
    const LNP_PREIMAGE: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn accepts_known_good_triple() {
        let report = verify_payment(GOOD_OFFER, GOOD_INVOICE, GOOD_PREIMAGE).unwrap();
        assert!(report.valid, "{report:?}");
    }

    #[test]
    fn rejects_wrong_preimage() {
        let report = verify_payment(GOOD_OFFER, GOOD_INVOICE, GOOD_PREIMAGE_2).unwrap();
        assert!(!report.valid);
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "preimage" && !c.passed));
    }

    #[test]
    fn rejects_phoenix_mismatch() {
        let report = verify_payment(PHOENIX_OFFER, PHOENIX_INVOICE, GOOD_PREIMAGE).unwrap();
        assert!(!report.valid);
    }

    #[test]
    fn verifies_ldk_minimal_payer_proof() {
        match decode(LNP_MINIMAL).unwrap() {
            Decoded::PayerProof(proof) => {
                assert_eq!(proof.payment_preimage, LNP_PREIMAGE);
            }
            other => panic!("expected payer proof, got {other:?}"),
        }
    }

    #[test]
    fn verifies_payer_proof_against_matching_offer() {
        let offer = bech32_from_hex::<lightning::offers::offer::Offer>(include_str!(
            "../tests/fixtures/payer_proof/offer.hex"
        ));
        let proof = bech32_from_hex::<lightning::offers::payer_proof::PayerProof>(include_str!(
            "../tests/fixtures/payer_proof/offer_proof.hex"
        ));
        let report = verify_payer_proof(&proof, &offer).unwrap();
        assert!(report.valid, "{report:?}");
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "pays_offers_recipient" && c.passed));
    }

    #[test]
    fn rejects_payer_proof_for_other_offer_recipient() {
        let other = bech32_from_hex::<lightning::offers::offer::Offer>(include_str!(
            "../tests/fixtures/payer_proof/other_offer.hex"
        ));
        let proof = bech32_from_hex::<lightning::offers::payer_proof::PayerProof>(include_str!(
            "../tests/fixtures/payer_proof/offer_proof.hex"
        ));
        let report = verify_payer_proof(&proof, &other).unwrap();
        assert!(!report.valid);
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "pays_offers_recipient" && !c.passed));
    }

    #[test]
    fn rejects_garbage_payer_proof() {
        let report = verify_payer_proof("lnp1qqqq", GOOD_OFFER).unwrap();
        assert!(!report.valid);
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "decode" && !c.passed));
    }

    fn bech32_from_hex<T>(hex: &str) -> String
    where
        T: TryFrom<Vec<u8>> + ToString,
        T::Error: core::fmt::Debug,
    {
        let hex = hex.trim();
        assert!(
            hex.len() % 2 == 0,
            "vector must have an even number of hex digits"
        );
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector must be valid hex"))
            .collect::<Vec<_>>();
        T::try_from(bytes)
            .expect("LDK test vector must decode")
            .to_string()
    }
}
