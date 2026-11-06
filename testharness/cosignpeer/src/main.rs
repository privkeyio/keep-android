//! A FROST peer for the phone's co-sign e2e. Reads one request line on stdin,
//! `<case> <salt> <relay> <passphrase> <share export>`, joins the relay with that share,
//! waits for the phone, asks it to co-sign a taproot spend, and prints one line:
//! `SIGNED <signature hex>` once the signature verifies under the group key, or
//! `ERR <reason>`.
//!
//! Cases: `one` pays 99,000 - salt sats to a P2WPKH output from a 100,000 sat input,
//! and `two` pays 90,000 - salt sats to a P2WPKH output and 8,500 sats to an OP_RETURN,
//! which has no address form. Both spend with SIGHASH_DEFAULT. `keypath` pays 98,000 -
//! salt sats to the same output but spends the group's own BIP-86 output on the key
//! path, so the phone signs under the tweaked output key. The salt, under 1,000, lets the phone tell this run's spend
//! from a relay's replay of an earlier run's.

use std::io::BufRead;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, TxOut, WPubkeyHash};
use keep_core::frost::ShareExport;
use keep_frost_net::{KfpNode, KfpNodeEvent, MSG_TYPE_BITCOIN_SIGHASH};
use tokio::time::timeout;

fn p2wpkh(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([3u8; 20])),
    }
}

fn fresh_txid() -> [u8; 32] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos();
    bitcoin::hashes::sha256::Hash::hash(&nanos.to_le_bytes()).to_byte_array()
}

// The transaction keep_frost_net's own tests build in key_spend_payload_paying, with any
// number of outputs: one 100,000 sat input locked by `spent` and spent with SIGHASH_DEFAULT.
fn payload_paying(spent: &ScriptBuf, outputs: Vec<TxOut>) -> ([u8; 32], Vec<u8>) {
    use bitcoin::absolute::LockTime;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Psbt, Sequence, Transaction, TxIn, Txid, Witness};

    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: spent.clone(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            // A fresh outpoint each run, so the same spend is never a replay of an earlier run's.
            previous_output: OutPoint::new(Txid::from_byte_array(fresh_txid()), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            TapSighashType::Default,
        )
        .expect("sighash");
    let payload = keep_frost_net::BitcoinSighashPayload {
        psbt: Psbt::from_unsigned_tx(tx).expect("unsigned tx").serialize(),
        input_index: 0,
        sighash_type: 0,
        prevouts: vec![bitcoin::consensus::serialize(&prevout)],
    };
    (
        sighash.to_byte_array(),
        serde_json::to_vec(&payload).expect("payload json"),
    )
}

async fn run(line: &str) -> Result<String, String> {
    let mut fields = line.split_whitespace();
    let (Some(case), Some(salt), Some(relay), Some(passphrase), Some(export)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err("expected: <case> <salt> <relay> <passphrase> <share export>".into());
    };
    let salt: u64 = match salt.parse() {
        Ok(s) if s < 1_000 => s,
        _ => return Err(format!("bad salt {salt}")),
    };
    let outputs = match case {
        "one" => vec![p2wpkh(99_000 - salt)],
        "keypath" => vec![p2wpkh(98_000 - salt)],
        "two" => vec![
            p2wpkh(90_000 - salt),
            TxOut {
                value: Amount::from_sat(8_500),
                script_pubkey: ScriptBuf::new_op_return([2u8; 4]),
            },
        ],
        other => return Err(format!("unknown case {other}")),
    };
    let share = ShareExport::parse(export)
        .and_then(|e| e.to_share(passphrase, "cosign-peer"))
        .map_err(|e| format!("share: {e}"))?;
    let group_pubkey = *share.group_pubkey();
    let key_path = case == "keypath";
    let spent = if key_path {
        keep_core::frost::taproot::TaprootTweak::default()
            .script_pubkey(&group_pubkey)
            .map_err(|e| format!("group output: {e}"))?
    } else {
        ScriptBuf::new_op_return([1u8; 4])
    };
    let mut node = KfpNode::new(share, vec![relay.to_string()])
        .await
        .map_err(|e| format!("node: {e}"))?;
    let mut events = node.subscribe();
    let _shutdown = node.take_shutdown_handle();
    let node = Arc::new(node);
    let runner = Arc::clone(&node);
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    timeout(Duration::from_secs(90), async {
        while !matches!(events.recv().await, Ok(KfpNodeEvent::PeerDiscovered { .. })) {}
    })
    .await
    .map_err(|_| "the phone was not discovered".to_string())?;
    // Seeing the phone's announcement does not mean the phone has seen this one yet, and
    // until it has, it drops the request unanswered. So a request that times out is
    // announced and sent again, as a fresh transaction with the same outputs, since the
    // same one again would be a replay. A refusal or a signature is the phone's answer.
    let mut attempt = 0;
    let (sighash, signature) = loop {
        attempt += 1;
        let (sighash, payload) = payload_paying(&spent, outputs.clone());
        let request = async {
            if key_path {
                node.request_key_path_spend(sighash.to_vec(), payload, vec![], Default::default())
                    .await
            } else {
                node.request_signature_structured(
                    sighash.to_vec(),
                    MSG_TYPE_BITCOIN_SIGHASH,
                    Some(payload),
                )
                .await
            }
        };
        let result = timeout(Duration::from_secs(60), request).await;
        match result {
            Ok(Ok(signature)) => break (sighash, signature),
            Ok(Err(keep_frost_net::FrostNetError::Timeout(msg)))
                if attempt < 3 && !msg.contains("Peer reported error") => {}
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) if attempt < 3 => {}
            Err(_) => return Err("no answer from the phone".into()),
        }
        eprintln!("attempt {attempt} unanswered, announcing again");
        let _ = node.announce().await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    let secp = Secp256k1::verification_only();
    let internal = XOnlyPublicKey::from_slice(&group_pubkey).map_err(|e| e.to_string())?;
    // The key-path output key is tweaked here with the bitcoin crate rather than the
    // core's own tweak, so the check does not share a bug with the signer.
    let signer = if key_path {
        let (tweaked, _) = internal.tap_tweak(&secp, None);
        if ScriptBuf::new_p2tr_tweaked(tweaked) != spent {
            return Err("the spent output is not the group's BIP-86 output".into());
        }
        tweaked.to_x_only_public_key()
    } else {
        internal
    };
    secp.verify_schnorr(
        &Signature::from_slice(&signature).map_err(|e| e.to_string())?,
        &Message::from_digest(sighash),
        &signer,
    )
    .map_err(|e| format!("the signature does not verify: {e}"))?;
    Ok(format!("SIGNED {}", hex::encode(signature)))
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    match run(line.trim()).await {
        Ok(out) => println!("{out}"),
        Err(e) => println!("ERR {}", e.replace('\n', " ")),
    }
}
