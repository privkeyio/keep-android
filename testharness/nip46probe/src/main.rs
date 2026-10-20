//! Host-side NIP-46 client for BunkerRevokeE2ETest. Reads one request line on stdin,
//! so client secrets and bunker URLs never appear on a command line:
//!
//!   pubkey  <client_secret_hex>
//!   nsec    <secret_hex>        (bech32 form, for importing a test account)
//!   connect <client_secret_hex> <bunker_url> [timeout_secs]
//!   sign    <client_secret_hex> <bunker_url> <kind> [timeout_secs]
//!
//! `sign` sends sign_event without connecting first, so it can exercise a grant the
//! bunker restored from disk. Prints one line: `OK <result>`, `ERR <error>`, `TIMEOUT`,
//! or `UNSENT <reason>` when no relay took the subscription or the request.

use std::time::Duration;

use nostr::nips::nip46::NostrConnectURI;
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).expect("request on stdin");
    let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let keys = Keys::parse(&args[1]).expect("client secret key");
    let timeout = |i: usize| args.get(i).map(|s| s.parse().expect("timeout")).unwrap_or(25);
    match args[0].as_str() {
        "pubkey" => println!("{}", keys.public_key().to_hex()),
        "nsec" => println!("{}", keys.secret_key().to_bech32().expect("bech32")),
        "connect" => {
            let (signer, relays, secret) = bunker(&args[2]);
            let mut params = vec![signer.to_hex()];
            params.extend(secret);
            println!("{}", request(&keys, signer, &relays, "connect", params, timeout(3)).await);
        }
        "sign" => {
            let (signer, relays, _) = bunker(&args[2]);
            let kind: u16 = args[3].parse().expect("kind");
            let event = serde_json::json!({
                "kind": kind,
                "content": "keep-android bunker revoke e2e",
                "tags": [],
                "created_at": Timestamp::now().as_secs()
            })
            .to_string();
            println!("{}", request(&keys, signer, &relays, "sign_event", vec![event], timeout(4)).await);
        }
        other => panic!("unknown command {other}"),
    }
}

fn debug(line: String) {
    if std::env::var_os("NIP46PROBE_DEBUG").is_some() {
        eprintln!("{line}");
    }
}

fn bunker(url: &str) -> (PublicKey, Vec<RelayUrl>, Option<String>) {
    match NostrConnectURI::parse(url).expect("bunker url") {
        NostrConnectURI::Bunker { remote_signer_public_key, relays, secret } => (remote_signer_public_key, relays, secret),
        NostrConnectURI::Client { .. } => panic!("expected a bunker:// url"),
    }
}

async fn request(keys: &Keys, signer: PublicKey, relays: &[RelayUrl], method: &str, params: Vec<String>, timeout: u64) -> String {
    let client = Client::new(keys.clone());
    for relay in relays {
        client.add_relay(relay.clone()).await.expect("add relay");
    }
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;
    // Signers may backdate their replies by a few seconds, so look back rather than from now;
    // the reply is matched on the request id below.
    let since = Timestamp::from_secs(Timestamp::now().as_secs().saturating_sub(60));
    let filter = Filter::new().kind(Kind::NostrConnect).pubkey(keys.public_key()).since(since);
    let subscribed = client.subscribe(filter, None).await.expect("subscribe");
    if subscribed.success.is_empty() {
        client.disconnect().await;
        return format!("UNSENT subscribe failed {:?}", subscribed.failed);
    }
    let mut notifications = client.notifications();

    // Random, so a reply to an earlier request from the same client key never matches.
    let id = Keys::generate().public_key().to_hex();
    let body = serde_json::json!({ "id": id, "method": method, "params": params }).to_string();
    let content = nip44::encrypt(keys.secret_key(), &signer, &body, nip44::Version::V2).expect("encrypt");
    let event = EventBuilder::new(Kind::NostrConnect, content)
        .tag(Tag::public_key(signer))
        .sign_with_keys(keys)
        .expect("sign request");
    let sent = client.send_event(&event).await.expect("send request");
    debug(format!("sent {} to {:?}, failed {:?}", event.id, sent.success, sent.failed));
    // A request no relay took cannot be answered; never let it pass for a TIMEOUT.
    if sent.success.is_empty() {
        client.disconnect().await;
        return format!("UNSENT {:?}", sent.failed);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
    let out = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(received) = tokio::time::timeout(left, notifications.recv()).await else {
            break "TIMEOUT".to_string();
        };
        let Ok(RelayPoolNotification::Event { event, .. }) = received else { continue };
        debug(format!("received kind {} from {} at {}", event.kind, event.pubkey, event.created_at));
        if event.pubkey != signer {
            continue;
        }
        let Ok(plain) = nip44::decrypt(keys.secret_key(), &signer, &event.content) else { continue };
        let Ok(response) = serde_json::from_str::<serde_json::Value>(&plain) else { continue };
        if response["id"] != id {
            continue;
        }
        match response["error"].as_str().filter(|e| !e.is_empty()) {
            Some(err) => break format!("ERR {err}"),
            None => break format!("OK {}", response["result"]),
        }
    };
    client.disconnect().await;
    out
}
