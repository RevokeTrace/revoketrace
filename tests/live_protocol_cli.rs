//! End-to-end checks of how `revoketrace live` handles the ledger protocol
//! version reported by an RPC server. A loopback HTTP server stands in for
//! Horizon and Stellar RPC, and the real binary talks to it with real `curl`.
//! Nothing leaves the machine.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;

use stellar_xdr::{
    Hash, LedgerHeader, LedgerHeaderExt, Limits, ReadXdr, StellarValue, StellarValueExt, TimePoint,
    UpgradeType, VecM, WriteXdr,
};

const ISSUER: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
const TRUSTOR: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
const TESTNET: &str = "Test SDF Network ; September 2015";
const LEDGER_HASH: &str = "0000000000000000000000000000000000000000000000000000000000001234";

fn header(version: u32) -> LedgerHeader {
    LedgerHeader {
        ledger_version: version,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: TimePoint(1_793_098_875),
            upgrades: VecM::<UpgradeType, 6>::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash([0u8; 32]),
        ledger_seq: 5000,
        total_coins: 100_000_000_000_000_000,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 1000,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 100,
        skip_list: [
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
        ],
        ext: LedgerHeaderExt::V0,
    }
}

fn valid_header_xdr(version: u32) -> String {
    header(version).to_xdr_base64(Limits::none()).unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A header using the millisecond `StellarValue` arm (discriminant 3) that
/// Stellar Core selects from protocol 30. The pinned decoder cannot parse it.
fn protocol_30_style_header_xdr() -> String {
    let mut bytes = header(30).to_xdr(Limits::none()).unwrap();
    let offset = 4 + 32 + 32 + 8 + 4;
    bytes[offset..offset + 4].copy_from_slice(&3_u32.to_be_bytes());
    let encoded = base64_encode(&bytes);
    assert!(LedgerHeader::from_xdr_base64(&encoded, Limits::none()).is_err());
    encoded
}

/// Serves one Horizon account (no balances) for GET and the given
/// `getLatestLedger` body for POST, on a loopback port.
fn serve(latest_ledger_body: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap_or(0);
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(position + 4);
                }
            };
            let Some(header_end) = header_end else {
                continue;
            };
            let head = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + length {
                let read = stream.read(&mut buffer).unwrap_or(0);
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let body = if head.starts_with("get ") {
                format!(r#"{{"id":"{}","balances":[]}}"#, TRUSTOR)
            } else {
                latest_ledger_body.clone()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn latest_ledger(rpc_version: u32, header_xdr: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "id": LEDGER_HASH, "protocolVersion": rpc_version,
            "sequence": 5000, "headerXdr": header_xdr
        }
    })
    .to_string()
}

fn live(latest_ledger_body: String) -> Output {
    let port = serve(latest_ledger_body);
    let url = format!("http://127.0.0.1:{}", port);
    Command::new(env!("CARGO_BIN_EXE_revoketrace"))
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .args([
            "live",
            "--network-passphrase",
            TESTNET,
            "--horizon-url",
            &url,
            "--rpc-url",
            &url,
            "--operation",
            "SetTrustLineFlags",
            "--source-account",
            ISSUER,
            "--trustor",
            TRUSTOR,
            "--asset-code",
            "FLUTTER",
            "--asset-issuer",
            ISSUER,
            "--before-flags",
            "1",
            "--after-flags",
            "0",
            "--timeout-secs",
            "10",
        ])
        .output()
        .expect("run revoketrace")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn protocol_30_ledger_is_unsupported_even_though_its_header_cannot_be_decoded() {
    let output = live(latest_ledger(30, &protocol_30_style_header_xdr()));
    assert_eq!(output.status.code(), Some(30), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("reviewed range 18 to 29"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn unsupported_rpc_version_wins_over_a_garbage_header() {
    for version in [17, 30, u32::MAX] {
        let output = live(latest_ledger(version, "not-base64-xdr!!"));
        assert_eq!(
            output.status.code(),
            Some(30),
            "{} {}",
            version,
            stderr(&output)
        );
    }
}

#[test]
fn supported_version_with_a_malformed_header_is_a_provider_data_failure() {
    let output = live(latest_ledger(29, "not-base64-xdr!!"));
    assert_eq!(output.status.code(), Some(50), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("LedgerHeader"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn rpc_and_header_protocol_disagreement_is_inconclusive() {
    let output = live(latest_ledger(29, &valid_header_xdr(28)));
    assert_eq!(output.status.code(), Some(20), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("inconsistent protocol version"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn matching_supported_versions_pass_the_protocol_checks() {
    // The loopback RPC does not implement getLedgerEntries, so the run still
    // fails later, but not with an unsupported or inconsistent protocol error.
    for version in [18, 29] {
        let output = live(latest_ledger(version, &valid_header_xdr(version)));
        let text = stderr(&output);
        assert_ne!(output.status.code(), Some(30), "{} {}", version, text);
        assert!(
            !text.contains("inconsistent protocol version"),
            "{} {}",
            version,
            text
        );
        assert!(!text.contains("reviewed range"), "{} {}", version, text);
    }
}
