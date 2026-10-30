//! Runs the real `revoketrace` binary against inputs that `live` must refuse
//! before it contacts any network.

use std::process::{Command, Output};

const ISSUER: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
const TRUSTOR: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";

fn live(passphrase: &str, horizon: &str, rpc: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_revoketrace"))
        .args([
            "live",
            "--network-passphrase",
            passphrase,
            "--horizon-url",
            horizon,
            "--rpc-url",
            rpc,
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
        ])
        .output()
        .expect("run revoketrace")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

#[test]
fn live_refuses_a_non_testnet_passphrase_before_any_request() {
    let output = live(MAINNET, "https://127.0.0.1:9", "https://127.0.0.1:9");
    assert_eq!(output.status.code(), Some(40));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("only the Stellar Testnet network passphrase"));
}

#[test]
fn live_refuses_cleartext_non_loopback_endpoints_before_any_request() {
    for (horizon, rpc, label) in [
        ("http://horizon.example", "https://127.0.0.1:9", "Horizon"),
        ("https://127.0.0.1:9", "http://rpc.example", "RPC"),
    ] {
        let output = live(TESTNET, horizon, rpc);
        assert_eq!(output.status.code(), Some(40), "{} {}", horizon, rpc);
        assert!(output.stdout.is_empty());
        let message = stderr(&output);
        assert!(message.contains(label), "{}", message);
        assert!(message.contains("https://"), "{}", message);
    }
}

#[test]
fn live_reports_an_unreachable_loopback_endpoint_as_a_network_failure() {
    // Port 9 on loopback refuses connections, so this exercises the real curl
    // transport failure path without leaving the machine.
    let output = live(TESTNET, "http://127.0.0.1:9", "http://127.0.0.1:9");
    assert_eq!(output.status.code(), Some(50));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("live evidence acquisition failed"));
}
