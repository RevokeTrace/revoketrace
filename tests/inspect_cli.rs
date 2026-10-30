//! Runs the real `revoketrace` binary and checks what a user actually sees
//! when inspecting a caller-supplied saved report.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const ISSUER: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
const TRUSTOR: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";

struct Workdir(PathBuf);

impl Workdir {
    fn new(label: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "revoketrace-inspect-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ));
        fs::create_dir(&path).unwrap();
        Workdir(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn revoketrace(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_revoketrace"))
        .args(args)
        .output()
        .expect("run revoketrace")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8 stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

/// Produces a genuine JSON report by analyzing the bundled fixture.
fn genuine_report(dir: &Workdir) -> (PathBuf, Value) {
    let path = dir.path("genuine.json");
    let snapshot = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/live-testnet-discovery.json"
    );
    let output = revoketrace(&[
        "analyze",
        "--snapshot",
        snapshot,
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
        "--tx-source-account",
        ISSUER,
        "--sequence",
        "42",
        "--operation-index",
        "0",
        "--format",
        "json",
        "--output",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(10), "{}", stderr(&output));
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    (path, value)
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn inspect(path: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["inspect", "--report", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    revoketrace(&args)
}

/// Phrases that would make a saved file look verified, approved, or safe.
fn assert_no_misleading_wording(text: &str) {
    for phrase in [
        "SUPPORTED_SAFE",
        "approved",
        "safe to submit",
        "verification passed",
        "authenticated report",
        "RevokeTrace verified",
        "Forecast classification:",
        "Evidence classification:",
    ] {
        assert!(
            !text.contains(phrase),
            "misleading phrase {:?} in output:\n{}",
            phrase,
            text
        );
    }
}

fn assert_untrusted_banner(text: &str) {
    for required in [
        "RevokeTrace Saved Report Inspection",
        "NOT VERIFIED BY REVOKETRACE",
        "supplied by the caller",
        "origin is unauthenticated",
        "did not recompute the forecast",
        "not results verified by this run",
        "This is not transaction approval.",
    ] {
        assert!(
            text.contains(required),
            "missing {:?} in output:\n{}",
            required,
            text
        );
    }
}

#[test]
fn genuine_saved_report_is_presented_as_unverified_input() {
    let dir = Workdir::new("genuine");
    let (path, _) = genuine_report(&dir);
    let output = inspect(&path, &[]);
    let text = stdout(&output);

    assert_eq!(output.status.code(), Some(10));
    assert_untrusted_banner(&text);
    assert!(text.contains(
        "Saved evidence classification (unverified claim): LEDGER_CONSISTENT_INCOMPLETE"
    ));
    assert!(text.contains("Saved forecast classification (not recomputed): UNVERIFIED_FORECAST"));
    assert!(text.contains("Inspection notice: nothing above was verified by RevokeTrace."));
    assert_no_misleading_wording(&text);
}

#[test]
fn forged_complete_authority_label_is_shown_only_as_an_unverified_claim() {
    let dir = Workdir::new("forged-authority");
    let (_, mut report) = genuine_report(&dir);
    report["evidence"]["evidence_classification"] = Value::from("COMPLETE_AUTHORITATIVE_LEDGER");
    report["evidence"]["limitations"] = Value::Array(Vec::new());
    report["warnings"] = Value::Array(Vec::new());
    let forged = dir.path("forged.json");
    write_json(&forged, &report);

    let output = inspect(&forged, &[]);
    let text = stdout(&output);

    assert_eq!(output.status.code(), Some(10));
    assert_untrusted_banner(&text);
    assert!(text.contains(
        "Saved evidence classification (unverified claim): COMPLETE_AUTHORITATIVE_LEDGER"
    ));
    // A file with its limitations stripped must not read as "no limitations".
    assert!(
        text.contains(
            "None written in the file. This does not mean the evidence has no limitations."
        )
    );
    assert!(text.contains("Warnings (as written in the file):"));
    assert_no_misleading_wording(&text);

    // The same evidence analyzed freshly is still incomplete.
    let fresh_dir = Workdir::new("fresh-compare");
    let (_, fresh) = genuine_report(&fresh_dir);
    assert_eq!(
        fresh["evidence"]["evidence_classification"],
        "LEDGER_CONSISTENT_INCOMPLETE"
    );
}

#[test]
fn modified_forecast_classification_is_labelled_as_not_recomputed() {
    let dir = Workdir::new("forged-forecast");
    let (_, mut report) = genuine_report(&dir);
    report["forecast"]["classification"] = Value::from("SUPPORTED_BLOCKED");
    let forged = dir.path("forged.json");
    write_json(&forged, &report);

    let output = inspect(&forged, &[]);
    let text = stdout(&output);

    // The exit code follows the saved label by design; the text says so.
    assert_eq!(output.status.code(), Some(0));
    assert_untrusted_banner(&text);
    assert!(text.contains(
        "Saved forecast classification (not recomputed): SUPPORTED_BLOCKED (blocked by modeled rules)"
    ));
    assert_no_misleading_wording(&text);
}

#[test]
fn supported_safe_label_is_rejected_as_invalid_input() {
    let dir = Workdir::new("supported-safe");
    let (_, mut report) = genuine_report(&dir);
    report["forecast"]["classification"] = Value::from("SUPPORTED_SAFE");
    let forged = dir.path("forged.json");
    write_json(&forged, &report);

    let output = inspect(&forged, &[]);

    assert_eq!(output.status.code(), Some(40));
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("report JSON is invalid"));
}

#[test]
fn unsupported_schema_and_malformed_reports_are_rejected_without_output() {
    let dir = Workdir::new("rejects");
    let (_, mut report) = genuine_report(&dir);
    report["schema_version"] = Value::from(2);
    let wrong_schema = dir.path("schema.json");
    write_json(&wrong_schema, &report);
    let output = inspect(&wrong_schema, &[]);
    assert_eq!(output.status.code(), Some(40));
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("unsupported report schema version 2"));

    let malformed = dir.path("malformed.json");
    fs::write(&malformed, b"{ not json").unwrap();
    let output = inspect(&malformed, &[]);
    assert_eq!(output.status.code(), Some(40));
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("report JSON is invalid"));

    let missing = dir.path("missing.json");
    let output = inspect(&missing, &[]);
    assert_eq!(output.status.code(), Some(40));
    assert!(stdout(&output).is_empty());
}

#[test]
fn json_inspection_keeps_schema_one_unchanged_and_warns_on_stderr() {
    let dir = Workdir::new("json");
    let (path, original) = genuine_report(&dir);
    let output = inspect(&path, &["--format", "json"]);

    assert_eq!(output.status.code(), Some(10));
    let echoed: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(echoed, original, "schema 1 document must not change");
    assert_eq!(echoed["schema_version"], 1);
    let notice = stderr(&output);
    assert!(notice.contains("caller-supplied file"));
    assert!(notice.contains("unauthenticated"));
    assert!(notice.contains("did not recompute the forecast"));
    assert!(notice.contains("not transaction approval"));
}

#[test]
fn analyze_output_is_not_labelled_as_a_saved_inspection() {
    let dir = Workdir::new("fresh");
    let snapshot = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/live-testnet-discovery.json"
    );
    let output = revoketrace(&[
        "analyze",
        "--snapshot",
        snapshot,
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
    ]);
    let text = stdout(&output);
    drop(dir);

    assert_eq!(output.status.code(), Some(10));
    assert!(text.starts_with("RevokeTrace Forecast Report\n"));
    assert!(text.contains("Evidence classification: LEDGER_CONSISTENT_INCOMPLETE"));
    assert!(!text.contains("NOT VERIFIED BY REVOKETRACE"));
}

#[test]
fn help_describes_inspect_as_unverified_input() {
    for args in [&["help"][..], &["help", "inspect"][..]] {
        let output = revoketrace(args);
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(0));
        assert!(
            text.contains("unverified, caller-supplied data"),
            "help output: {}",
            text
        );
    }
}
