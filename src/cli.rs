//! Command-line orchestration for RevokeTrace.
//!
//! The CLI owns input validation, bounded file I/O, report presentation, and
//! exit-code mapping. Forecast calculations remain in `crate::evaluate` and
//! live evidence acquisition remains in the existing bounded adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
use std::sync::{Arc, Barrier, Mutex, OnceLock};

use serde_json::Value;

use crate::evidence::{AuthoritativeCaptureArtifact, EvidenceClassification};
use crate::report::{ReportClassification, ReportDocument, ReportMode, render_human};
use crate::{
    AuthoritativeEvidenceAdapter, Classification, CreditAsset, CurlTransport, DiscoveryError,
    DiscoverySource, OperationSpec, Report as EngineReport, Snapshot, classify_transition,
    decode_account_id, evaluate,
};

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FORECAST_WARNING: i32 = 10;
pub const EXIT_INCONCLUSIVE: i32 = 20;
pub const EXIT_UNSUPPORTED: i32 = 30;
pub const EXIT_INVALID_INPUT: i32 = 40;
pub const EXIT_NETWORK: i32 = 50;
pub const EXIT_OUTPUT: i32 = 60;
pub const EXIT_INTERNAL: i32 = 70;

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 10_000;
const MAX_NETWORK_PASSPHRASE_BYTES: usize = 256;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

#[cfg(test)]
static TEST_INSTALL_BARRIER: OnceLock<Mutex<Option<Arc<Barrier>>>> = OnceLock::new();

#[cfg(test)]
fn test_install_barrier_slot() -> &'static Mutex<Option<Arc<Barrier>>> {
    TEST_INSTALL_BARRIER.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn set_test_install_barrier(barrier: Option<Arc<Barrier>>) {
    *test_install_barrier_slot().lock().unwrap() = barrier;
}

#[cfg(test)]
fn wait_for_test_install_barrier() {
    let barrier = test_install_barrier_slot().lock().unwrap().clone();
    if let Some(barrier) = barrier {
        barrier.wait();
    }
}

#[cfg(not(test))]
fn wait_for_test_install_barrier() {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
struct OutputOptions {
    format: OutputFormat,
    output: Option<PathBuf>,
    force: bool,
}

#[derive(Debug)]
struct CliError {
    code: i32,
    message: String,
}

impl CliError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_INVALID_INPUT,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_INTERNAL,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_UNSUPPORTED,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
struct Options {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

impl Options {
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

#[derive(Debug)]
struct AnalyzeRequest {
    snapshot_path: PathBuf,
    operation: OperationSpec,
    output: OutputOptions,
}

#[derive(Debug)]
struct LiveRequest {
    operation: OperationSpec,
    network_passphrase: String,
    horizon_url: String,
    rpc_url: String,
    timeout_secs: u32,
    output: OutputOptions,
}

#[derive(Debug)]
struct InspectRequest {
    report_path: PathBuf,
    output: OutputOptions,
}

#[derive(Debug)]
struct LoadedSnapshot {
    snapshot: Snapshot,
    artifact_error: Option<String>,
}

/// Runs the CLI and returns the documented process exit code.
pub fn run<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let args = args
        .into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| CliError::invalid("arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>();
    let args = match args {
        Ok(args) => args,
        Err(error) => return report_cli_error(error),
    };

    match dispatch(&args) {
        Ok(code) => code,
        Err(error) => report_cli_error(error),
    }
}

fn dispatch(args: &[String]) -> Result<i32, CliError> {
    let command = args.get(1).map(String::as_str).unwrap_or("help");
    match command {
        "help" => {
            if args.len() > 3 {
                return Err(CliError::invalid("help accepts at most one command name"));
            }
            let topic = args.get(2).map(String::as_str);
            print_help(topic);
            Ok(EXIT_SUCCESS)
        }
        "--help" | "-h" => {
            if args.len() != 2 {
                return Err(CliError::invalid(
                    "--help does not accept additional arguments",
                ));
            }
            print_help(None);
            Ok(EXIT_SUCCESS)
        }
        "version" | "--version" | "-V" => {
            if args.len() != 2 {
                return Err(CliError::invalid(
                    "version does not accept additional arguments",
                ));
            }
            println!("{} {}", crate::report::TOOL_NAME, env!("CARGO_PKG_VERSION"));
            Ok(EXIT_SUCCESS)
        }
        "analyze" => {
            if contains_help(&args[2..]) {
                print_help(Some("analyze"));
                return Ok(EXIT_SUCCESS);
            }
            execute_analyze(parse_analyze(&args[2..])?)
        }
        "live" => {
            if contains_help(&args[2..]) {
                print_help(Some("live"));
                return Ok(EXIT_SUCCESS);
            }
            execute_live(parse_live(&args[2..])?)
        }
        "inspect" => {
            if contains_help(&args[2..]) {
                print_help(Some("inspect"));
                return Ok(EXIT_SUCCESS);
            }
            execute_inspect(parse_inspect(&args[2..])?)
        }
        other => Err(CliError::invalid(format!(
            "unknown command '{}'; use 'revoketrace help' for usage",
            other
        ))),
    }
}

fn contains_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn parse_analyze(args: &[String]) -> Result<AnalyzeRequest, CliError> {
    let options = parse_options(
        args,
        &[
            "snapshot",
            "operation",
            "source-account",
            "source",
            "trustor",
            "asset-code",
            "code",
            "asset-issuer",
            "issuer",
            "before-flags",
            "after-flags",
            "tx-source-account",
            "tx-source",
            "sequence",
            "operation-index",
            "format",
            "output",
        ],
        &["force"],
    )?;
    let snapshot_path = PathBuf::from(required(&options, "snapshot")?);
    let operation = parse_operation(&options)?;
    let output = parse_output(&options)?;
    Ok(AnalyzeRequest {
        snapshot_path,
        operation,
        output,
    })
}

fn parse_live(args: &[String]) -> Result<LiveRequest, CliError> {
    let options = parse_options(
        args,
        &[
            "operation",
            "source-account",
            "source",
            "trustor",
            "asset-code",
            "code",
            "asset-issuer",
            "issuer",
            "before-flags",
            "after-flags",
            "tx-source-account",
            "tx-source",
            "sequence",
            "operation-index",
            "network-passphrase",
            "horizon-url",
            "rpc-url",
            "timeout-secs",
            "format",
            "output",
        ],
        &["force"],
    )?;
    let operation = parse_operation(&options)?;
    let network_passphrase = required(&options, "network-passphrase")?.to_owned();
    validate_network_passphrase(&network_passphrase)?;
    if network_passphrase != TESTNET_PASSPHRASE {
        return Err(CliError::invalid(
            "live mode currently supports only the Stellar Testnet network passphrase",
        ));
    }
    let horizon_url = required(&options, "horizon-url")?.to_owned();
    let rpc_url = required(&options, "rpc-url")?.to_owned();
    validate_endpoint("Horizon", &horizon_url)?;
    validate_endpoint("RPC", &rpc_url)?;
    let timeout_secs = options
        .value("timeout-secs")
        .map(|value| parse_u32("timeout-secs", value))
        .transpose()?
        .unwrap_or(15);
    if timeout_secs == 0 || timeout_secs > 300 {
        return Err(CliError::invalid(
            "timeout-secs must be between 1 and 300 seconds",
        ));
    }
    Ok(LiveRequest {
        operation,
        network_passphrase,
        horizon_url,
        rpc_url,
        timeout_secs,
        output: parse_output(&options)?,
    })
}

fn parse_inspect(args: &[String]) -> Result<InspectRequest, CliError> {
    let options = parse_options(args, &["report", "format", "output"], &["force"])?;
    Ok(InspectRequest {
        report_path: PathBuf::from(required(&options, "report")?),
        output: parse_output(&options)?,
    })
}

fn parse_options(
    args: &[String],
    value_names: &[&str],
    flag_names: &[&str],
) -> Result<Options, CliError> {
    let values = value_names.iter().copied().collect::<BTreeSet<_>>();
    let flags = flag_names.iter().copied().collect::<BTreeSet<_>>();
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if !token.starts_with("--") {
            return Err(CliError::invalid(format!(
                "unexpected positional argument '{}'",
                token
            )));
        }
        let raw = &token[2..];
        let (name, inline_value) = match raw.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (raw, None),
        };
        if values.contains(name) {
            if options.values.contains_key(name) {
                return Err(CliError::invalid(format!(
                    "option '--{}' was supplied more than once",
                    name
                )));
            }
            let value = match inline_value {
                Some(value) if !value.is_empty() => value.to_owned(),
                Some(_) => {
                    return Err(CliError::invalid(format!(
                        "option '--{}' cannot be empty",
                        name
                    )));
                }
                None => {
                    let next = args.get(index + 1).ok_or_else(|| {
                        CliError::invalid(format!("option '--{}' requires a value", name))
                    })?;
                    if next.starts_with('-') && next != "-" {
                        return Err(CliError::invalid(format!(
                            "option '--{}' requires a value",
                            name
                        )));
                    }
                    index += 1;
                    next.clone()
                }
            };
            options.values.insert(name.to_owned(), value);
        } else if flags.contains(name) {
            if inline_value.is_some() || !options.flags.insert(name.to_owned()) {
                return Err(CliError::invalid(format!(
                    "flag '--{}' was supplied more than once or has a value",
                    name
                )));
            }
        } else {
            return Err(CliError::invalid(format!("unknown option '--{}'", name)));
        }
        index += 1;
    }
    Ok(options)
}

fn required<'a>(options: &'a Options, name: &str) -> Result<&'a str, CliError> {
    options
        .value(name)
        .ok_or_else(|| CliError::invalid(format!("missing required option '--{}'", name)))
}

fn alias<'a>(
    options: &'a Options,
    canonical: &str,
    alternate: &str,
) -> Result<Option<&'a str>, CliError> {
    match (options.value(canonical), options.value(alternate)) {
        (Some(_), Some(_)) => Err(CliError::invalid(format!(
            "use only one of '--{}' and '--{}'",
            canonical, alternate
        ))),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn required_alias<'a>(
    options: &'a Options,
    canonical: &str,
    alternate: &str,
) -> Result<&'a str, CliError> {
    alias(options, canonical, alternate)?.ok_or_else(|| {
        CliError::invalid(format!(
            "missing required option '--{}' (alias '--{}')",
            canonical, alternate
        ))
    })
}

fn parse_output(options: &Options) -> Result<OutputOptions, CliError> {
    let format = match options.value("format").unwrap_or("text") {
        "text" => OutputFormat::Text,
        "json" => OutputFormat::Json,
        other => {
            return Err(CliError::invalid(format!(
                "format must be 'text' or 'json', not '{}'",
                other
            )));
        }
    };
    let output = options.value("output").map(PathBuf::from);
    if options.flag("force") && output.is_none() {
        return Err(CliError::invalid("--force requires --output"));
    }
    if let Some(path) = &output {
        validate_output_path(path)?;
    }
    Ok(OutputOptions {
        format,
        output,
        force: options.flag("force"),
    })
}

fn parse_operation(options: &Options) -> Result<OperationSpec, CliError> {
    let operation = required(options, "operation")?.to_owned();
    if operation != "SetTrustLineFlags" && operation != "AllowTrust" {
        return Err(CliError::unsupported(format!(
            "unsupported operation '{}'; use SetTrustLineFlags or AllowTrust",
            operation
        )));
    }

    let source_account = required_alias(options, "source-account", "source")?;
    let trustor = required(options, "trustor")?;
    let asset_code = required_alias(options, "asset-code", "code")?;
    let asset_issuer = required_alias(options, "asset-issuer", "issuer")?;
    validate_account("source-account", source_account)?;
    validate_account("trustor", trustor)?;
    validate_account("asset-issuer", asset_issuer)?;
    if source_account == trustor {
        return Err(CliError::invalid("source-account and trustor must differ"));
    }
    if source_account != asset_issuer {
        return Err(CliError::invalid(
            "source-account must equal asset-issuer for issuer authorization changes",
        ));
    }
    validate_asset_code(asset_code)?;

    let before_flags = parse_u32("before-flags", required(options, "before-flags")?)?;
    let after_flags = parse_u32("after-flags", required(options, "after-flags")?)?;
    validate_flags("before-flags", before_flags)?;
    validate_flags("after-flags", after_flags)?;

    let tx_source = alias(options, "tx-source-account", "tx-source")?;
    let sequence = options.value("sequence");
    let operation_index = options.value("operation-index");
    if tx_source.is_some() != sequence.is_some() || sequence.is_some() != operation_index.is_some()
    {
        return Err(CliError::invalid(
            "tx-source-account, sequence, and operation-index must be supplied together",
        ));
    }
    let tx_source_account = tx_source
        .map(|value| validate_account("tx-source-account", value).map(|_| value.to_owned()))
        .transpose()?;
    let sequence = sequence
        .map(|value| parse_u64("sequence", value))
        .transpose()?
        .map(|value| {
            if value == 0 || value > i64::MAX as u64 {
                Err(CliError::invalid("sequence must be between 1 and i64::MAX"))
            } else {
                Ok(value)
            }
        })
        .transpose()?;
    let operation_index = operation_index
        .map(|value| parse_u32("operation-index", value))
        .transpose()?;

    Ok(OperationSpec {
        operation,
        source_account: source_account.to_owned(),
        tx_source_account,
        trustor: trustor.to_owned(),
        sequence,
        operation_index,
        asset: CreditAsset {
            code: asset_code.to_owned(),
            issuer: asset_issuer.to_owned(),
        },
        before_flags,
        after_flags,
    })
}

fn parse_u32(name: &str, value: &str) -> Result<u32, CliError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::invalid(format!(
            "{} must be an unsigned decimal integer",
            name
        )));
    }
    value
        .parse::<u32>()
        .map_err(|_| CliError::invalid(format!("{} is outside the u32 range", name)))
}

fn parse_u64(name: &str, value: &str) -> Result<u64, CliError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::invalid(format!(
            "{} must be an unsigned decimal integer",
            name
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| CliError::invalid(format!("{} is outside the u64 range", name)))
}

fn validate_flags(name: &str, flags: u32) -> Result<(), CliError> {
    if flags & !0b111 != 0 {
        return Err(CliError::invalid(format!(
            "{} contains unknown trustline flag bits",
            name
        )));
    }
    if flags & 0b011 == 0b011 {
        return Err(CliError::invalid(format!(
            "{} contains conflicting authorization bits",
            name
        )));
    }
    Ok(())
}

fn validate_account(label: &str, value: &str) -> Result<(), CliError> {
    decode_account_id(value).map_err(|error| {
        CliError::invalid(format!(
            "{} is not a valid Stellar account StrKey: {}",
            label, error
        ))
    })?;
    Ok(())
}

fn validate_asset_code(code: &str) -> Result<(), CliError> {
    if code.is_empty() || code.len() > 12 || !code.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(CliError::invalid(
            "asset code must contain 1 to 12 ASCII letters or digits",
        ));
    }
    if code.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(CliError::invalid(
            "asset code must use uppercase ASCII letters",
        ));
    }
    Ok(())
}

fn validate_network_passphrase(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.len() > MAX_NETWORK_PASSPHRASE_BYTES {
        return Err(CliError::invalid(
            "network passphrase must be non-empty and at most 256 bytes",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(CliError::invalid(
            "network passphrase cannot contain control characters",
        ));
    }
    Ok(())
}

fn validate_endpoint(label: &str, value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
        return Err(CliError::invalid(format!(
            "{} endpoint must be non-empty and at most {} bytes",
            label, MAX_ENDPOINT_BYTES
        )));
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CliError::invalid(format!(
            "{} endpoint contains whitespace or control characters",
            label
        )));
    }
    if value.contains('@') || value.contains('%') {
        return Err(CliError::invalid(format!(
            "{} endpoint cannot contain credentials or encoded components",
            label
        )));
    }
    let (rest, cleartext) = if let Some(rest) = value.strip_prefix("https://") {
        (rest, false)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (rest, true)
    } else {
        return Err(CliError::invalid(format!(
            "{} endpoint must use https://",
            label
        )));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || authority.contains('%') {
        return Err(CliError::invalid(format!(
            "{} endpoint must contain a host and no credentials or encoded authority",
            label
        )));
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(CliError::invalid(format!(
            "{} endpoint cannot contain query strings or fragments",
            label
        )));
    }
    let host = if authority.starts_with('[') {
        let close = authority.find(']').ok_or_else(|| {
            CliError::invalid(format!("{} endpoint has an invalid IPv6 host", label))
        })?;
        let suffix = &authority[close + 1..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').ok_or_else(|| {
                CliError::invalid(format!("{} endpoint has an invalid port", label))
            })?;
            validate_port(label, port)?;
        }
        &authority[1..close]
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or_default();
        if let Some(port) = parts.next() {
            validate_port(label, port)?;
        }
        if parts.next().is_some() {
            return Err(CliError::invalid(format!(
                "{} endpoint must bracket IPv6 addresses",
                label
            )));
        }
        host
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b".-_:".contains(&byte)))
    {
        return Err(CliError::invalid(format!(
            "{} endpoint has an invalid host",
            label
        )));
    }
    // TLS is the only protection for RPC and Horizon responses, so cleartext
    // HTTP is limited to a local endpoint such as a loopback proxy.
    if cleartext && !is_loopback_host(host) {
        return Err(CliError::invalid(format!(
            "{} endpoint must use https:// unless it targets a loopback host",
            label
        )));
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    crate::discovery::is_loopback_host(host)
}

fn validate_port(label: &str, port: &str) -> Result<(), CliError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::invalid(format!(
            "{} endpoint has an invalid port",
            label
        )));
    }
    let port = port.parse::<u32>().map_err(|_| {
        CliError::invalid(format!(
            "{} endpoint port is outside the valid range",
            label
        ))
    })?;
    if port == 0 || port > u32::from(u16::MAX) {
        return Err(CliError::invalid(format!(
            "{} endpoint port is outside the valid range",
            label
        )));
    }
    Ok(())
}

fn validate_output_path(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty() {
        return Err(CliError::invalid("output path cannot be empty"));
    }
    if path.as_os_str() == "-" {
        return Ok(());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(CliError::invalid(
            "output paths containing '..' are rejected for safety",
        ));
    }
    if path.file_name().is_none() {
        return Err(CliError::invalid("output path must name a file"));
    }
    Ok(())
}

fn execute_analyze(request: AnalyzeRequest) -> Result<i32, CliError> {
    let loaded = load_snapshot(&request.snapshot_path)?;
    validate_snapshot_shape(&loaded.snapshot)?;

    let mut engine_report;
    let evidence_classification =
        match AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(&loaded.snapshot)
        {
            Ok(classification) => {
                engine_report = evaluate(&request.operation, &loaded.snapshot);
                classification
            }
            Err(error) => {
                engine_report = error_engine_report(&request.operation, &error);
                EvidenceClassification::InvalidOrContradictory
            }
        };
    if let Some(error) = loaded.artifact_error {
        engine_report.classification = Classification::Inconclusive;
        engine_report.errors.push(error);
    }
    let document = ReportDocument::from_engine(
        ReportMode::Offline,
        &request.operation,
        &loaded.snapshot,
        evidence_classification,
        &engine_report,
    )
    .map_err(CliError::internal)?;
    emit_document(&document, &request.output)?;
    Ok(exit_code_for_classification(
        document.forecast.classification,
    ))
}

fn execute_live(request: LiveRequest) -> Result<i32, CliError> {
    let adapter = AuthoritativeEvidenceAdapter::new(
        CurlTransport::new(request.timeout_secs),
        request.horizon_url,
        request.rpc_url,
        request.network_passphrase,
    );
    let snapshot =
        match adapter.acquire_live_evidence(&request.operation.trustor, &request.operation.asset) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!("error: live evidence acquisition failed: {}", error);
                return Ok(exit_code_for_discovery_error(&error));
            }
        };
    if let Err(error) = validate_snapshot_shape(&snapshot) {
        eprintln!(
            "error: live RPC returned an invalid snapshot: {}",
            error.message
        );
        return Ok(EXIT_NETWORK);
    }
    let evidence_classification =
        match AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(&snapshot) {
            Ok(classification) => classification,
            Err(error) => {
                eprintln!("error: live evidence failed strict validation: {}", error);
                return Ok(exit_code_for_discovery_error(&error));
            }
        };
    let engine_report = evaluate(&request.operation, &snapshot);
    let document = ReportDocument::from_engine(
        ReportMode::LiveTestnet,
        &request.operation,
        &snapshot,
        evidence_classification,
        &engine_report,
    )
    .map_err(CliError::internal)?;
    emit_document(&document, &request.output)?;
    Ok(exit_code_for_classification(
        document.forecast.classification,
    ))
}

fn execute_inspect(request: InspectRequest) -> Result<i32, CliError> {
    let bytes = read_bounded(&request.report_path, "report")?;
    let report: ReportDocument = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::invalid(format!("report JSON is invalid: {}", error)))?;
    report.validate_schema().map_err(CliError::invalid)?;
    emit_document(&report, &request.output)?;
    Ok(exit_code_for_classification(report.forecast.classification))
}

fn error_engine_report(operation: &OperationSpec, error: &DiscoveryError) -> EngineReport {
    let classification = error.into_classification();
    EngineReport {
        classification,
        transition: classify_transition(operation.before_flags, operation.after_flags),
        pool_redemptions: Vec::new(),
        account_deltas: Vec::new(),
        warnings: Vec::new(),
        errors: vec![error.to_string()],
    }
}

fn exit_code_for_classification(classification: ReportClassification) -> i32 {
    match classification {
        ReportClassification::SupportedBlocked => EXIT_SUCCESS,
        ReportClassification::UnverifiedForecast => EXIT_FORECAST_WARNING,
        ReportClassification::Inconclusive => EXIT_INCONCLUSIVE,
        ReportClassification::Unsupported => EXIT_UNSUPPORTED,
    }
}

fn exit_code_for_discovery_error(error: &DiscoveryError) -> i32 {
    match error {
        DiscoveryError::UnsupportedProtocolVersion { .. } => EXIT_UNSUPPORTED,
        DiscoveryError::TransportError(_) | DiscoveryError::ParseError(_) => EXIT_NETWORK,
        _ => EXIT_INCONCLUSIVE,
    }
}

fn load_snapshot(path: &Path) -> Result<LoadedSnapshot, CliError> {
    let bytes = read_bounded(path, "snapshot")?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::invalid(format!("snapshot JSON is invalid: {}", error)))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::invalid("snapshot JSON must contain an object"))?;
    if object.contains_key("snapshot") {
        let artifact: AuthoritativeCaptureArtifact =
            serde_json::from_value(value).map_err(|error| {
                CliError::invalid(format!(
                    "authoritative capture artifact is invalid: {}",
                    error
                ))
            })?;
        let mut artifact_error = None;
        if artifact.network_passphrase != artifact.snapshot.network_passphrase
            || artifact.ledger_sequence != artifact.snapshot.ledger_sequence
            || artifact.manifest_sha256 != artifact.snapshot.discovery.manifest_sha256
        {
            artifact_error =
                Some("capture artifact metadata contradicts its embedded snapshot".to_owned());
        }
        if artifact.evidence_classification == EvidenceClassification::CompleteAuthoritativeLedger {
            artifact_error = Some(
                "caller-supplied CompleteAuthoritativeLedger is not independently verifiable"
                    .to_owned(),
            );
        }
        Ok(LoadedSnapshot {
            snapshot: artifact.snapshot,
            artifact_error,
        })
    } else {
        let snapshot: Snapshot = serde_json::from_value(value)
            .map_err(|error| CliError::invalid(format!("snapshot format is invalid: {}", error)))?;
        Ok(LoadedSnapshot {
            snapshot,
            artifact_error: None,
        })
    }
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, CliError> {
    let mut reader: Box<dyn Read> = if path.as_os_str() == "-" {
        Box::new(io::stdin())
    } else {
        let metadata = fs::metadata(path).map_err(|error| {
            CliError::invalid(format!(
                "cannot read {} '{}': {}",
                label,
                path.display(),
                error
            ))
        })?;
        if !metadata.is_file() {
            return Err(CliError::invalid(format!(
                "{} path '{}' is not a regular file",
                label,
                path.display()
            )));
        }
        if metadata.len() > MAX_INPUT_BYTES {
            return Err(CliError::invalid(format!(
                "{} file '{}' exceeds the {}-byte limit",
                label,
                path.display(),
                MAX_INPUT_BYTES
            )));
        }
        Box::new(File::open(path).map_err(|error| {
            CliError::invalid(format!(
                "cannot open {} '{}': {}",
                label,
                path.display(),
                error
            ))
        })?)
    };
    let mut bytes = Vec::with_capacity(4096);
    reader
        .by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::invalid(format!("cannot read {}: {}", label, error)))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(CliError::invalid(format!(
            "{} exceeds the {}-byte limit",
            label, MAX_INPUT_BYTES
        )));
    }
    Ok(bytes)
}

fn validate_snapshot_shape(snapshot: &Snapshot) -> Result<(), CliError> {
    validate_network_passphrase(&snapshot.network_passphrase)?;
    if snapshot.ledger_sequence == 0 {
        return Err(CliError::invalid(
            "snapshot ledger sequence must be greater than zero",
        ));
    }
    if snapshot.entries_ledger_sequence == 0 || snapshot.discovery.target_ledger_sequence == 0 {
        return Err(CliError::invalid(
            "snapshot entry and discovery ledger sequences must be greater than zero",
        ));
    }
    if snapshot.discovery.manifest_sha256.len() != 64
        || hex::decode(&snapshot.discovery.manifest_sha256).is_err()
    {
        return Err(CliError::invalid(
            "snapshot discovery manifest_sha256 must be a 64-character hexadecimal digest",
        ));
    }
    check_collection("accounts", snapshot.accounts.len())?;
    check_collection("trustlines", snapshot.trustlines.len())?;
    check_collection(
        "pool_share_trustlines",
        snapshot.pool_share_trustlines.len(),
    )?;
    check_collection("sponsorship_handoffs", snapshot.sponsorship_handoffs.len())?;
    validate_source(&snapshot.discovery.source)?;
    for account in &snapshot.accounts {
        validate_account("snapshot account id", &account.id)?;
    }
    for trustline in &snapshot.trustlines {
        validate_account("snapshot trustline owner", &trustline.owner)?;
        validate_asset_identity(&trustline.asset.code, &trustline.asset.issuer, false)?;
        if let Some(sponsor) = &trustline.sponsor {
            validate_account("snapshot trustline sponsor", sponsor)?;
        }
    }
    for pool in &snapshot.pool_share_trustlines {
        if pool.pool_id.len() != 64
            || pool.pool_id != pool.pool_id.to_ascii_lowercase()
            || hex::decode(&pool.pool_id).is_err()
        {
            return Err(CliError::invalid(format!(
                "snapshot pool ID '{}' must be 64 lowercase hexadecimal characters",
                pool.pool_id
            )));
        }
        validate_account("snapshot pool owner", &pool.owner)?;
        validate_asset_identity(&pool.asset_a, &pool.asset_a_issuer, true)?;
        validate_asset_identity(&pool.asset_b, &pool.asset_b_issuer, true)?;
        if let Some(sponsor) = &pool.sponsor {
            validate_account("snapshot pool sponsor", sponsor)?;
        }
    }
    for handoff in &snapshot.sponsorship_handoffs {
        validate_account(
            "sponsorship handoff sponsored account",
            &handoff.sponsored_account,
        )?;
        validate_account(
            "sponsorship handoff replacement sponsor",
            &handoff.replacement_sponsor,
        )?;
    }
    for pool_id in &snapshot.discovery.pool_ids {
        if pool_id.len() != 64
            || pool_id != &pool_id.to_ascii_lowercase()
            || hex::decode(pool_id).is_err()
        {
            return Err(CliError::invalid(format!(
                "snapshot discovery pool ID '{}' is not canonical lowercase hexadecimal",
                pool_id
            )));
        }
    }
    Ok(())
}

fn validate_source(source: &DiscoverySource) -> Result<(), CliError> {
    match source {
        DiscoverySource::SyntheticFixture => Ok(()),
        DiscoverySource::LedgerCapture { endpoint } => validate_endpoint("capture", endpoint),
        DiscoverySource::TwoTierDiscovery {
            horizon_endpoint,
            rpc_endpoint,
        } => {
            validate_endpoint("Horizon", horizon_endpoint)?;
            validate_endpoint("RPC", rpc_endpoint)
        }
        DiscoverySource::AuthoritativeExport { export_id } => {
            if export_id.is_empty()
                || export_id.len() > 256
                || export_id.chars().any(char::is_control)
            {
                return Err(CliError::invalid(
                    "authoritative export ID must be printable and at most 256 bytes",
                ));
            }
            Ok(())
        }
    }
}

fn validate_asset_identity(code: &str, issuer: &str, allow_native: bool) -> Result<(), CliError> {
    if allow_native && (issuer == "native" || issuer.is_empty()) {
        if code != "XLM" {
            return Err(CliError::invalid(
                "native pool constituents must use the XLM asset code",
            ));
        }
        return Ok(());
    }
    validate_asset_code(code)?;
    validate_account("asset issuer", issuer)
}

fn check_collection(label: &str, length: usize) -> Result<(), CliError> {
    if length > MAX_COLLECTION_ITEMS {
        return Err(CliError::invalid(format!(
            "snapshot {} contains {} entries, exceeding the {}-entry limit",
            label, length, MAX_COLLECTION_ITEMS
        )));
    }
    Ok(())
}

fn emit_document(report: &ReportDocument, output: &OutputOptions) -> Result<(), CliError> {
    let bytes = match output.format {
        OutputFormat::Text => render_human(report).into_bytes(),
        OutputFormat::Json => report.json_bytes().map_err(|error| {
            CliError::internal(format!("cannot serialize JSON report: {}", error))
        })?,
    };
    if let Some(path) = &output.output {
        if path.as_os_str() == "-" {
            io::stdout().write_all(&bytes).map_err(|error| CliError {
                code: EXIT_OUTPUT,
                message: format!("cannot write report to stdout: {}", error),
            })?;
        } else {
            write_atomic(path, &bytes, output.force)?;
            eprintln!("report written to {}", path.display());
        }
    } else {
        io::stdout().write_all(&bytes).map_err(|error| CliError {
            code: EXIT_OUTPUT,
            message: format!("cannot write report to stdout: {}", error),
        })?;
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    validate_output_path(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| CliError {
        code: EXIT_OUTPUT,
        message: format!(
            "cannot access output directory '{}': {}",
            parent.display(),
            error
        ),
    })?;
    if parent_metadata.file_type().is_symlink() {
        return Err(CliError {
            code: EXIT_OUTPUT,
            message: "refusing to write through a symbolic-link output directory".to_owned(),
        });
    }
    let parent = fs::canonicalize(parent).map_err(|error| CliError {
        code: EXIT_OUTPUT,
        message: format!(
            "cannot resolve output directory '{}': {}",
            parent.display(),
            error
        ),
    })?;
    let metadata = fs::symlink_metadata(&parent).map_err(|error| CliError {
        code: EXIT_OUTPUT,
        message: format!(
            "cannot access resolved output directory '{}': {}",
            parent.display(),
            error
        ),
    })?;
    if !metadata.is_dir() {
        return Err(CliError {
            code: EXIT_OUTPUT,
            message: format!("output parent '{}' is not a directory", parent.display()),
        });
    }
    let install_path = parent.join(path.file_name().expect("validated output filename"));
    match fs::symlink_metadata(&install_path) {
        Ok(existing) => {
            if existing.file_type().is_symlink() {
                return Err(CliError {
                    code: EXIT_OUTPUT,
                    message: "refusing to overwrite a symbolic-link output path".to_owned(),
                });
            }
            if !force {
                return Err(CliError {
                    code: EXIT_OUTPUT,
                    message: format!(
                        "refusing to overwrite existing file '{}'; pass --force to replace it",
                        path.display()
                    ),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError {
                code: EXIT_OUTPUT,
                message: format!(
                    "cannot inspect output destination '{}': {}",
                    path.display(),
                    error
                ),
            });
        }
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CliError {
            code: EXIT_OUTPUT,
            message: "output filename must be valid UTF-8".to_owned(),
        })?;
    let pid = std::process::id();
    for attempt in 0..8_u8 {
        let temp_path = parent.join(format!(
            ".{}.revoketrace-{}-{}.tmp",
            file_name, pid, attempt
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CliError {
                    code: EXIT_OUTPUT,
                    message: format!("cannot create temporary report file: {}", error),
                });
            }
        };
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            return Err(output_install_error(
                &temp_path,
                format!("cannot complete temporary report write: {}", error),
            ));
        }
        drop(file);
        wait_for_test_install_barrier();
        if force {
            match fs::symlink_metadata(&install_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(output_install_error(
                        &temp_path,
                        "refusing to overwrite a symbolic-link output path".to_owned(),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(output_install_error(
                        &temp_path,
                        format!(
                            "cannot inspect output destination '{}': {}",
                            path.display(),
                            error
                        ),
                    ));
                }
            }
            if let Err(error) = fs::rename(&temp_path, &install_path) {
                return Err(output_install_error(
                    &temp_path,
                    format!(
                        "cannot atomically replace report '{}': {}",
                        path.display(),
                        error
                    ),
                ));
            }
        } else {
            // `hard_link` creates the destination directory entry without
            // replacing an existing entry. This is the final security
            // decision for --force=false; the earlier existence check is only
            // for a clearer fast-path error.
            if let Err(error) = fs::hard_link(&temp_path, &install_path) {
                return Err(output_install_error(
                    &temp_path,
                    format!(
                        "cannot install report '{}' without replacing an existing destination: {}",
                        path.display(),
                        error
                    ),
                ));
            }
            if let Err(error) = fs::remove_file(&temp_path) {
                return Err(CliError {
                    code: EXIT_OUTPUT,
                    message: format!(
                        "report '{}' was installed but its temporary file could not be removed: {}",
                        path.display(),
                        error
                    ),
                });
            }
        }
        return Ok(());
    }
    Err(CliError {
        code: EXIT_OUTPUT,
        message: "could not allocate a unique temporary report path".to_owned(),
    })
}

fn output_install_error(temp_path: &Path, message: String) -> CliError {
    match fs::remove_file(temp_path) {
        Ok(()) => CliError {
            code: EXIT_OUTPUT,
            message,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CliError {
            code: EXIT_OUTPUT,
            message,
        },
        Err(error) => CliError {
            code: EXIT_OUTPUT,
            message: format!("{}; temporary file cleanup failed: {}", message, error),
        },
    }
}

fn report_cli_error(error: CliError) -> i32 {
    eprintln!("error: {}", error.message);
    error.code
}

fn print_help(topic: Option<&str>) {
    match topic {
        Some("analyze") => println!(
            "RevokeTrace offline analysis\n\n\
Usage:\n  revoketrace analyze --snapshot PATH --operation OP --source-account ISSUER --trustor ACCOUNT \\\n    --asset-code CODE --asset-issuer ISSUER --before-flags N --after-flags N [OPTIONS]\n\n\
The snapshot is read locally and no network request is made. Use --format json to emit the\nversioned report schema. Operation context (tx source, sequence, operation index) is optional\nbut must be supplied as a complete set."
        ),
        Some("live") => println!(
            "RevokeTrace bounded Stellar Testnet analysis\n\n\
Usage:\n  revoketrace live --network-passphrase 'Test SDF Network ; September 2015' \\\n    --horizon-url URL --rpc-url URL --operation OP --source-account ISSUER \\\n    --trustor ACCOUNT --asset-code CODE --asset-issuer ISSUER \\\n    --before-flags N --after-flags N [OPTIONS]\n\n\
Live mode uses the existing bounded Horizon candidate enumeration and one-batch RPC evidence\nadapter. It does not prove complete ledger coverage or provide transaction signing/broadcasting."
        ),
        Some("inspect") => println!(
            "Inspect a RevokeTrace JSON report\n\nUsage:\n  revoketrace inspect --report PATH [--format text|json] [--output PATH] [--force]"
        ),
        Some(other) => println!("unknown help topic '{}'; use 'revoketrace help'", other),
        None => println!(
            "RevokeTrace {}\n\n\
Read-only Stellar Classic authorization-revocation forecasts.\n\n\
Commands:\n  analyze   Evaluate a validated local JSON snapshot (offline)\n  live      Acquire bounded Stellar Testnet evidence and evaluate it\n  inspect   Inspect classifications, warnings, and evidence limitations in a JSON report\n  version   Display the CLI version\n  help      Display command help\n\n\
Common options:\n  --format text|json       Human output (default) or stable JSON report\n  --output PATH            Write without overwriting an existing file\n  --force                  Explicitly permit replacement of an existing output file\n\n\
Exit codes:\n  0  command completed (including a modeled blocked result; never transaction approval)\n  10 valid but unverified forecast containing warnings\n  20 inconclusive or contradictory evidence\n  30 unsupported operation or protocol\n  40 invalid CLI input or input file\n  50 live network/RPC failure\n  60 report output failure\n  70 internal error\n\n\
Security boundary: the CLI is read-only, never signs or broadcasts, rejects bounded input/path\nviolations, and does not expose caller credentials in reports. UNVERIFIED_FORECAST is not a\nsuccessful transaction preflight.\n\nUse 'revoketrace help analyze', 'revoketrace help live', or 'revoketrace help inspect' for details.",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ACCOUNT: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
    static OUTPUT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn output_test_lock() -> std::sync::MutexGuard<'static, ()> {
        OUTPUT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap()
    }

    fn test_output_dir(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "revoketrace-cli-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ));
        fs::create_dir(&path).expect("unique test output directory");
        path
    }

    fn assert_no_temporary_reports(dir: &Path) {
        let leftovers = fs::read_dir(dir)
            .expect("read test output directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".revoketrace-")
            })
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "temporary report files remain: {:?}",
            leftovers
        );
    }

    struct InstallBarrierReset;

    impl Drop for InstallBarrierReset {
        fn drop(&mut self) {
            set_test_install_barrier(None);
        }
    }

    #[test]
    fn rejects_malformed_strkeys_and_asset_codes() {
        assert!(validate_account("account", "not-a-strkey").is_err());
        assert!(validate_asset_code("bad-code").is_err());
        assert!(validate_asset_code("lower").is_err());
        assert!(validate_account("account", VALID_ACCOUNT).is_ok());
    }

    #[test]
    fn rejects_unsafe_output_paths() {
        assert!(validate_output_path(Path::new("../report.json")).is_err());
        assert!(validate_output_path(Path::new("report.json")).is_ok());
        assert!(validate_output_path(Path::new("-")).is_ok());
    }

    #[test]
    fn parses_decimal_sequences_without_signs() {
        assert!(parse_u64("sequence", "0").is_ok());
        assert!(parse_u64("sequence", "-1").is_err());
        assert!(parse_u32("operation-index", "4294967296").is_err());
    }

    #[test]
    fn validates_endpoint_credentials_and_queries() {
        assert!(validate_endpoint("RPC", "https://example.test/rpc").is_ok());
        assert!(validate_endpoint("RPC", "https://user:secret@example.test").is_err());
        assert!(validate_endpoint("RPC", "https://example.test?token=secret").is_err());
    }

    #[test]
    fn cleartext_http_endpoints_are_limited_to_loopback_hosts() {
        for accepted in [
            "https://horizon-testnet.stellar.org",
            "https://example.test:8443/rpc",
            "http://localhost:8000",
            "http://LOCALHOST/rpc",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            assert!(
                validate_endpoint("RPC", accepted).is_ok(),
                "should accept {}",
                accepted
            );
        }
        for rejected in [
            "http://example.test",
            "http://horizon-testnet.stellar.org",
            "http://127.0.0.1.example.test",
            "http://localhost.example.test",
            "http://10.0.0.5:8000",
            "ftp://example.test",
            "example.test",
        ] {
            assert!(
                validate_endpoint("RPC", rejected).is_err(),
                "should reject {}",
                rejected
            );
        }
        let message = validate_endpoint("RPC", "http://example.test")
            .unwrap_err()
            .message;
        assert!(message.contains("https://"), "{}", message);
    }

    #[test]
    fn output_format_is_strict() {
        let mut options = Options::default();
        options
            .values
            .insert("format".to_owned(), "yaml".to_owned());
        assert!(parse_output(&options).is_err());
    }

    fn fixture_report() -> ReportDocument {
        let snapshot: Snapshot =
            serde_json::from_slice(include_bytes!("../fixtures/live-testnet-discovery.json"))
                .expect("fixture snapshot");
        let operation = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: VALID_ACCOUNT.to_owned(),
            sequence: Some(42),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: 1,
            after_flags: 0,
        };
        let evidence =
            AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(&snapshot)
                .expect("fixture evidence classification");
        let engine = evaluate(&operation, &snapshot);
        ReportDocument::from_engine(
            ReportMode::Offline,
            &operation,
            &snapshot,
            evidence,
            &engine,
        )
        .expect("fixture report")
    }

    #[test]
    fn deterministic_fixture_reports_have_stable_json() {
        let first = fixture_report();
        let second = fixture_report();
        assert_eq!(first.json_bytes().unwrap(), second.json_bytes().unwrap());
        let json = String::from_utf8(first.json_bytes().unwrap()).unwrap();
        assert!(json.contains("UNVERIFIED_FORECAST"));
        assert!(!json.contains("SUPPORTED_SAFE"));

        let mut wrong_version = first.clone();
        wrong_version.schema_version += 1;
        assert!(wrong_version.validate_schema().is_err());
        let mut wrong_type = first.clone();
        wrong_type.report_type = "other.report".to_owned();
        assert!(wrong_type.validate_schema().is_err());
        let mut altered = first;
        altered.evidence.manifest_sha256 = "0".repeat(64);
        assert!(altered.validate_schema().is_ok());
    }

    #[test]
    fn inspect_preserves_saved_report_classification_without_authenticating_provenance() {
        let dir = test_output_dir("inspect-untrusted");
        let path = dir.join("report.json");
        let mut report = fixture_report();
        report.evidence.evidence_classification =
            crate::report::ReportEvidenceClassification::CompleteAuthoritativeLedger;
        fs::write(&path, report.json_bytes().expect("serialized report")).unwrap();

        let code = run([
            OsString::from("revoketrace"),
            OsString::from("inspect"),
            OsString::from("--report"),
            path.into_os_string(),
            OsString::from("--format"),
            OsString::from("json"),
        ]);

        assert_eq!(code, EXIT_FORECAST_WARNING);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn inspect_rejects_unsupported_report_schema() {
        let dir = test_output_dir("inspect-schema");
        let path = dir.join("report.json");
        let mut report = fixture_report();
        report.schema_version += 1;
        fs::write(&path, report.json_bytes().expect("serialized report")).unwrap();

        let code = run([
            OsString::from("revoketrace"),
            OsString::from("inspect"),
            OsString::from("--report"),
            path.into_os_string(),
        ]);

        assert_eq!(code, EXIT_INVALID_INPUT);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn contradictory_snapshot_evidence_maps_to_inconclusive() {
        let mut snapshot: Snapshot =
            serde_json::from_slice(include_bytes!("../fixtures/live-testnet-discovery.json"))
                .expect("fixture snapshot");
        snapshot.entries_ledger_sequence += 1;
        let error = AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(&snapshot)
            .expect_err("mixed ledger evidence must fail closed");
        let operation = OperationSpec::new(
            "SetTrustLineFlags",
            "issuer",
            "holder",
            CreditAsset {
                code: "USD".to_owned(),
                issuer: "issuer".to_owned(),
            },
            1,
            0,
        );
        assert_eq!(
            error_engine_report(&operation, &error).classification,
            Classification::Inconclusive
        );
    }

    #[test]
    fn bounded_input_reader_rejects_invalid_json_and_oversized_files() {
        let base = std::env::temp_dir().join(format!(
            "revoketrace-cli-test-{}-{}",
            std::process::id(),
            "input"
        ));
        fs::write(&base, b"not json").unwrap();
        assert!(load_snapshot(&base).is_err());
        fs::write(&base, vec![b'0'; MAX_INPUT_BYTES as usize + 1]).unwrap();
        assert!(read_bounded(&base, "snapshot").is_err());
        let _ = fs::remove_file(base);
    }

    #[test]
    fn atomic_output_refuses_overwrite_and_supports_explicit_force() {
        let _lock = output_test_lock();
        let dir = test_output_dir("overwrite");
        let path = dir.join("report.json");
        fs::write(&path, b"old").unwrap();
        let error = write_atomic(&path, b"new", false).expect_err("overwrite must be refused");
        assert_eq!(error.code, EXIT_OUTPUT);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        write_atomic(&path, b"new", true).expect("explicit force should replace atomically");
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_no_temporary_reports(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn successful_installation_writes_complete_content() {
        let _lock = output_test_lock();
        let dir = test_output_dir("complete");
        let path = dir.join("report.json");
        let content = b"complete deterministic report bytes\n";
        write_atomic(&path, content, false).expect("report installation");
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_no_temporary_reports(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_no_force_installation_never_overwrites_destination() {
        let _lock = output_test_lock();
        let dir = test_output_dir("race");
        let path = Arc::new(dir.join("report.json"));
        let barrier = Arc::new(Barrier::new(2));
        set_test_install_barrier(Some(barrier));
        let _reset = InstallBarrierReset;

        let (left, right) = std::thread::scope(|scope| {
            let left_path = Arc::clone(&path);
            let right_path = Arc::clone(&path);
            let left = scope.spawn(move || write_atomic(&left_path, b"left", false));
            let right = scope.spawn(move || write_atomic(&right_path, b"right", false));
            (
                left.join().expect("left installer thread"),
                right.join().expect("right installer thread"),
            )
        });

        let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
        assert_eq!(successes, 1, "exactly one no-replace installer must win");
        let failure = if left.is_err() { left } else { right };
        assert_eq!(
            failure.expect_err("one installer must fail").code,
            EXIT_OUTPUT
        );
        let installed = fs::read(&*path).unwrap();
        assert!(installed == b"left" || installed == b"right");
        assert_no_temporary_reports(&dir);
        drop(_reset);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_force_installation_preserves_destination_and_cleans_temp() {
        let _lock = output_test_lock();
        let dir = test_output_dir("failed");
        let path = dir.join("report.json");
        fs::create_dir(&path).unwrap();
        let error = write_atomic(&path, b"new", true).expect_err("directory cannot be replaced");
        assert_eq!(error.code, EXIT_OUTPUT);
        assert!(path.is_dir());
        assert_no_temporary_reports(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_destinations_are_rejected_without_following() {
        let _lock = output_test_lock();
        let dir = test_output_dir("symlink");
        let real = dir.join("real.json");
        let link = dir.join("report.json");
        fs::write(&real, b"keep").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = write_atomic(&link, b"replace", true).expect_err("symlink must be rejected");
        assert_eq!(error.code, EXIT_OUTPUT);
        assert_eq!(fs::read(&real).unwrap(), b"keep");
        assert_eq!(fs::read_link(&link).unwrap(), real);
        assert_no_temporary_reports(&dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exit_codes_keep_forecast_classification_separate_from_execution() {
        assert_eq!(
            exit_code_for_classification(ReportClassification::SupportedBlocked),
            0
        );
        assert_eq!(
            exit_code_for_classification(ReportClassification::UnverifiedForecast),
            10
        );
        assert_eq!(
            exit_code_for_classification(ReportClassification::Inconclusive),
            20
        );
        assert_eq!(
            exit_code_for_classification(ReportClassification::Unsupported),
            30
        );
    }
}
