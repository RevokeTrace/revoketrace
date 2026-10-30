//! Exercises the real `curl` transport against loopback HTTP servers: status
//! handling, redirects, request bodies, and the effect of a hostile curl
//! configuration file. Nothing leaves the machine.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use revoketrace_spike::discovery::{CurlTransport, DiscoveryError, HttpTransport};

/// What the test server saw and how it answers.
struct Reply {
    status: u16,
    location: Option<String>,
    body: String,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Reply {
            status: 200,
            location: None,
            body: body.to_owned(),
        }
    }
    fn status(status: u16, body: &str) -> Self {
        Reply {
            status,
            location: None,
            body: body.to_owned(),
        }
    }
    fn redirect(location: &str) -> Self {
        Reply {
            status: 302,
            location: Some(location.to_owned()),
            body: String::new(),
        }
    }
}

struct Server {
    port: u16,
    hits: Arc<AtomicUsize>,
    last_body: Arc<Mutex<String>>,
}

impl Server {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

fn serve(reply: impl Fn() -> Reply + Send + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let last_body = Arc::new(Mutex::new(String::new()));
    let (hits_thread, body_thread) = (hits.clone(), last_body.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            hits_thread.fetch_add(1, Ordering::SeqCst);
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
            *body_thread.lock().unwrap() =
                String::from_utf8_lossy(&request[header_end..]).into_owned();
            let reply = reply();
            let location = reply
                .location
                .map(|l| format!("Location: {}\r\n", l))
                .unwrap_or_default();
            let response = format!(
                "HTTP/1.1 {} X\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.status,
                location,
                reply.body.len(),
                reply.body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Server {
        port,
        hits,
        last_body,
    }
}

fn transport_error(result: Result<String, DiscoveryError>) -> String {
    match result {
        Err(DiscoveryError::TransportError(message)) => message,
        other => panic!("expected a transport error, got {:?}", other),
    }
}

#[test]
fn success_returns_the_body_without_the_status_line() {
    let server = serve(|| Reply::ok(r#"{"ok":true}"#));
    let transport = CurlTransport::new(10);
    assert_eq!(transport.get(&server.url()).unwrap(), r#"{"ok":true}"#);
    assert_eq!(
        transport.post(&server.url(), "{}").unwrap(),
        r#"{"ok":true}"#
    );
}

#[test]
fn post_body_is_sent_literally_even_when_it_starts_with_an_at_sign() {
    let server = serve(|| Reply::ok("{}"));
    let transport = CurlTransport::new(10);
    transport
        .post(&server.url(), "@/etc/passwd")
        .expect("post succeeds");
    assert_eq!(*server.last_body.lock().unwrap(), "@/etc/passwd");
}

#[test]
fn unsuccessful_statuses_are_errors_and_the_body_is_not_trusted() {
    for (status, expected) in [
        (404, "HTTP 404"),
        (429, "rate limited"),
        (500, "HTTP 500"),
        (503, "HTTP 503"),
    ] {
        // A body that would parse as a valid answer must not be used.
        let server = serve(move || Reply::status(status, r#"{"id":"SECRET-BODY","balances":[]}"#));
        let transport = CurlTransport::new(10);
        for message in [
            transport_error(transport.get(&server.url())),
            transport_error(transport.post(&server.url(), "{}")),
        ] {
            assert!(message.contains(expected), "{}: {}", status, message);
            assert!(!message.contains("SECRET-BODY"), "{}", message);
        }
    }
}

#[test]
fn redirects_are_not_followed() {
    let target = serve(|| Reply::ok(r#"{"id":"redirected"}"#));
    let target_url = target.url();
    let origin = serve(move || Reply::redirect(&target_url));
    let transport = CurlTransport::new(10);

    let message = transport_error(transport.get(&origin.url()));
    assert!(message.contains("HTTP 302"), "{}", message);
    assert!(
        message.contains("redirects are not followed"),
        "{}",
        message
    );
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}

struct Home(PathBuf);

impl Home {
    /// A home directory whose `.curlrc` would follow redirects and use a dead
    /// proxy, if curl read it.
    fn with_hostile_curlrc(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "revoketrace-curlrc-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join(".curlrc"),
            "location\nmax-redirs = 5\nproxy = \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        Home(dir)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const ISSUER: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
const TRUSTOR: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";

#[test]
fn a_hostile_curlrc_cannot_change_how_requests_are_made() {
    let home = Home::with_hostile_curlrc("redirect");
    let configured = |command: &mut Command| {
        command
            .env("HOME", &home.0)
            .env("CURL_HOME", &home.0)
            .env("XDG_CONFIG_HOME", &home.0)
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1");
    };

    // Control: plain curl does read the file. It follows the redirect (the
    // file sets `location`), so the target is reached. Without this the test
    // below could pass for the wrong reason.
    let target = serve(|| Reply::ok(r#"{"id":"redirected"}"#));
    let target_url = target.url();
    let origin = serve(move || Reply::redirect(&target_url));
    let mut control = Command::new("curl");
    configured(&mut control);
    let control_output = control
        .args(["-s", "--noproxy", "*", &origin.url()])
        .output()
        .expect("run curl");
    assert_eq!(
        String::from_utf8_lossy(&control_output.stdout),
        r#"{"id":"redirected"}"#,
        "the hostile .curlrc must take effect for plain curl"
    );
    assert_eq!(target.hits.load(Ordering::SeqCst), 1);

    // The product: the same environment, through the real binary.
    let target = serve(|| Reply::ok(r#"{"id":"redirected"}"#));
    let target_url = target.url();
    let origin = serve(move || Reply::redirect(&target_url));
    let mut live = Command::new(env!("CARGO_BIN_EXE_revoketrace"));
    configured(&mut live);
    let output = live
        .args([
            "live",
            "--network-passphrase",
            "Test SDF Network ; September 2015",
            "--horizon-url",
            &origin.url(),
            "--rpc-url",
            &origin.url(),
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
        .expect("run revoketrace");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(50), "{}", stderr);
    assert!(stderr.contains("HTTP 302"), "{}", stderr);
    assert_eq!(
        target.hits.load(Ordering::SeqCst),
        0,
        "the redirect target must never be contacted"
    );
}
