//! Fixture loader for the spec-derived conformance harness.
//!
//! Fixtures are ordinary SIP/SDP text with `#` comment lines at the top. Every
//! fixture cites the clause it is derived from; the comments are stripped before
//! parsing, so the bytes below the comments are real wire messages.

use std::path::PathBuf;

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name)
}

/// Load a fixture, dropping `#` comment lines and normalising to CRLF.
pub fn load(name: &str) -> String {
    let text = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"));
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let mut out = lines.join("\r\n");
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out
}

pub fn sip(name: &str) -> sip::Message {
    sip::Message::parse(&load(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

pub fn sdp(name: &str) -> ims::Sdp {
    ims::Sdp::parse(&load(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}
