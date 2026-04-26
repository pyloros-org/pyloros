#![no_main]
//! Fuzz the v2 fetch-response parser used by the force-push sidecar.
//!
//! `parse_fetch_response` consumes whatever the upstream returns over HTTP;
//! a misbehaving or malicious upstream must not be able to crash or hang
//! the proxy. The parser must always return one of the three
//! `AncestryCheck` variants for any byte input.

use libfuzzer_sys::fuzz_target;
use pyloros::filter::upstream_negotiate::parse_fetch_response;

fuzz_target!(|data: &[u8]| {
    let _ = parse_fetch_response(data);
});
