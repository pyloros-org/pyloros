//! Git-LFS batch-response inspection.
//!
//! After a successful `POST {repo}/info/lfs/objects/batch`, the response body
//! advertises per-object action URLs (download/upload/verify) which the client
//! will use next — typically on a different host (e.g. `lfs.github.com`,
//! `github-cloud.s3.amazonaws.com`). Those hosts are not predictable from
//! config, so we extract the URLs here and feed them into the dynamic whitelist
//! method-pinned and TTL-bounded. See `dynamic_whitelist::insert_lfs_action`.
//!
//! Reference: <https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md>

use hyper::http::Method;
use serde::Deserialize;
use std::time::{Duration, Instant};

/// Sane bounds on the per-action TTL we will trust from upstream. Some servers
/// emit very long expirations (hours/days) that would let stale URLs accumulate
/// in the whitelist; others omit it entirely. Clamp to [60s, 3600s] in that case.
const MIN_ACTION_TTL: Duration = Duration::from_secs(60);
const MAX_ACTION_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsActionKind {
    Download,
    Upload,
    Verify,
}

impl LfsActionKind {
    /// HTTP method the LFS client will use for this action, per the LFS batch spec.
    pub fn method(self) -> Method {
        match self {
            LfsActionKind::Download => Method::GET,
            LfsActionKind::Upload => Method::PUT,
            LfsActionKind::Verify => Method::POST,
        }
    }

    /// Whether this action kind is covered by the LFS operation `op`
    /// (matches the `lfs_operations` field on a compiled rule).
    /// `download` actions are part of the `download` operation; `upload` and
    /// `verify` are both part of the `upload` operation (verify is the post-upload
    /// callback that confirms the object reached the storage backend).
    pub fn covered_by(self, op: &str) -> bool {
        matches!(
            (self, op),
            (LfsActionKind::Download, "download")
                | (LfsActionKind::Upload, "upload")
                | (LfsActionKind::Verify, "upload")
        )
    }
}

#[derive(Debug, Clone)]
pub struct LfsAction {
    pub kind: LfsActionKind,
    pub url: String,
    /// Per-action expiration (already converted to a wall-clock instant and
    /// clamped to [`MIN_ACTION_TTL`, `MAX_ACTION_TTL`]). `None` means the
    /// caller should fall back to its default TTL.
    pub expires_at: Option<Instant>,
}

impl LfsAction {
    /// Method the client will use when hitting `url`.
    pub fn method(&self) -> Method {
        self.kind.method()
    }

    /// TTL until expiry from `now`, or `None` if no per-action expiration was
    /// provided (caller should use its default).
    pub fn ttl_from(&self, now: Instant) -> Option<Duration> {
        self.expires_at.map(|t| t.saturating_duration_since(now))
    }
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    objects: Vec<BatchObject>,
}

#[derive(Deserialize)]
struct BatchObject {
    #[serde(default)]
    actions: Option<BatchActions>,
}

#[derive(Deserialize)]
struct BatchActions {
    #[serde(default)]
    download: Option<BatchAction>,
    #[serde(default)]
    upload: Option<BatchAction>,
    #[serde(default)]
    verify: Option<BatchAction>,
}

#[derive(Deserialize)]
struct BatchAction {
    href: Option<String>,
    /// RFC 3339 timestamp.
    expires_at: Option<String>,
    /// Seconds until expiry, relative to receipt of the response.
    expires_in: Option<i64>,
}

/// Decompress `body` according to `content_encoding` (None / "identity" / "gzip" / "x-gzip" / "deflate").
/// Returns the original bytes (no copy) when no decoding is needed, an owned
/// `Vec<u8>` when it is, and `None` when the encoding is unsupported or the
/// body is malformed.
pub fn decode_body<'a>(
    body: &'a [u8],
    content_encoding: Option<&str>,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    use std::borrow::Cow;
    use std::io::Read;
    match content_encoding {
        None => Some(Cow::Borrowed(body)),
        Some(enc) if enc.is_empty() || enc.eq_ignore_ascii_case("identity") => {
            Some(Cow::Borrowed(body))
        }
        Some(enc) if enc.eq_ignore_ascii_case("gzip") || enc.eq_ignore_ascii_case("x-gzip") => {
            let mut decoder = flate2::read::GzDecoder::new(body);
            let mut buf = Vec::with_capacity(body.len() * 4);
            decoder.read_to_end(&mut buf).ok()?;
            Some(Cow::Owned(buf))
        }
        Some(enc) if enc.eq_ignore_ascii_case("deflate") => {
            let mut decoder = flate2::read::ZlibDecoder::new(body);
            let mut buf = Vec::with_capacity(body.len() * 4);
            decoder.read_to_end(&mut buf).ok()?;
            Some(Cow::Owned(buf))
        }
        Some(_) => None,
    }
}

/// Parse an LFS batch response body — possibly compressed with `Content-Encoding`
/// `gzip`/`deflate` — and extract advertised actions. Returns `None` on
/// unsupported encoding, decompression failure, or invalid JSON.
pub fn parse_lfs_batch_response_encoded(
    body: &[u8],
    content_encoding: Option<&str>,
) -> Option<Vec<LfsAction>> {
    let decoded = decode_body(body, content_encoding)?;
    parse_lfs_batch_response(&decoded)
}

/// Parse an LFS batch response body and extract advertised actions. Returns
/// `None` if the body is not valid JSON; returns `Some(empty)` if it parses
/// but has no actions to whitelist.
pub fn parse_lfs_batch_response(body: &[u8]) -> Option<Vec<LfsAction>> {
    let parsed: BatchResponse = serde_json::from_slice(body).ok()?;
    let now = Instant::now();
    let mut out = Vec::new();
    for obj in parsed.objects {
        let Some(actions) = obj.actions else { continue };
        if let Some(a) = actions.download {
            push_action(&mut out, LfsActionKind::Download, a, now);
        }
        if let Some(a) = actions.upload {
            push_action(&mut out, LfsActionKind::Upload, a, now);
        }
        if let Some(a) = actions.verify {
            push_action(&mut out, LfsActionKind::Verify, a, now);
        }
    }
    Some(out)
}

fn push_action(out: &mut Vec<LfsAction>, kind: LfsActionKind, action: BatchAction, now: Instant) {
    let Some(url) = action.href else { return };
    if url.is_empty() {
        return;
    }
    let expires_at = derive_expires_at(action.expires_at.as_deref(), action.expires_in, now);
    out.push(LfsAction {
        kind,
        url,
        expires_at,
    });
}

fn derive_expires_at(
    expires_at: Option<&str>,
    expires_in: Option<i64>,
    now: Instant,
) -> Option<Instant> {
    let raw_secs = if let Some(secs) = expires_in {
        if secs <= 0 {
            return None;
        }
        secs as u64
    } else if let Some(s) = expires_at {
        let parsed =
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
        let now_utc = time::OffsetDateTime::now_utc();
        let delta = parsed - now_utc;
        let secs = delta.whole_seconds();
        if secs <= 0 {
            return None;
        }
        secs as u64
    } else {
        return None;
    };
    let clamped = Duration::from_secs(raw_secs)
        .max(MIN_ACTION_TTL)
        .min(MAX_ACTION_TTL);
    Some(now + clamped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_parse_real_shape_upload_response() {
        let t = test_report!("Parses a typical GitHub-style batch response with upload + verify");
        let body = br#"{
            "transfer": "basic",
            "objects": [{
                "oid": "abc",
                "size": 12,
                "actions": {
                    "upload": {
                        "href": "https://github-cloud.s3.amazonaws.com/alambic/?token=xyz",
                        "header": {"Authorization": "RemoteAuth ..."}
                    },
                    "verify": {
                        "href": "https://lfs.github.com/org/repo/objects/abc/verify",
                        "header": {"Authorization": "RemoteAuth ..."}
                    }
                }
            }]
        }"#;
        let actions = parse_lfs_batch_response(body).expect("parses");
        t.assert_eq("two actions extracted", &actions.len(), &2usize);
        t.assert_true(
            "upload kind",
            actions
                .iter()
                .any(|a| matches!(a.kind, LfsActionKind::Upload)),
        );
        t.assert_true(
            "verify kind",
            actions
                .iter()
                .any(|a| matches!(a.kind, LfsActionKind::Verify)),
        );
        let upload = actions
            .iter()
            .find(|a| matches!(a.kind, LfsActionKind::Upload))
            .unwrap();
        t.assert_eq("upload method", &upload.method(), &Method::PUT);
        let verify = actions
            .iter()
            .find(|a| matches!(a.kind, LfsActionKind::Verify))
            .unwrap();
        t.assert_eq("verify method", &verify.method(), &Method::POST);
    }

    #[test]
    fn test_parse_download_response() {
        let t = test_report!("Parses a download batch response and assigns GET method");
        let body = br#"{"objects":[{"oid":"a","size":1,"actions":{
            "download": {"href":"https://media.githubusercontent.com/x"}
        }}]}"#;
        let actions = parse_lfs_batch_response(body).expect("parses");
        t.assert_eq("one action", &actions.len(), &1usize);
        t.assert_eq("method", &actions[0].method(), &Method::GET);
        t.assert_eq(
            "url",
            &actions[0].url.as_str(),
            &"https://media.githubusercontent.com/x",
        );
    }

    #[test]
    fn test_skips_actions_without_href() {
        let t = test_report!("Skips action entries that lack href (defensive, no panic)");
        let body = br#"{"objects":[{"actions":{
            "download": {},
            "upload":   {"href": ""}
        }}]}"#;
        let actions = parse_lfs_batch_response(body).expect("parses");
        t.assert_true("no usable actions extracted", actions.is_empty());
    }

    #[test]
    fn test_skips_objects_with_error_field() {
        let t = test_report!("Objects with no actions field (e.g. error responses) are skipped");
        let body = br#"{"objects":[
            {"oid":"a","error":{"code":404,"message":"not found"}},
            {"oid":"b","actions":{"download":{"href":"https://example.com/b"}}}
        ]}"#;
        let actions = parse_lfs_batch_response(body).expect("parses");
        t.assert_eq(
            "only the second object yields an action",
            &actions.len(),
            &1usize,
        );
    }

    #[test]
    fn test_parse_encoded_gzip() {
        let t = test_report!("parse_lfs_batch_response_encoded gunzips Content-Encoding: gzip");
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let raw = br#"{"objects":[{"actions":{"download":{"href":"https://x/y"}}}]}"#;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw).unwrap();
        let gz = enc.finish().unwrap();
        let actions =
            parse_lfs_batch_response_encoded(&gz, Some("gzip")).expect("decoded + parsed");
        t.assert_eq("one action", &actions.len(), &1usize);
        t.assert_eq("download method", &actions[0].method(), &Method::GET);
    }

    #[test]
    fn test_parse_encoded_identity_passthrough() {
        let t = test_report!("parse_lfs_batch_response_encoded passes through identity / None");
        let raw = br#"{"objects":[{"actions":{"upload":{"href":"https://x/y"}}}]}"#;
        let with_identity = parse_lfs_batch_response_encoded(raw, Some("identity"));
        let with_none = parse_lfs_batch_response_encoded(raw, None);
        t.assert_eq(
            "identity yields 1 action",
            &with_identity.unwrap().len(),
            &1usize,
        );
        t.assert_eq("None yields 1 action", &with_none.unwrap().len(), &1usize);
    }

    #[test]
    fn test_parse_encoded_unsupported_returns_none() {
        let t = test_report!(
            "Unsupported Content-Encoding (e.g. br) yields None instead of misparsing"
        );
        let raw = br#"{"objects":[]}"#;
        t.assert_true(
            "br rejected",
            parse_lfs_batch_response_encoded(raw, Some("br")).is_none(),
        );
    }

    #[test]
    fn test_parse_encoded_corrupt_gzip_returns_none() {
        let t = test_report!("Corrupt gzip body yields None (no panic)");
        t.assert_true(
            "garbage gzip rejected",
            parse_lfs_batch_response_encoded(b"not gzip", Some("gzip")).is_none(),
        );
    }

    #[test]
    fn test_invalid_json_returns_none() {
        let t = test_report!("parse_lfs_batch_response returns None on malformed JSON");
        t.assert_true(
            "garbage rejected",
            parse_lfs_batch_response(b"not json").is_none(),
        );
    }

    #[test]
    fn test_expires_in_honored_and_clamped_short() {
        let t = test_report!("expires_in below MIN clamps up to MIN");
        let body = br#"{"objects":[{"actions":{"upload":{
            "href":"https://x/y",
            "expires_in": 5
        }}}]}"#;
        let actions = parse_lfs_batch_response(body).unwrap();
        // Use the post-parse instant — the action's expires_at was set during parse.
        let ttl = actions[0].ttl_from(Instant::now()).unwrap();
        t.assert_true(
            "ttl >= ~60s minus tiny scheduling slack",
            ttl + Duration::from_secs(1) >= MIN_ACTION_TTL,
        );
    }

    #[test]
    fn test_expires_in_clamped_long() {
        let t = test_report!("expires_in above MAX clamps down to MAX");
        let body = br#"{"objects":[{"actions":{"upload":{
            "href":"https://x/y",
            "expires_in": 86400
        }}}]}"#;
        let actions = parse_lfs_batch_response(body).unwrap();
        let ttl = actions[0].ttl_from(Instant::now()).unwrap();
        t.assert_true("ttl <= 3600s", ttl <= MAX_ACTION_TTL);
    }

    #[test]
    fn test_expires_at_rfc3339_parsed() {
        let t = test_report!("expires_at RFC3339 string is parsed");
        // 30 minutes in the future — within [MIN, MAX] so no clamping
        let future = time::OffsetDateTime::now_utc() + time::Duration::minutes(30);
        let s = future
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let body = format!(
            r#"{{"objects":[{{"actions":{{"upload":{{
                "href":"https://x/y","expires_at":"{}"
            }}}}}}]}}"#,
            s
        );
        let actions = parse_lfs_batch_response(body.as_bytes()).unwrap();
        let ttl = actions[0].ttl_from(Instant::now()).unwrap();
        // Should land roughly 30 min out (allow generous slack for test scheduling)
        t.assert_true(
            "ttl reflects ~30min",
            ttl > Duration::from_secs(60 * 25) && ttl < Duration::from_secs(60 * 35),
        );
    }

    #[test]
    fn test_no_expiration_yields_none_ttl() {
        let t = test_report!("Action without expires_at/expires_in returns ttl_from = None");
        let body = br#"{"objects":[{"actions":{"verify":{"href":"https://x/y"}}}]}"#;
        let actions = parse_lfs_batch_response(body).unwrap();
        t.assert_true("no ttl", actions[0].ttl_from(Instant::now()).is_none());
    }

    #[test]
    fn test_covered_by_logic() {
        let t = test_report!(
            "LfsActionKind::covered_by maps download->download, upload+verify->upload"
        );
        t.assert_true(
            "download covered by download",
            LfsActionKind::Download.covered_by("download"),
        );
        t.assert_true(
            "upload covered by upload",
            LfsActionKind::Upload.covered_by("upload"),
        );
        t.assert_true(
            "verify covered by upload",
            LfsActionKind::Verify.covered_by("upload"),
        );
        t.assert_true(
            "download NOT covered by upload",
            !LfsActionKind::Download.covered_by("upload"),
        );
        t.assert_true(
            "upload NOT covered by download",
            !LfsActionKind::Upload.covered_by("download"),
        );
    }
}
