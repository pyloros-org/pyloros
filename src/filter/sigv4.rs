//! AWS Signature Version 4 signing and verification.
//!
//! Uses `ring` for SHA-256 and HMAC-SHA256, which is already a transitive
//! dependency via rcgen/rustls.

use ring::digest;
use ring::hmac;

/// Parsed fields from an existing AWS Authorization header.
pub struct AwsAuthParsed {
    pub access_key_id: String,
    pub date_stamp: String,
    pub region: String,
    pub service: String,
    pub signed_headers: String,
    pub signature: String,
}

/// Parse an existing Authorization header to extract all SigV4 fields.
///
/// Expected format:
/// `AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef`
pub fn parse_authorization(auth_header: &str) -> Option<AwsAuthParsed> {
    let auth = auth_header.trim();
    if !auth.starts_with("AWS4-HMAC-SHA256") {
        return None;
    }

    // Find Credential= field
    let cred_start = auth.find("Credential=")?;
    let after_cred = &auth[cred_start + "Credential=".len()..];
    let cred_end = after_cred.find([',', ' ']).unwrap_or(after_cred.len());
    let credential_value = &after_cred[..cred_end];

    // credential_value = "AKID/20250101/us-east-1/sts/aws4_request"
    let parts: Vec<&str> = credential_value.split('/').collect();
    if parts.len() < 5 {
        return None;
    }

    // Find SignedHeaders= field
    let sh_start = auth.find("SignedHeaders=")?;
    let after_sh = &auth[sh_start + "SignedHeaders=".len()..];
    let sh_end = after_sh.find([',', ' ']).unwrap_or(after_sh.len());
    let signed_headers = &after_sh[..sh_end];

    // Find Signature= field
    let sig_start = auth.find("Signature=")?;
    let after_sig = &auth[sig_start + "Signature=".len()..];
    let sig_end = after_sig.find([',', ' ']).unwrap_or(after_sig.len());
    let signature = &after_sig[..sig_end];

    Some(AwsAuthParsed {
        access_key_id: parts[0].to_string(),
        date_stamp: parts[1].to_string(),
        region: parts[2].to_string(),
        service: parts[3].to_string(),
        signed_headers: signed_headers.to_string(),
        signature: signature.to_string(),
    })
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// SHA-256 hash, returned as lowercase hex string.
fn sha256_hex(data: &[u8]) -> String {
    hex_encode(digest::digest(&digest::SHA256, data).as_ref())
}

/// HMAC-SHA256 sign, returning raw bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&signing_key, data).as_ref().to_vec()
}

/// Derive the SigV4 signing key via chained HMAC.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret);
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Build the canonical query string: sort parameters by name, then by value.
fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut params: Vec<(&str, &str)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut parts = p.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let val = parts.next().unwrap_or("");
            (key, val)
        })
        .collect();
    params.sort();
    params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Core signing logic with explicit timestamps.
///
/// `headers` must be sorted lowercase (name, trimmed_value) pairs and should NOT
/// include `authorization`, `x-amz-date`, `x-amz-content-sha256`, or
/// `x-amz-security-token` — those are stripped before calling this function.
#[allow(clippy::too_many_arguments)]
fn sign_request_at(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    method: &str,
    canonical_uri: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
    date_stamp: &str,
    amz_date: &str,
) -> Vec<(String, String)> {
    // Body hash
    let payload_hash = sha256_hex(body);

    // Build signed headers list: original headers + x-amz-date + x-amz-content-sha256
    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    all_headers.push(("x-amz-date".to_string(), amz_date.to_string()));
    if let Some(token) = session_token {
        all_headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    all_headers.sort_by(|a, b| a.0.cmp(&b.0));

    // Canonical headers and signed headers
    let canonical_headers: String = all_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();
    let signed_headers: String = all_headers
        .iter()
        .map(|h| h.0.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // Canonical URI (must be at least "/")
    let uri = if canonical_uri.is_empty() {
        "/"
    } else {
        canonical_uri
    };

    // Canonical request
    let canonical_query = canonical_query_string(query);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, canonical_query, canonical_headers, signed_headers, payload_hash
    );

    // Credential scope
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);

    // String to sign
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    // Derive signing key and sign
    let signing_key = derive_signing_key(secret_access_key, date_stamp, region, service);
    let signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    // Build Authorization header
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key_id, credential_scope, signed_headers, signature
    );

    // Return headers to set
    let mut result = vec![
        ("authorization".to_string(), authorization),
        ("x-amz-date".to_string(), amz_date.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash),
    ];
    if let Some(token) = session_token {
        result.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    result
}

/// Sign a request using AWS SigV4, returning headers to set.
///
/// `headers` must be sorted lowercase (name, trimmed_value) pairs and should NOT
/// include `authorization`, `x-amz-date`, `x-amz-content-sha256`, or
/// `x-amz-security-token` — those are stripped before calling this function.
///
/// Returns: `[(header_name, header_value), ...]` for Authorization, X-Amz-Date,
/// X-Amz-Content-Sha256, and optionally X-Amz-Security-Token.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    method: &str,
    canonical_uri: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
) -> Vec<(String, String)> {
    let now = time::OffsetDateTime::now_utc();
    let date_stamp = now
        .format(&time::format_description::well_known::Iso8601::DATE)
        .unwrap()
        .replace('-', "");
    let amz_date = format!(
        "{}T{:02}{:02}{:02}Z",
        date_stamp,
        now.hour(),
        now.minute(),
        now.second()
    );

    sign_request_at(
        access_key_id,
        secret_access_key,
        session_token,
        method,
        canonical_uri,
        query,
        headers,
        body,
        region,
        service,
        &date_stamp,
        &amz_date,
    )
}

/// Verify a request's SigV4 signature against local credentials.
///
/// Reconstructs the canonical request and computes the expected signature
/// using the local (inside) credentials. Returns true if the signature matches.
///
/// `all_headers` should contain all request headers (lowercase name, trimmed value),
/// NOT including `authorization` but INCLUDING `x-amz-date`, `x-amz-content-sha256`,
/// and `x-amz-security-token` if present.
#[allow(clippy::too_many_arguments)]
pub fn verify_request_signature(
    local_access_key_id: &str,
    local_secret_access_key: &str,
    method: &str,
    canonical_uri: &str,
    query: &str,
    all_headers: &[(String, String)],
    body: &[u8],
    auth_header: &str,
) -> bool {
    let parsed = match parse_authorization(auth_header) {
        Some(p) => p,
        None => return false,
    };

    // Check access_key_id matches
    if parsed.access_key_id != local_access_key_id {
        return false;
    }

    // Get amz_date from headers
    let amz_date = match all_headers.iter().find(|(k, _)| k == "x-amz-date") {
        Some((_, v)) => v.clone(),
        None => return false,
    };

    // Body hash
    let payload_hash = sha256_hex(body);

    // Filter headers to only those in the signed headers list
    let signed_header_names: Vec<&str> = parsed.signed_headers.split(';').collect();
    let mut signed_header_pairs: Vec<(String, String)> = all_headers
        .iter()
        .filter(|(k, _)| signed_header_names.contains(&k.as_str()))
        .cloned()
        .collect();
    signed_header_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    // Canonical headers and signed headers
    let canonical_headers: String = signed_header_pairs
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();

    // Canonical URI
    let uri = if canonical_uri.is_empty() {
        "/"
    } else {
        canonical_uri
    };

    // Canonical request
    let canonical_query = canonical_query_string(query);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, canonical_query, canonical_headers, parsed.signed_headers, payload_hash
    );

    // Credential scope
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        parsed.date_stamp, parsed.region, parsed.service
    );

    // String to sign
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    // Derive signing key and compute expected signature
    let signing_key = derive_signing_key(
        local_secret_access_key,
        &parsed.date_stamp,
        &parsed.region,
        &parsed.service,
    );
    let expected_signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    // Use HMAC-based comparison to avoid timing side channels.
    // We compute HMAC(expected) and verify against HMAC(actual) using the same key.
    let cmp_key = hmac::Key::new(hmac::HMAC_SHA256, b"sigv4-verify");
    let expected_tag = hmac::sign(&cmp_key, expected_signature.as_bytes());
    hmac::verify(&cmp_key, parsed.signature.as_bytes(), expected_tag.as_ref()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_parse_authorization_basic() {
        let t = test_report!("Parse standard AWS Authorization header");
        let auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024";
        let parsed = parse_authorization(auth).unwrap();
        t.assert_eq(
            "access_key_id",
            &parsed.access_key_id.as_str(),
            &"AKIAIOSFODNN7EXAMPLE",
        );
        t.assert_eq("date_stamp", &parsed.date_stamp.as_str(), &"20130524");
        t.assert_eq("region", &parsed.region.as_str(), &"us-east-1");
        t.assert_eq("service", &parsed.service.as_str(), &"s3");
        t.assert_eq(
            "signed_headers",
            &parsed.signed_headers.as_str(),
            &"host;range;x-amz-date",
        );
        t.assert_eq(
            "signature",
            &parsed.signature.as_str(),
            &"fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
        );
    }

    #[test]
    fn test_parse_authorization_sts() {
        let t = test_report!("Parse STS Authorization header");
        let auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20250101/us-west-2/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123";
        let parsed = parse_authorization(auth).unwrap();
        t.assert_eq("region", &parsed.region.as_str(), &"us-west-2");
        t.assert_eq("service", &parsed.service.as_str(), &"sts");
        t.assert_eq("signature", &parsed.signature.as_str(), &"abc123");
    }

    #[test]
    fn test_parse_authorization_missing_prefix() {
        let t = test_report!("Reject non-AWS4 Authorization header");
        let result = parse_authorization("Bearer some-token");
        t.assert_true("returns None", result.is_none());
    }

    #[test]
    fn test_parse_authorization_too_few_parts() {
        let t = test_report!("Reject malformed credential scope");
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1";
        let result = parse_authorization(auth);
        t.assert_true("returns None", result.is_none());
    }

    #[test]
    fn test_parse_authorization_empty() {
        let t = test_report!("Empty Authorization header returns None");
        let result = parse_authorization("");
        t.assert_true("returns None", result.is_none());
    }

    #[test]
    fn test_parse_authorization_missing_signed_headers() {
        let t = test_report!("Reject Authorization header without SignedHeaders");
        let auth =
            "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/aws4_request, Signature=abc123";
        let result = parse_authorization(auth);
        t.assert_true("returns None", result.is_none());
    }

    #[test]
    fn test_parse_authorization_missing_signature() {
        let t = test_report!("Reject Authorization header without Signature");
        let auth = "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date";
        let result = parse_authorization(auth);
        t.assert_true("returns None", result.is_none());
    }

    #[test]
    fn test_sha256_hex_empty() {
        let t = test_report!("SHA256 of empty body");
        let hash = sha256_hex(b"");
        t.assert_eq(
            "empty body hash",
            &hash.as_str(),
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn test_sha256_hex_payload() {
        let t = test_report!("SHA256 of 'hello'");
        let hash = sha256_hex(b"hello");
        t.assert_eq(
            "hash",
            &hash.as_str(),
            &"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
    }

    #[test]
    fn test_canonical_query_string_empty() {
        let t = test_report!("Empty query string");
        let result = canonical_query_string("");
        t.assert_eq("empty", &result.as_str(), &"");
    }

    #[test]
    fn test_canonical_query_string_sorted() {
        let t = test_report!("Query string parameters sorted");
        let result = canonical_query_string("z=1&a=2&m=3");
        t.assert_eq("sorted", &result.as_str(), &"a=2&m=3&z=1");
    }

    #[test]
    fn test_derive_signing_key() {
        let t = test_report!("Derive signing key (AWS test vector)");
        // AWS test vector from docs
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        let hex = hex_encode(&key);
        t.assert_eq(
            "signing key",
            &hex.as_str(),
            &"f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
        );
    }

    #[test]
    fn test_sign_request_returns_required_headers() {
        let t =
            test_report!("sign_request returns Authorization, X-Amz-Date, X-Amz-Content-Sha256");
        let headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let result = sign_request(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            "GET",
            "/",
            "",
            &headers,
            b"",
            "us-east-1",
            "sts",
        );
        let names: Vec<&str> = result.iter().map(|(n, _)| n.as_str()).collect();
        t.assert_true("has authorization", names.contains(&"authorization"));
        t.assert_true("has x-amz-date", names.contains(&"x-amz-date"));
        t.assert_true(
            "has x-amz-content-sha256",
            names.contains(&"x-amz-content-sha256"),
        );
        t.assert_true(
            "no security token",
            !names.contains(&"x-amz-security-token"),
        );

        // Verify authorization header structure
        let auth = result
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();
        t.assert_starts_with(
            "auth prefix",
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/",
        );
        t.assert_contains("auth has region", auth, "us-east-1");
        t.assert_contains("auth has service", auth, "sts");
    }

    #[test]
    fn test_sign_request_with_session_token() {
        let t = test_report!("sign_request includes X-Amz-Security-Token when provided");
        let headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let result = sign_request(
            "AKID",
            "SECRET",
            Some("MY-SESSION-TOKEN"),
            "GET",
            "/",
            "",
            &headers,
            b"",
            "us-east-1",
            "sts",
        );
        let token = result
            .iter()
            .find(|(n, _)| n == "x-amz-security-token")
            .map(|(_, v)| v.as_str());
        t.assert_eq("token value", &token, &Some("MY-SESSION-TOKEN"));
    }

    #[test]
    fn test_sign_request_body_hash() {
        let t = test_report!("sign_request computes correct body hash");
        let body = b"Action=GetCallerIdentity&Version=2011-06-15";
        let headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let result = sign_request(
            "AKID",
            "SECRET",
            None,
            "POST",
            "/",
            "",
            &headers,
            body,
            "us-east-1",
            "sts",
        );
        let content_hash = result
            .iter()
            .find(|(n, _)| n == "x-amz-content-sha256")
            .map(|(_, v)| v.as_str())
            .unwrap();
        let expected = sha256_hex(body);
        t.assert_eq("body hash", &content_hash, &expected.as_str());
    }

    #[test]
    fn test_sign_request_empty_body_hash() {
        let t = test_report!("sign_request: empty body produces known SHA256");
        let headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let result = sign_request(
            "AKID",
            "SECRET",
            None,
            "GET",
            "/",
            "",
            &headers,
            b"",
            "us-east-1",
            "sts",
        );
        let content_hash = result
            .iter()
            .find(|(n, _)| n == "x-amz-content-sha256")
            .map(|(_, v)| v.as_str())
            .unwrap();
        t.assert_eq(
            "empty body hash",
            &content_hash,
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn test_verify_request_signature_valid() {
        let t = test_report!("verify_request_signature accepts valid signature");
        let key_id = "AKIAIOSFODNN7EXAMPLE";
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let base_headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let body = b"";

        // Sign a request
        let signed = sign_request_at(
            key_id,
            secret,
            None,
            "GET",
            "/",
            "",
            &base_headers,
            body,
            "us-east-1",
            "sts",
            "20250101",
            "20250101T120000Z",
        );

        let auth_header = signed
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();

        // Build all_headers for verification (everything except authorization)
        let mut all_headers: Vec<(String, String)> = base_headers.clone();
        for (name, value) in &signed {
            if name != "authorization" {
                all_headers.push((name.clone(), value.clone()));
            }
        }
        all_headers.sort_by(|a, b| a.0.cmp(&b.0));

        let result = verify_request_signature(
            key_id,
            secret,
            "GET",
            "/",
            "",
            &all_headers,
            body,
            &auth_header,
        );
        t.assert_true("valid signature accepted", result);
    }

    #[test]
    fn test_verify_request_signature_wrong_secret() {
        let t = test_report!("verify_request_signature rejects wrong secret key");
        let key_id = "AKIAIOSFODNN7EXAMPLE";
        let real_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let wrong_secret = "WRONGSECRETWRONGSECRETWRONGSECRETWRONGSE";
        let base_headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];
        let body = b"";

        // Sign with real secret
        let signed = sign_request_at(
            key_id,
            real_secret,
            None,
            "GET",
            "/",
            "",
            &base_headers,
            body,
            "us-east-1",
            "sts",
            "20250101",
            "20250101T120000Z",
        );

        let auth_header = signed
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();

        let mut all_headers: Vec<(String, String)> = base_headers.clone();
        for (name, value) in &signed {
            if name != "authorization" {
                all_headers.push((name.clone(), value.clone()));
            }
        }
        all_headers.sort_by(|a, b| a.0.cmp(&b.0));

        // Verify with wrong secret
        let result = verify_request_signature(
            key_id,
            wrong_secret,
            "GET",
            "/",
            "",
            &all_headers,
            body,
            &auth_header,
        );
        t.assert_true("wrong secret rejected", !result);
    }

    #[test]
    fn test_verify_request_signature_wrong_key_id() {
        let t = test_report!("verify_request_signature rejects wrong access key ID");
        let key_id = "AKIAIOSFODNN7EXAMPLE";
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let base_headers = vec![("host".to_string(), "sts.amazonaws.com".to_string())];

        let signed = sign_request_at(
            key_id,
            secret,
            None,
            "GET",
            "/",
            "",
            &base_headers,
            b"",
            "us-east-1",
            "sts",
            "20250101",
            "20250101T120000Z",
        );

        let auth_header = signed
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();

        let mut all_headers: Vec<(String, String)> = base_headers.clone();
        for (name, value) in &signed {
            if name != "authorization" {
                all_headers.push((name.clone(), value.clone()));
            }
        }
        all_headers.sort_by(|a, b| a.0.cmp(&b.0));

        let result = verify_request_signature(
            "AKIAWRONGKEYID12345",
            secret,
            "GET",
            "/",
            "",
            &all_headers,
            b"",
            &auth_header,
        );
        t.assert_true("wrong key ID rejected", !result);
    }

    #[test]
    fn test_verify_request_signature_with_body() {
        let t = test_report!("verify_request_signature with non-empty body");
        let key_id = "AKIAEXAMPLE";
        let secret = "secretkey12345678901234567890123456789012";
        let base_headers = vec![
            ("host".to_string(), "s3.amazonaws.com".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let body = b"{\"key\": \"value\"}";

        let signed = sign_request_at(
            key_id,
            secret,
            None,
            "PUT",
            "/bucket/object",
            "",
            &base_headers,
            body,
            "us-west-2",
            "s3",
            "20250315",
            "20250315T100000Z",
        );

        let auth_header = signed
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();

        let mut all_headers: Vec<(String, String)> = base_headers.clone();
        for (name, value) in &signed {
            if name != "authorization" {
                all_headers.push((name.clone(), value.clone()));
            }
        }
        all_headers.sort_by(|a, b| a.0.cmp(&b.0));

        let result = verify_request_signature(
            key_id,
            secret,
            "PUT",
            "/bucket/object",
            "",
            &all_headers,
            body,
            &auth_header,
        );
        t.assert_true("body signature valid", result);

        // Tampered body should fail
        let result_tampered = verify_request_signature(
            key_id,
            secret,
            "PUT",
            "/bucket/object",
            "",
            &all_headers,
            b"tampered",
            &auth_header,
        );
        t.assert_true("tampered body rejected", !result_tampered);
    }

    #[test]
    fn test_verify_request_signature_invalid_auth_header() {
        let t = test_report!("verify_request_signature rejects non-AWS auth header");
        let result = verify_request_signature(
            "AKID",
            "SECRET",
            "GET",
            "/",
            "",
            &[],
            b"",
            "Bearer some-token",
        );
        t.assert_true("non-AWS rejected", !result);
    }
}
