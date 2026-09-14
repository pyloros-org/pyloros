# rcgen omits Authority Key Identifier by default

`CertificateParams::default()` writes a Subject Key Identifier but **no** Authority Key
Identifier. OpenSSL's `X509_V_FLAG_X509_STRICT` rejects such chains with:

```
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Missing Authority Key Identifier
```

Python 3.12+ sets `ssl.VERIFY_X509_STRICT` by default, so any MITM chain without AKI breaks
`requests`/`urllib` while curl and rustls still accept it.

Fix: `params.use_authority_key_identifier_extension = true;` on both the CA and the per-host
certs (`src/tls/ca.rs`).

Backwards compatible with CAs generated before this change: `Issuer::from_ca_cert_der` picks up
the CA's existing SKI as `KeyIdMethod::PreSpecified`, falling back to SHA-256 over the SPKI when
the CA cert has no SKI at all.

Reproducing without a full proxy run: `tests/fixtures/x509_strict_check.py` runs a Python TLS
server with the leaf cert and a client with `VERIFY_X509_STRICT` set (`tests/x509_strict_test.rs`).
