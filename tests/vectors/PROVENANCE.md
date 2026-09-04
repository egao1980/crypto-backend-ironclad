# Signature test vectors

## RFC 8032 (Ed25519)

`rfc8032-ed25519.lisp` — test 1 from [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
(empty message). IETF document; no additional license.

Round-trip + flipped-bit fail-closed coverage for RSA-PSS, RSA-PKCS1, and
ECDSA P-256 lives in `tests/sign-test.lisp` (generated keys, not KATs).

Full [Wycheproof](https://github.com/C2SP/wycheproof) JSON is not vendored
(size / fetch). Revisit if we pin a tagged excerpt.
