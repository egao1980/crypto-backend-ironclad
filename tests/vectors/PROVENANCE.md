# Signature test vectors

## RFC 8032 (Ed25519)

`rfc8032-ed25519.lisp` — test 1 from [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
(empty message). IETF document; no additional license.

## Wycheproof excerpt (Apache-2.0)

Vendored as Lisp tables (not the full JSON dump):

| File | Source | Cases |
|------|--------|-------|
| `wycheproof-ed25519.lisp` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/ed25519_test.json` (google-wycheproof 0.9rc5) | tcId 1–3 valid, tcId 10 invalid (zero r,s) |
| `wycheproof-ecdsa-p256.lisp` | `testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` | tcId 1 valid P1363, tcId 2 invalid (`r + n`) |

RSA-PSS stays generated-key round-trip in `tests/sign-test.lisp` (full RSA Wycheproof groups are huge). JWT interop vs PyJWT lives in `cl-stack-jwt/tests/peers/`.

Upstream license: [Apache-2.0](https://github.com/C2SP/wycheproof/blob/master/LICENSE).
