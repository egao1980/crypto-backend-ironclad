# crypto-backend-ironclad

Ironclad backend for:

- [`crypto-protocol`](https://github.com/egao1980/crypto-protocol) — digest / HMAC / AEAD / `seal` / **sign/verify**
- [`secrets-protocol`](https://github.com/egao1980/secrets-protocol) — CSPRNG / tokens / UUID / password KDFs

One ASDF system, one instance bound to both `*crypto-backend*` and `*secrets-backend*`.

```lisp
(asdf:load-system "crypto-backend-ironclad")
(stack-crypto:seal pt :key (stack-secrets:random-bytes 32))
(stack-secrets:hash-password "s3cret")
```

Signatures: `:ed25519`, `:rsa-pss-sha256`, `:ecdsa-p256-sha256`, `:rsa-pkcs1-sha256`
(JWT aliases `:eddsa` / `:ps256` / `:es256` / `:rs256`). Known-answer: RFC 8032
Ed25519 (see `tests/vectors/PROVENANCE.md`).

OCI: `ghcr.io/egao1980/cl-systems/crypto-backend-ironclad:0.2.0`

## License

MIT
