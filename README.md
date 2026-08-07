# crypto-backend-ironclad

Ironclad backend for:

- [`crypto-protocol`](https://github.com/egao1980/crypto-protocol) — digest / HMAC / AEAD / `seal`
- [`secrets-protocol`](https://github.com/egao1980/secrets-protocol) — CSPRNG / tokens / UUID / password KDFs

One ASDF system, one instance bound to both `*crypto-backend*` and `*secrets-backend*`.

```lisp
(asdf:load-system "crypto-backend-ironclad")
(stack-crypto:seal pt :key (stack-secrets:random-bytes 32))
(stack-secrets:hash-password "s3cret")
```

OCI: `ghcr.io/egao1980/cl-systems/crypto-backend-ironclad:0.1.1`

## License

MIT
