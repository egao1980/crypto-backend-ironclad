# crypto-backend-ironclad

Ironclad backend for [`crypto-protocol`](https://github.com/egao1980/crypto-protocol).

```lisp
(asdf:load-system "crypto-backend-ironclad")  ; sets stack-crypto:*crypto-backend*
(stack-crypto:seal pt :key key)
```

OCI: `ghcr.io/egao1980/cl-systems/crypto-backend-ironclad:0.1.0`  
Depends on: `crypto-protocol` **0.1.0**, `ironclad`.

## License

MIT
