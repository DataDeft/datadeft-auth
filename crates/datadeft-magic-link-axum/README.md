# datadeft-magic-link-axum

Axum HTTP integration for
[`datadeft-magic-link-service`](https://crates.io/crates/datadeft-magic-link-service).

```toml
[dependencies]
datadeft-magic-link-axum = "0.4"
```

Bounded request decoding, scanner-safe landing and confirmation handlers,
cookie helpers, session authentication, and generic public errors. The crate is
headless: it returns structured results and prepared `Set-Cookie` headers, and
your application owns the router and renders responses.

## Response contract

- Only the same-origin confirmation `POST` consumes a link and creates a
  session. Never consume on `GET`.
- The landing `GET` must stay side-effect-free: email scanners fetch links.
- Return `Rejected` with the same status as success, so link validity cannot
  be enumerated.
- Apply `apply_magic_link_security_headers` to every landing and confirmation
  response.

## Mandatory deployment gate

The magic-link token is in the landing request target before any handler runs.
Your proxy, access logs, middleware, tracing, metrics, and error reporting must
use route templates and never record raw request targets, query strings, or
cookies. Verify this with production-like probes.

The crate docs contain a compiling quickstart. The full runnable integration is
[`examples/axum-magic-link`](https://github.com/DataDeft/datadeft-auth/blob/main/examples/axum-magic-link).

## Security

The normative security policy is [`docs/security.md`](https://github.com/DataDeft/datadeft-auth/blob/main/docs/security.md).

## License

Licensed under MIT.
