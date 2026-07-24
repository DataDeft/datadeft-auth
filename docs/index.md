# Datadeft auth libraries

This repository contains reusable Rust authentication libraries.

Crates:

- `dd-pow-core` — pure proof-of-work challenge mint/verify.
- `dd-auth-token-core` — Branca/keyring/session/PoW cookie primitives.
- `dd-magic-link-core` — magic-link token grammar and pure auth primitives.
- `dd-magic-link-service` — storage/email/rate-limit trait based flow orchestration.
- `dd-magic-link-axum` — optional Axum HTTP integration.
- `dd-magic-link-aws` — optional AWS DynamoDB/SES adapters.

Optional package:

- `dd-protect-client` — optional npm/browser proof-of-work client.

Development docs:

- [Extraction plan](plan.md)
- [Rust standards](rust-standards.md)
- [Operating model](operating.md)
- [Security rules](security.md)
