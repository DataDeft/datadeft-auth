# Datadeft auth documentation

## Start here

- [Software architecture](architecture.md) — current components, protocols, diagrams, algorithms, and complexity
- [Customer onboarding and implementation status](onboarding.md) — production checklist and MVP backlog
- [Security rules](security.md) — normative security requirements
- [Formal assurance roadmap](formal-methods.md) — planned TLA+, simulation, fuzzing, and bounded verification

## Libraries

- `dd-pow-core` — implemented pure proof-of-work challenge mint/verify primitives
- `dd-auth-token-core` — implemented token, keyring, session, and flow-cookie primitives
- `dd-magic-link-core` — implemented magic-link token and HMAC primitives
- `dd-magic-link-service` — implemented request, confirmation, session, and repository orchestration
- `dd-magic-link-axum` — implemented optional Axum HTTP integration
- `dd-magic-link-aws` — implemented optional DynamoDB/SES adapters and fakes
- `dd-protect-client` — **planned; browser package is currently a skeleton**

## Contributor and historical documents

- [Rust standards](rust-standards.md)
- [Operating model](operating.md)
- [Extraction plan](plan.md) — historical roadmap
- [Production fix plan](fix.md) — historical remediation input
- [Prior review](review.md) — historical audit input
