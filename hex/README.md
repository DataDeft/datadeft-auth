# Elixir implementation

- [`datadeft_auth/`](datadeft_auth/): one native Elixir Hex package.
- [`examples/bandit_magic_link/`](examples/bandit_magic_link/README.md): runnable loopback-only Plug/Bandit consumer.

All Elixir code, tests, examples and package-specific scripts live here. There is
no Mix umbrella. A tiny owner-approved Rustler crypto NIF reuses the existing
Rust core; services, storage and HTTP remain in Elixir. Root mise tasks
orchestrate the package and mixed-language compatibility suite.

The shared browser client stays in `packages/dd-protect-client/`; Rust libraries
stay in `crates/`. Shared contracts and vectors live in `spec/compatibility/`.

See [the approved plan](../docs/elixir-0.8-plan.md) and
[the implementation checklist](datadeft_auth/IMPLEMENTATION.md).
