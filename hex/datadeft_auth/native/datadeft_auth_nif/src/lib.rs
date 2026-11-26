#![deny(unsafe_code)]
//! Minimal BEAM crypto boundary. See ../../../CRYPTO-DEPENDENCIES.md.
//! No service logic, callbacks, resources, or infrastructure.

mod branca;

rustler::init!("Elixir.DatadeftAuth.Native");
