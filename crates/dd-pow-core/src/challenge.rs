//! Wire value types: the challenge served to the client, the solution
//! submitted for verification, and the verified result.

/// Challenge as served to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Hex BLAKE3 hash of `Time={tim}:Nonce={hex(entropy)}`.
    pub chg: String,
    /// Number of leading zero hex characters the solution hash must have.
    pub dif: u8,
    /// Mint time, RFC3339 (the client echoes it back unchanged).
    pub tim: String,
    /// Hex HMAC-SHA256 over the framed `(domain, chg, dif, tim)` tuple.
    pub tag: String,
}

/// Solution as submitted for verification.
///
/// The shipping client/API posts `{ chg, sol, non, dif, tim, tag }`. The client
/// echoes `dif` from the minted challenge. The HMAC tag binds it, so a client
/// cannot lower the work factor. [`crate::verify_solution`] separately checks it
/// against the server's current minimum to support explicit difficulty bumps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solution {
    /// Challenge id, echoed from the [`Challenge`].
    pub chg: String,
    /// Hex SHA-256 of `chg + non`, lowercase, with `dif` leading `'0'` chars.
    pub sol: String,
    /// Nonce as a decimal string (the worker sends `nonce.toString()`).
    pub non: String,
    /// Difficulty the challenge was minted at, echoed by the client/API.
    pub dif: u8,
    /// Mint time, RFC3339, echoed from the [`Challenge`].
    pub tim: String,
    /// HMAC tag, echoed from the [`Challenge`].
    pub tag: String,
}

/// Successful verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Replay-safe token identity: hex BLAKE3 hash of `chg`. Replaying the
    /// same solve always yields the same `tid`, so the API layer can use it
    /// for idempotent cookie minting and a per-tid budget.
    ///
    /// # Warning: not a secret or capability
    ///
    /// `tid` is derived from `chg`, which is itself derived from public mint
    /// inputs (time + entropy). Anyone who saw the challenge can recompute
    /// `tid`, so it carries no authenticity on its own. It must never be used
    /// as a bearer token, never authorize anything on its own, and never be
    /// exposed to clients unbound. Single-use / replay enforcement must wrap
    /// it under a server-held secret (e.g. a signed/encrypted proof cookie)
    /// in an upper layer.
    pub tid: String,
}
