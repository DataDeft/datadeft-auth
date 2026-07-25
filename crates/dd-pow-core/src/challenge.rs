//! Wire value types: the challenge served to the client, the solution
//! submitted for verification, and the verified result.

/// Challenge as served to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Hex BLAKE3 hash of `Time={tim}:Nonce={hex(entropy)}`.
    pub chg: String,
    /// Number of leading zero hex characters the solution hash must have.
    pub dif: u8,
    /// Mint time, RFC3339 (echoed back by the client verbatim).
    pub tim: String,
    /// Hex HMAC-SHA256 over `"{chg}:{dif}:{tim}"`.
    pub tag: String,
}

/// Solution as submitted for verification.
///
/// The shipping client posts `{ chg, sol, non, tim, tag }` — it does not echo
/// `dif`. The API layer sets `dif` to the server's current difficulty before
/// calling [`crate::verify_solution`]; the HMAC tag binds the minted
/// difficulty, so a mismatch fails as [`crate::PowError::InvalidTag`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solution {
    /// Challenge id, echoed from the [`Challenge`].
    pub chg: String,
    /// Hex SHA-256 of `chg + non`, lowercase, with `dif` leading `'0'` chars.
    pub sol: String,
    /// Nonce as a decimal string (the worker sends `nonce.toString()`).
    pub non: String,
    /// Difficulty the challenge was minted at (supplied by the API layer).
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
    pub tid: String,
}
