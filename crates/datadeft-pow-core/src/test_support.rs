//! Deterministic fixtures shared by the PoW test suites: fixed secret,
//! clock, and the worker-style solver.
//!
//! Available under `cfg(test)` and the explicit `test-support` feature only.
//! Never use it in default production builds. The solver is an honest
//! brute-force client for tests; production clients solve in the browser
//! worker.

#[cfg(test)]
use crate::challenge::Solution;
#[cfg(test)]
use crate::clock::UnixMillis;
#[cfg(test)]
use crate::mint_challenge;
#[cfg(test)]
use crate::secret::PowSecret;
use sha2::{Digest, Sha256};

#[cfg(test)]
pub(crate) const TIM: &str = "2026-07-09T12:00:00Z";
/// Unix timestamp of TIM (2026-07-09T12:00:00Z).
#[cfg(test)]
pub(crate) const TIM_UNIX: u64 = 1_783_598_400;
#[cfg(test)]
pub(crate) const MAX_AGE: u64 = 300;

/// Millisecond clock at a whole-second unix instant. The fixtures predate
/// millisecond resolution and are specified in seconds.
#[cfg(test)]
pub(crate) fn at(unix_secs: u64) -> UnixMillis {
    UnixMillis::from_millis(unix_secs * 1000)
}

#[cfg(test)]
pub(crate) fn secret() -> PowSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    PowSecret::new(bytes)
}

#[cfg(test)]
pub(crate) fn entropy() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    bytes
}

/// Solve a challenge the way the browser worker does, for tests.
///
/// Mirrors the worker exactly: it hashes `chg + String(nonce)` (UTF-8,
/// decimal nonce, counting up from 0) with SHA-256 and checks `dif` leading
/// zero NIBBLES of the digest (its hex string therefore starts with `dif`
/// '0' chars). Single-worker equivalent: startNonce=0, step=1.
///
/// Returns `(non, sol)` as the client posts them: the decimal nonce string
/// and the lowercase hex digest.
#[must_use]
pub fn solve(chg: &str, dif: u8) -> (String, String) {
    let mut nonce: u64 = 0;
    loop {
        let digest = Sha256::digest(format!("{chg}{nonce}").as_bytes());
        let ok = (0..usize::from(dif)).all(|i| {
            let byte = digest[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            nibble == 0
        });
        if ok {
            return (nonce.to_string(), hex::encode(digest));
        }
        nonce += 1;
    }
}

#[cfg(test)]
pub(crate) fn solved_solution(dif: u8) -> Solution {
    let challenge = mint_challenge(&secret(), dif, at(TIM_UNIX), entropy()).expect("mint");
    let (non, sol) = solve(&challenge.chg, dif);
    // Field mapping as the client builds its Solution JSON: chg/tim/tag/dif
    // echoed, sol = hash, non = nonce.toString().
    Solution {
        chg: challenge.chg,
        sol,
        non,
        dif,
        tim: challenge.tim,
        tag: challenge.tag,
    }
}
