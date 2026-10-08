//! Shared fixtures for the PoW test modules: fixed secret, clock, and worker-style solver.

//! Tests for the proof-of-work core. Time/entropy are injected data, so
//! generation is deterministic apart from proptest's own seeded RNG.

use crate::challenge::Solution;
use crate::clock::UnixMillis;
use crate::mint_challenge;
use crate::secret::PowSecret;
use sha2::{Digest, Sha256};

pub(super) const TIM: &str = "2026-07-09T12:00:00Z";
/// Unix timestamp of TIM (2026-07-09T12:00:00Z).
pub(super) const TIM_UNIX: u64 = 1_783_598_400;
pub(super) const MAX_AGE: u64 = 300;

/// Millisecond clock at a whole-second unix instant. The fixtures predate
/// millisecond resolution and are specified in seconds.
pub(super) fn at(unix_secs: u64) -> UnixMillis {
    UnixMillis::from_millis(unix_secs * 1000)
}

pub(super) fn secret() -> PowSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    PowSecret::new(bytes)
}

pub(super) fn entropy() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    bytes
}

/// Mirrors the browser worker exactly: the worker hashes
/// `challenge + String(nonce)` (UTF-8, decimal nonce) with SHA-256 and
/// checks `difficulty` leading zero NIBBLES of the digest (its hex string
/// therefore starts with `difficulty` '0' chars). It reports the hash as
/// lowercase hex. Single-worker equivalent: startNonce=0, step=1.
pub(super) fn solve_like_worker(chg: &str, dif: u8) -> (u64, String) {
    let mut nonce: u64 = 0;
    loop {
        let digest = Sha256::digest(format!("{chg}{nonce}").as_bytes());
        let ok = (0..usize::from(dif)).all(|i| {
            let byte = digest[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            nibble == 0
        });
        if ok {
            return (nonce, hex::encode(digest));
        }
        nonce += 1;
    }
}

pub(super) fn solved_solution(dif: u8) -> Solution {
    let challenge = mint_challenge(&secret(), dif, at(TIM_UNIX), entropy()).expect("mint");
    let (nonce, hash) = solve_like_worker(&challenge.chg, dif);
    // Field mapping as the client builds its Solution JSON: chg/tim/tag/dif
    // echoed, sol = hash, non = nonce.toString().
    Solution {
        chg: challenge.chg,
        sol: hash,
        non: nonce.to_string(),
        dif,
        tim: challenge.tim,
        tag: challenge.tag,
    }
}
