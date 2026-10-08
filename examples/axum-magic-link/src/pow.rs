//! Proof-of-work admission: challenge route, solution check, and the replay set.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use datadeft_magic_link_service::DependencyError;
use datadeft_pow_core::{Challenge, Solution, mint_challenge, verify_solution};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::state::*;
use super::util::*;
use super::*;

pub(super) async fn pow_challenge(
    State(state): State<AppState>,
) -> Result<Json<PowChallengeJson>, (StatusCode, &'static str)> {
    let mut entropy = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "randomness unavailable\n"))?;
    let now = current_unix_millis()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "clock unavailable\n"))?;
    let challenge = mint_challenge(&state.pow_secret, POW_DIFFICULTY, now, entropy)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "pow unavailable\n"))?;
    Ok(Json(PowChallengeJson::from(challenge)))
}

pub(super) fn verify_pow_solution(
    state: &AppState,
    body: PowSolutionJson,
) -> Result<(), datadeft_pow_core::PowError> {
    let now = current_unix_millis().map_err(|_| datadeft_pow_core::PowError::InvalidTimestamp)?;
    let verified = verify_solution(
        &state.pow_secret,
        &body.into_solution(),
        now,
        POW_CHALLENGE_TTL_SECS,
        POW_DIFFICULTY,
    )?;
    // The replay table keeps whole-second bookkeeping.
    let now_unix = now.as_secs();
    let expires_at_unix = now_unix
        .checked_add(POW_CHALLENGE_TTL_SECS)
        .ok_or(datadeft_pow_core::PowError::InvalidTimestamp)?;
    consume_pow_tid(&state.pow_replay, &verified.tid, now_unix, expires_at_unix)
        .map_err(|_| datadeft_pow_core::PowError::InvalidSolution)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub(super) struct PowChallengeJson {
    pub(super) chg: String,
    pub(super) dif: u8,
    pub(super) tim: String,
    pub(super) tag: String,
}

impl From<Challenge> for PowChallengeJson {
    fn from(value: Challenge) -> Self {
        Self {
            chg: value.chg,
            dif: value.dif,
            tim: value.tim,
            tag: value.tag,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PowSolutionJson {
    pub(super) chg: String,
    pub(super) sol: String,
    pub(super) non: String,
    pub(super) dif: u8,
    pub(super) tim: String,
    pub(super) tag: String,
}

impl PowSolutionJson {
    pub(super) fn into_solution(self) -> Solution {
        Solution {
            chg: self.chg,
            sol: self.sol,
            non: self.non,
            dif: self.dif,
            tim: self.tim,
            tag: self.tag,
        }
    }
}

/// Single-use PoW proof enforcement: reject a tid that was already spent and
/// drop expired entries.
pub(super) fn consume_pow_tid(
    replay: &Mutex<HashMap<String, u64>>,
    tid: &str,
    now_unix: u64,
    expires_at_unix: u64,
) -> Result<(), DependencyError> {
    let mut tids = replay.lock().map_err(|_| DependencyError::Internal)?;
    tids.retain(|_, expires_at| *expires_at > now_unix);
    if tids.contains_key(tid) {
        return Err(DependencyError::ConditionalWriteFailed);
    }
    tids.insert(tid.to_owned(), expires_at_unix);
    Ok(())
}
