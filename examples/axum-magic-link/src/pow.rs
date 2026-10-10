//! Proof-of-work admission through `datadeft-pow-axum`: the challenge and
//! validate routes, and the per-solve budget over the shared limiter.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use datadeft_magic_link_aws::FakeDynamoDbAuthStore;
use datadeft_magic_link_axum::{APPLICATION_JSON, MagicLinkHttpError, guarded_body};
use datadeft_magic_link_service::{RateLimitDecision, RateLimitKey, RateLimiter};
use datadeft_pow_axum::{
    PowFlowError, PowSolutionRequest, ProofBudget, ProofBudgetDecision, ProofBudgetUnavailable,
    mint_pow_challenge, verify_pow_solution,
};
use rand_core::{OsRng, RngCore};

use super::state::AppState;
use super::util::current_unix_millis;

/// `POST /auth/pow/create`: a fresh challenge.
pub(super) async fn pow_create(State(state): State<AppState>) -> Response {
    let mut entropy = [0_u8; 16];
    if OsRng.try_fill_bytes(&mut entropy).is_err() {
        return PowFlowError::Internal.into_response();
    }
    let Ok(now) = current_unix_millis() else {
        return PowFlowError::Internal.into_response();
    };
    match mint_pow_challenge(&state.pow_secret, state.pow_policy, now, entropy) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(error) => error.into_response(),
    }
}

/// `POST /auth/pow/validate`: verify a solution and set the `dd_pow` cookie.
/// A failed solution answers `401` + `WWW-Authenticate: DD-PoW`.
pub(super) async fn pow_validate(State(state): State<AppState>, request: Request) -> Response {
    let guarded = match guarded_body(request, &[APPLICATION_JSON], 1024).await {
        Ok(guarded) => guarded,
        Err(error) => return error.into_response(),
    };
    let Ok(solution) = serde_json::from_slice::<PowSolutionRequest>(&guarded.bytes) else {
        return MagicLinkHttpError::BadRequest.into_response();
    };
    let Ok(now) = current_unix_millis() else {
        return PowFlowError::Internal.into_response();
    };
    match verify_pow_solution(
        &state.pow_secret,
        state.pow_policy,
        &solution,
        &state.pow_proof_keyring,
        &state.pow_cookie,
        &mut OsRng,
        now,
        |_| None,
    ) {
        Ok(admission) => {
            (StatusCode::NO_CONTENT, [(SET_COOKIE, admission.set_cookie)]).into_response()
        }
        Err(error) => error.into_response(),
    }
}

/// The per-solve budget over the shared limiter's lifetime counter
/// (docs/integration.md, "Per-solve budget"). With DynamoDB, the same few
/// lines run over `DynamoDbAuthStore`.
pub(super) struct SharedProofBudget<'a>(pub(super) &'a FakeDynamoDbAuthStore);

impl ProofBudget for SharedProofBudget<'_> {
    async fn spend(
        &self,
        tid: &str,
        per_solve: u32,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<ProofBudgetDecision, ProofBudgetUnavailable> {
        let key = RateLimitKey::parse(&format!("pow:budget:{tid}"))
            .map_err(|_| ProofBudgetUnavailable)?;
        match self
            .0
            .check_lifetime_limit(&key, per_solve, expires_at_unix, now_unix)
            .await
        {
            Ok(RateLimitDecision::Allowed) => Ok(ProofBudgetDecision::Spent),
            Ok(RateLimitDecision::Denied) => Ok(ProofBudgetDecision::Exhausted),
            Err(_) => Err(ProofBudgetUnavailable),
        }
    }
}
