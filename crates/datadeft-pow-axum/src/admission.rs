//! Per-request proof admission with the per-solve budget (CeleraTax #8).
//!
//! [`admit_proof`] reads the `dd_pow` cookie, verifies it, and spends one unit
//! of its solve's budget in the shared [`ProofBudget`] store. A solve buys
//! [`ProofBudgetPolicy::per_solve`] admissions over its whole lifetime,
//! across every node (`spec/tla/PowBudget.tla`).

use core::fmt;

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use datadeft_auth_token_core::cookie_header::select_cookie;
use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_pow_core::{
    PowProofCookie, ProofBudget, ProofBudgetDecision, verify_pow_proof_cookie_with_clock_skew,
};

use crate::cookie::PowProofCookieConfig;
use crate::handlers::PowPolicy;
use crate::response::{pow_required_response, unavailable_response};

/// Largest accepted per-solve budget.
pub const MAX_PROOF_BUDGET_PER_SOLVE: u32 = 1_000;

/// How many admissions one solve buys.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProofBudgetPolicy {
    per_solve: u32,
}

impl ProofBudgetPolicy {
    /// `per_solve` must be in `1..=MAX_PROOF_BUDGET_PER_SOLVE`.
    pub fn new(per_solve: u32) -> Result<Self, ProofBudgetPolicyError> {
        if (1..=MAX_PROOF_BUDGET_PER_SOLVE).contains(&per_solve) {
            Ok(Self { per_solve })
        } else {
            Err(ProofBudgetPolicyError)
        }
    }

    /// Admissions per solve.
    #[must_use]
    pub fn per_solve(&self) -> u32 {
        self.per_solve
    }
}

/// The per-solve budget is outside `1..=MAX_PROOF_BUDGET_PER_SOLVE`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProofBudgetPolicyError;

impl fmt::Display for ProofBudgetPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("per-solve budget must be in 1..=MAX_PROOF_BUDGET_PER_SOLVE")
    }
}

impl std::error::Error for ProofBudgetPolicyError {}

/// A request admitted by its proof: one unit of the solve's budget spent.
#[derive(Clone, Eq, PartialEq)]
pub struct AdmittedProof {
    tid: String,
    solve_class: Option<u8>,
}

impl AdmittedProof {
    /// The solve identity (64 lowercase hex), for metrics and further keyed
    /// limits. An identity, not a capability.
    #[must_use]
    pub fn tid(&self) -> &str {
        &self.tid
    }

    /// The authenticated solve-class byte, if the cookie carries one.
    #[must_use]
    pub fn solve_class(&self) -> Option<u8> {
        self.solve_class
    }
}

impl fmt::Debug for AdmittedProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmittedProof(..)")
    }
}

/// Why [`admit_proof`] refused a request: the typed reason, with
/// [`Self::reason`] as its stable label for logs and metrics. The public
/// response ([`IntoResponse`]) never says which it was beyond `401` versus
/// `503`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProofRejection {
    /// No usable proof cookie: missing, malformed, duplicated, forged, or
    /// expired. Answers `401` + `WWW-Authenticate: DD-PoW`.
    ProofRequired,
    /// The solve's budget is used up. Answers the constant `503`.
    BudgetExhausted,
    /// The budget store or the configuration failed. Fails closed with the
    /// constant `503`.
    Unavailable,
}

impl ProofRejection {
    /// Stable internal reason code for logs and metrics, never sent to the
    /// client.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::ProofRequired => "pow_proof_required",
            Self::BudgetExhausted => "pow_budget_exhausted",
            Self::Unavailable => "pow_budget_unavailable",
        }
    }
}

impl IntoResponse for ProofRejection {
    fn into_response(self) -> Response {
        match self {
            Self::ProofRequired => pow_required_response(),
            Self::BudgetExhausted | Self::Unavailable => unavailable_response(),
        }
    }
}

/// Admit a request by its proof cookie and spend one unit of its solve's
/// budget.
///
/// The budget's expiry is fixed at the first spend for a solve, far enough
/// out to cover every proof cookie that solve can produce: a solution can be
/// re-posted while its challenge is valid, so cookies for one solve are
/// issued up to the challenge max age apart, each valid for the cookie TTL,
/// within the clock-skew tolerance either way.
pub async fn admit_proof<B>(
    headers: &HeaderMap,
    keyring: &KeyRing<PowProofCookie>,
    cookie_config: &PowProofCookieConfig,
    policy: PowPolicy,
    budget: ProofBudgetPolicy,
    store: &B,
    now_unix: u64,
) -> Result<AdmittedProof, ProofRejection>
where
    B: ProofBudget,
{
    let value = select_cookie(
        headers.get_all(COOKIE).iter().map(HeaderValue::as_bytes),
        cookie_config.name(),
    )
    .map_err(|_| ProofRejection::ProofRequired)?;
    let verified = verify_pow_proof_cookie_with_clock_skew(
        value,
        keyring,
        now_unix,
        cookie_config.ttl_secs(),
        policy.clock_skew_secs(),
    )
    .map_err(|error| match error {
        datadeft_auth_token_core::TokenError::InvalidTimestamp => ProofRejection::Unavailable,
        _ => ProofRejection::ProofRequired,
    })?;
    let expires_at_unix = budget_expiry(cookie_config, policy, now_unix);
    match store
        .spend(
            verified.tid(),
            budget.per_solve(),
            expires_at_unix,
            now_unix,
        )
        .await
    {
        Ok(ProofBudgetDecision::Spent) => Ok(AdmittedProof {
            tid: verified.tid().to_owned(),
            solve_class: verified.solve_class(),
        }),
        Ok(ProofBudgetDecision::Exhausted) => Err(ProofRejection::BudgetExhausted),
        Err(_) => Err(ProofRejection::Unavailable),
    }
}

fn budget_expiry(cookie_config: &PowProofCookieConfig, policy: PowPolicy, now_unix: u64) -> u64 {
    now_unix
        .saturating_add(cookie_config.ttl_secs())
        .saturating_add(policy.challenge_max_age_secs())
        .saturating_add(policy.clock_skew_secs().saturating_mul(2))
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
