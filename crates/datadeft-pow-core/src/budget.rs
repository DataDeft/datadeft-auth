//! Per-solve admission budget.
//!
//! One solved challenge (one [`crate::Verified::tid`]) buys a bounded number
//! of admissions over the proof's whole lifetime, across every node. The
//! counting store is the caller's: implement [`ProofBudget`] over a shared
//! counter (for example `RateLimiter::check_lifetime_limit` in
//! datadeft-magic-link-service). The rules, checked in `spec/tla/PowBudget.tla`:
//!
//! - **Shared:** one counter per `tid` for the whole deployment, not one per
//!   node.
//! - **Over the lifetime:** the first spend fixes the counter's expiry and it
//!   never refills before then, whatever window the clock is in.
//! - **Fail closed:** a store failure is an error, never an admission.

use core::fmt;
use core::future::Future;

/// Outcome of spending one unit of a solve's budget.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProofBudgetDecision {
    /// One unit was spent; admit the request.
    Spent,
    /// The solve's budget is used up.
    Exhausted,
}

/// The budget store failed. The caller must refuse the request.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProofBudgetUnavailable;

impl fmt::Display for ProofBudgetUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proof budget store unavailable")
    }
}

impl std::error::Error for ProofBudgetUnavailable {}

/// Shared counter behind the per-solve budget.
pub trait ProofBudget {
    /// Spend one unit of `tid`'s budget of `per_solve` admissions. The first
    /// spend for a `tid` fixes its expiry at `expires_at_unix`; until then the
    /// count never resets. Return [`ProofBudgetUnavailable`] when the store
    /// fails, never `Spent`.
    fn spend(
        &self,
        tid: &str,
        per_solve: u32,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> impl Future<Output = Result<ProofBudgetDecision, ProofBudgetUnavailable>> + Send;
}

/// Largest accepted per-solve budget: beyond this the gate stops gating.
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

/// The one counter-key shape for a solve's budget, shared by every adapter
/// so the budget stays one deployment-wide counter per `tid`.
#[must_use]
pub fn proof_budget_key(tid: &str) -> String {
    format!("pow:budget:{tid}")
}

/// Expiry of a solve's budget counter, fixed at the first spend: far enough
/// out to cover every proof cookie the solve can produce. A solution can be
/// re-posted while its challenge is valid, so cookies for one solve are
/// issued up to the challenge max age apart, each valid for the proof TTL,
/// within the clock-skew tolerance either way.
#[must_use]
pub fn proof_budget_expiry(
    now_unix: u64,
    proof_ttl_secs: u64,
    challenge_max_age_secs: u64,
    clock_skew_secs: u64,
) -> u64 {
    now_unix
        .saturating_add(proof_ttl_secs)
        .saturating_add(challenge_max_age_secs)
        .saturating_add(clock_skew_secs.saturating_mul(2))
}
