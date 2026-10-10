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
