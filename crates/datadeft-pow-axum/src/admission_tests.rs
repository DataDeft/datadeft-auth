//! Per-solve budget admission: N admissions per solve, then 503; no proof,
//! 401 + DD-PoW; a failing store fails closed.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use datadeft_auth_token_core::test_support::{PerCallRng, test_keyring};
use datadeft_pow_core::{ProofBudgetUnavailable, mint_pow_proof_cookie};

use super::*;
use crate::handlers::{DEFAULT_POW_CHALLENGE_MAX_AGE_SECS, PowFlowError};

const NOW: u64 = 1_783_598_400;
const TID: &str = "0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000";

/// A shared counter with the required semantics: the first spend fixes the
/// expiry, the count never resets.
#[derive(Default)]
struct MemoryBudget {
    counts: Mutex<HashMap<String, (u32, u64)>>,
    fail: bool,
}

impl ProofBudget for MemoryBudget {
    async fn spend(
        &self,
        tid: &str,
        per_solve: u32,
        expires_at_unix: u64,
        _now_unix: u64,
    ) -> Result<ProofBudgetDecision, ProofBudgetUnavailable> {
        if self.fail {
            return Err(ProofBudgetUnavailable);
        }
        let mut counts = self.counts.lock().map_err(|_| ProofBudgetUnavailable)?;
        let (count, _) = counts.entry(tid.to_owned()).or_insert((0, expires_at_unix));
        if *count >= per_solve {
            return Ok(ProofBudgetDecision::Exhausted);
        }
        *count += 1;
        Ok(ProofBudgetDecision::Spent)
    }
}

fn keyring() -> KeyRing<PowProofCookie> {
    test_keyring::<PowProofCookie>(0x22, "test-active")
}

fn config() -> PowProofCookieConfig {
    PowProofCookieConfig::secure_defaults()
}

fn policy() -> PowPolicy {
    PowPolicy::new(1, DEFAULT_POW_CHALLENGE_MAX_AGE_SECS).expect("policy")
}

fn headers_with(cookie: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("other=1; dd_pow={cookie}")).expect("header"),
    );
    headers
}

fn proof_cookie(issued_at: u64) -> String {
    let mut rng = PerCallRng::starting_at(7);
    mint_pow_proof_cookie(TID, Some(3), &keyring(), &mut rng, issued_at)
        .expect("mint")
        .as_secret_value()
        .to_owned()
}

async fn admit(
    headers: &HeaderMap,
    store: &MemoryBudget,
    now: u64,
) -> Result<AdmittedProof, ProofRejection> {
    admit_proof(
        headers,
        &keyring(),
        &config(),
        policy(),
        ProofBudgetPolicy::new(3).expect("budget"),
        store,
        now,
    )
    .await
}

#[tokio::test]
async fn a_solve_buys_its_budget_then_answers_503() {
    let store = MemoryBudget::default();
    let headers = headers_with(&proof_cookie(NOW));
    for offset in [0, 60, 3_000] {
        let admitted = admit(&headers, &store, NOW + offset)
            .await
            .expect("admitted");
        assert_eq!(admitted.tid(), TID);
        assert_eq!(admitted.solve_class(), Some(3));
        assert_eq!(format!("{admitted:?}"), "AdmittedProof(..)");
    }
    assert_eq!(
        admit(&headers, &store, NOW + 3_100).await.unwrap_err(),
        ProofRejection::BudgetExhausted
    );
    // A second cookie for the same solve (a re-posted solution) shares the
    // budget: it is keyed on the solve, not the cookie.
    let again = headers_with(&proof_cookie(NOW + 100));
    assert_eq!(
        admit(&again, &store, NOW + 200).await.unwrap_err(),
        ProofRejection::BudgetExhausted
    );
}

#[tokio::test]
async fn the_budget_outlives_every_cookie_of_the_solve() {
    let store = MemoryBudget::default();
    admit(&headers_with(&proof_cookie(NOW)), &store, NOW)
        .await
        .expect("admitted");
    let (_, expires) = store.counts.lock().expect("lock")[TID];
    let latest_cookie_end =
        NOW + DEFAULT_POW_CHALLENGE_MAX_AGE_SECS + config().ttl_secs() + policy().clock_skew_secs();
    assert!(
        expires >= latest_cookie_end,
        "{expires} < {latest_cookie_end}"
    );
}

#[tokio::test]
async fn no_usable_proof_is_401_and_never_spends() {
    let store = MemoryBudget::default();
    let valid = proof_cookie(NOW);
    let mut tampered = valid.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ascii");
    let mut duplicate = HeaderMap::new();
    duplicate.append(
        COOKIE,
        HeaderValue::from_str(&format!("dd_pow={valid}")).expect("h"),
    );
    duplicate.append(
        COOKIE,
        HeaderValue::from_str(&format!("dd_pow={valid}")).expect("h"),
    );

    for (name, headers, now) in [
        ("missing", HeaderMap::new(), NOW),
        ("tampered", headers_with(&tampered), NOW),
        ("duplicated", duplicate, NOW),
        (
            "expired",
            headers_with(&valid),
            NOW + config().ttl_secs() + 1,
        ),
    ] {
        assert_eq!(
            admit(&headers, &store, now).await.unwrap_err(),
            ProofRejection::ProofRequired,
            "{name}"
        );
    }
    assert!(store.counts.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_failing_store_fails_closed() {
    let store = MemoryBudget {
        fail: true,
        ..MemoryBudget::default()
    };
    assert_eq!(
        admit(&headers_with(&proof_cookie(NOW)), &store, NOW)
            .await
            .unwrap_err(),
        ProofRejection::Unavailable
    );
}

#[tokio::test]
async fn rejections_render_the_public_contract() {
    let required = ProofRejection::ProofRequired.into_response();
    assert_eq!(required.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        required.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("DD-PoW"))
    );

    // Exhausted and unavailable are indistinguishable from outside.
    let mut bodies = Vec::new();
    for rejection in [ProofRejection::BudgetExhausted, ProofRejection::Unavailable] {
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(WWW_AUTHENTICATE), None);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        bodies.push((headers, body));
    }
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(
        bodies[0].1.as_ref(),
        br#"{"error":"unavailable","message":"The service is temporarily unavailable. Try again later."}"#
    );
    assert_ne!(
        ProofRejection::BudgetExhausted.reason(),
        ProofRejection::Unavailable.reason()
    );
}

#[test]
fn budget_policy_is_bounded() {
    assert!(ProofBudgetPolicy::new(0).is_err());
    assert!(ProofBudgetPolicy::new(MAX_PROOF_BUDGET_PER_SOLVE + 1).is_err());
    assert_eq!(ProofBudgetPolicy::new(5).expect("valid").per_solve(), 5);
}

#[tokio::test]
async fn solution_rejections_render_the_same_contract() {
    let rejected = PowFlowError::Rejected.into_response();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("DD-PoW"))
    );
    let internal = PowFlowError::Internal.into_response();
    assert_eq!(internal.status(), StatusCode::SERVICE_UNAVAILABLE);
    let internal = to_bytes(internal.into_body(), 1024).await.expect("body");
    let exhausted = to_bytes(
        ProofRejection::BudgetExhausted.into_response().into_body(),
        1024,
    )
    .await
    .expect("body");
    assert_eq!(internal, exhausted);
}
