//! The atomic authentication commit: user and session planning, retries, cookies, ids.

use datadeft_auth_token_core::cookie::mint_bound_cookie;
use datadeft_auth_token_core::keyring::KeyRing;
use datadeft_magic_link_core::confirm_cookie::VerifiedMagicLinkConfirm;
use datadeft_magic_link_core::{
    LookupHmac, LookupHmacKey, VerifierHash, confirm_account_binding, email_lookup_hmac,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::config::MagicLinkServiceConfig;
use crate::error::{CommitMagicLinkAuthenticationError, MagicLinkServiceError};
use crate::session_body::encode_session_cookie_body;
use crate::traits::MagicLinkAuthenticationRepository;
use crate::types::{
    AuthenticationAttemptId, CommitMagicLinkAuthentication, MagicLinkAuthenticationCandidate,
    MagicLinkAuthenticationExpectation, MagicLinkAuthenticationOutcome,
    MagicLinkAuthenticationUser, SessionCookie, SessionId, UserId, UserRecord, validate_country,
};

use super::flow::*;
use super::*;

pub(super) async fn load_scanner_authentication_state<
    Authentication: MagicLinkAuthenticationRepository,
>(
    authentication: &Authentication,
    lookup_hmac_key: &LookupHmacKey,
    config: &MagicLinkServiceConfig,
    selector_lookup: &LookupHmac,
    presented_verifier_hash: &VerifierHash,
    expected_account: &datadeft_magic_link_core::confirm_cookie::ConfirmAccountBinding,
    now_unix: u64,
) -> Result<(MagicLinkAuthenticationCandidate, Option<UserRecord>), MagicLinkServiceError> {
    let candidate = authentication
        .find_magic_link_for_authentication(selector_lookup)
        .await
        .map_err(map_dependency_error)?;
    let candidate = compare_candidate_verifier(candidate, presented_verifier_hash)?;
    let email_lookup = email_lookup_hmac(lookup_hmac_key, &candidate.email)
        .map_err(|_| MagicLinkServiceError::Internal)?;
    let candidate_account =
        confirm_account_binding(&email_lookup).map_err(|_| MagicLinkServiceError::Internal)?;
    if !expected_account.matches_constant_time(&candidate_account) {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    }
    validate_scanner_candidate_state(config, &candidate, now_unix)?;
    let user = authentication
        .find_user_for_authentication(&candidate.email)
        .await
        .map_err(map_dependency_error)?;
    Ok((candidate, user))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn authenticate_scanner_flow<Authentication, Rng>(
    authentication: &Authentication,
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    lookup_hmac_key: &LookupHmacKey,
    config: &MagicLinkServiceConfig,
    selector_lookup: &LookupHmac,
    presented_verifier_hash: &VerifierHash,
    verified: &VerifiedMagicLinkConfirm,
    now_unix: u64,
    country: Option<String>,
) -> Result<MagicLinkAuthenticationOutcome, MagicLinkServiceError>
where
    Authentication: MagicLinkAuthenticationRepository,
    Rng: RngCore + CryptoRng,
{
    let (candidate, user) = load_scanner_authentication_state(
        authentication,
        lookup_hmac_key,
        config,
        selector_lookup,
        presented_verifier_hash,
        verified.account(),
        now_unix,
    )
    .await?;
    let user_branch = plan_user(user, &candidate.email, rng)?;
    let expectation = authentication_expectation(selector_lookup, &candidate);
    let mut plan = build_initial_authentication_plan(
        session_keyring,
        rng,
        expectation,
        user_branch,
        now_unix,
        config.session_absolute_secs,
        country.as_deref(),
    )?;

    let mut replans = 0_u8;
    loop {
        match commit_with_dependency_retries(authentication, &plan.command).await {
            Ok(()) => {
                let session_cookie = core::mem::take(&mut *plan.session_cookie);
                let (user_id, user_created) = user_outcome(&plan.command.user);
                return Ok(MagicLinkAuthenticationOutcome {
                    session_cookie,
                    user_id,
                    session_id: plan.command.session_id.clone(),
                    user_created,
                    country,
                });
            }
            Err(CommitMagicLinkAuthenticationError::Rejected) => {
                return Err(MagicLinkServiceError::MagicLinkUnavailable);
            }
            Err(CommitMagicLinkAuthenticationError::Internal) => {
                return Err(MagicLinkServiceError::Internal);
            }
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable) => {
                return Err(MagicLinkServiceError::Unavailable);
            }
            Err(CommitMagicLinkAuthenticationError::UserConflict) => {
                if replans >= 2 {
                    return Err(MagicLinkServiceError::Unavailable);
                }
                replans += 1;
                let (candidate, user) = load_scanner_authentication_state(
                    authentication,
                    lookup_hmac_key,
                    config,
                    selector_lookup,
                    presented_verifier_hash,
                    verified.account(),
                    now_unix,
                )
                .await?;
                plan.command.magic_link = authentication_expectation(selector_lookup, &candidate);
                plan.command.user = plan_user(user, &candidate.email, rng)?;
                plan.command.attempt_id = generate_authentication_attempt_id(rng)?;
            }
            Err(CommitMagicLinkAuthenticationError::SessionConflict) => {
                if replans >= 2 {
                    return Err(MagicLinkServiceError::Unavailable);
                }
                replans += 1;
                replace_session_plan(
                    &mut plan,
                    session_keyring,
                    rng,
                    now_unix,
                    config.session_absolute_secs,
                    country.as_deref(),
                )?;
            }
        }
    }
}

pub(super) fn mint_country(
    config: &MagicLinkServiceConfig,
    country: Option<&str>,
) -> Result<Option<String>, MagicLinkServiceError> {
    if !config.enforce_country {
        return Ok(country.map(str::to_owned));
    }
    let Some(country) = country else {
        return Err(MagicLinkServiceError::MagicLinkUnavailable);
    };
    validate_country(country)?;
    Ok(Some(country.to_owned()))
}

pub(super) struct AuthenticationPlan {
    pub(super) command: CommitMagicLinkAuthentication,
    pub(super) session_cookie: Zeroizing<String>,
}

pub(super) fn plan_user<Rng: RngCore + CryptoRng + ?Sized>(
    user: Option<UserRecord>,
    expected_email: &datadeft_magic_link_core::NormalizedEmail,
    rng: &mut Rng,
) -> Result<MagicLinkAuthenticationUser, MagicLinkServiceError> {
    if let Some(user) = user {
        if user.email != *expected_email || user.disabled {
            return Err(MagicLinkServiceError::MagicLinkUnavailable);
        }
        return Ok(MagicLinkAuthenticationUser::Existing {
            user_id: user.user_id,
        });
    }

    Ok(MagicLinkAuthenticationUser::Create {
        user_id: generate_user_id(rng)?,
    })
}

/// The user id and whether the account was created, derived from the planned
/// user branch: the single source of truth, so no parallel state can drift.
pub(super) fn user_outcome(user: &MagicLinkAuthenticationUser) -> (UserId, bool) {
    match user {
        MagicLinkAuthenticationUser::Existing { user_id } => (user_id.clone(), false),
        MagicLinkAuthenticationUser::Create { user_id } => (user_id.clone(), true),
    }
}

pub(super) fn authentication_expectation(
    selector_lookup: &LookupHmac,
    candidate: &MagicLinkAuthenticationCandidate,
) -> MagicLinkAuthenticationExpectation {
    MagicLinkAuthenticationExpectation {
        selector_lookup_hmac: selector_lookup.clone(),
        email: candidate.email.clone(),
        expires_at_unix: candidate.expires_at_unix,
        terms_version: candidate.terms_version.clone(),
        privacy_version: candidate.privacy_version.clone(),
        consented_at_unix: candidate.consented_at_unix,
    }
}

/// Freshly generated per-attempt session material, shared by the initial plan
/// and every SessionConflict replan so the two paths cannot drift.
pub(super) struct SessionPlanParts {
    pub(super) session_id: SessionId,
    pub(super) session_expires_at_unix: u64,
    pub(super) session_cookie: Zeroizing<String>,
    pub(super) attempt_id: AuthenticationAttemptId,
}

pub(super) fn new_session_plan_parts<Rng: RngCore + CryptoRng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<SessionPlanParts, MagicLinkServiceError> {
    let session_id = generate_session_id(rng)?;
    let session_expires_at_unix = now_unix
        .checked_add(session_absolute_secs)
        .ok_or(MagicLinkServiceError::Internal)?;
    let session_cookie = Zeroizing::new(mint_session_cookie(
        session_keyring,
        rng,
        &session_id,
        now_unix,
        country,
    )?);
    let attempt_id = generate_authentication_attempt_id(rng)?;
    Ok(SessionPlanParts {
        session_id,
        session_expires_at_unix,
        session_cookie,
        attempt_id,
    })
}

pub(super) fn build_initial_authentication_plan<Rng: RngCore + CryptoRng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    magic_link: MagicLinkAuthenticationExpectation,
    user: MagicLinkAuthenticationUser,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<AuthenticationPlan, MagicLinkServiceError> {
    let parts = new_session_plan_parts(
        session_keyring,
        rng,
        now_unix,
        session_absolute_secs,
        country,
    )?;
    Ok(AuthenticationPlan {
        command: CommitMagicLinkAuthentication {
            magic_link,
            now_unix,
            attempt_id: parts.attempt_id,
            user,
            session_id: parts.session_id,
            session_expires_at_unix: parts.session_expires_at_unix,
        },
        session_cookie: parts.session_cookie,
    })
}

pub(super) fn replace_session_plan<Rng: RngCore + CryptoRng>(
    plan: &mut AuthenticationPlan,
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    now_unix: u64,
    session_absolute_secs: u64,
    country: Option<&str>,
) -> Result<(), MagicLinkServiceError> {
    let parts = new_session_plan_parts(
        session_keyring,
        rng,
        now_unix,
        session_absolute_secs,
        country,
    )?;
    plan.command.session_id = parts.session_id;
    plan.command.session_expires_at_unix = parts.session_expires_at_unix;
    plan.command.attempt_id = parts.attempt_id;
    plan.session_cookie = parts.session_cookie;
    Ok(())
}

pub(super) async fn commit_with_dependency_retries<
    Authentication: MagicLinkAuthenticationRepository,
>(
    authentication: &Authentication,
    command: &CommitMagicLinkAuthentication,
) -> Result<(), CommitMagicLinkAuthenticationError> {
    for retry in 0..3 {
        match authentication
            .commit_magic_link_authentication(command)
            .await
        {
            Err(CommitMagicLinkAuthenticationError::DependencyUnavailable) if retry < 2 => {}
            result => return result,
        }
    }
    Err(CommitMagicLinkAuthenticationError::DependencyUnavailable)
}

pub(super) fn mint_session_cookie<Rng>(
    session_keyring: &KeyRing<SessionCookie>,
    rng: &mut Rng,
    session_id: &SessionId,
    now_unix: u64,
    country: Option<&str>,
) -> Result<String, MagicLinkServiceError>
where
    Rng: RngCore + CryptoRng,
{
    let timestamp = u32::try_from(now_unix).map_err(|_| MagicLinkServiceError::Internal)?;
    let body = encode_session_cookie_body(session_id, country)?;
    mint_bound_cookie::<SessionCookie, _>(
        &body,
        session_keyring,
        rng,
        timestamp,
        timestamp,
        now_unix,
    )
    .map_err(MagicLinkServiceError::from)
}

/// Draw `BYTES` random bytes and render `{prefix}_{lowercase hex}`: the
/// canonical id shape the typed wrappers' service-built constructors expect.
pub(super) fn generate_prefixed_hex_id<R: RngCore + CryptoRng + ?Sized, const BYTES: usize>(
    rng: &mut R,
    prefix: &str,
) -> Result<String, MagicLinkServiceError> {
    let mut bytes = [0u8; BYTES];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| MagicLinkServiceError::Unavailable)?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

pub(super) fn generate_user_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<UserId, MagicLinkServiceError> {
    Ok(UserId::from_service_built(
        generate_prefixed_hex_id::<_, 16>(rng, "usr")?,
    ))
}

pub(super) fn generate_session_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<SessionId, MagicLinkServiceError> {
    Ok(SessionId::from_service_built(generate_prefixed_hex_id::<
        _,
        32,
    >(rng, "sid")?))
}

pub(super) fn generate_authentication_attempt_id<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<AuthenticationAttemptId, MagicLinkServiceError> {
    Ok(AuthenticationAttemptId::from_service_built(
        generate_prefixed_hex_id::<_, 16>(rng, "aid")?,
    ))
}
