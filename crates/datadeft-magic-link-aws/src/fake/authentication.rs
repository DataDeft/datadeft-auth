//! The fake magic-link authentication repository: candidate reads and the atomic commit.

use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError, LookupHmac,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository,
    MagicLinkAuthenticationUser, NormalizedEmail, SessionRecord, UserRecord,
};

use crate::hmac_key::EMAIL_LOOKUP_HMAC_PREFIX;

use super::*;

impl MagicLinkAuthenticationRepository for FakeDynamoDbAuthStore {
    async fn find_magic_link_for_authentication(
        &self,
        selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        Ok(inner
            .magic_links_by_selector_hmac
            .get(selector_lookup_hmac.as_storage_value())
            .map(|record| MagicLinkAuthenticationCandidate {
                verifier_hash: record.verifier_hash.clone(),
                email: record.email.clone(),
                expires_at_unix: record.expires_at_unix,
                consumed_at_unix: record.consumed_at_unix,
                terms_version: record.terms_version.clone(),
                privacy_version: record.privacy_version.clone(),
                consented_at_unix: record.consented_at_unix,
            }))
    }

    async fn find_user_for_authentication(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        let mut inner = self.lock_inner()?;
        Self::take_next_error(&mut inner)?;
        let (found_hmac, from_previous) =
            self.resolve_hmac(EMAIL_LOOKUP_HMAC_PREFIX, email.as_str(), |hmac| {
                inner.user_id_by_email_hmac.contains_key(hmac)
            })?;
        if from_previous {
            // Rotation window: migrate the lookup so the commit's condition
            // check sees it under the current key.
            let user_id = inner
                .user_id_by_email_hmac
                .get(&found_hmac)
                .cloned()
                .ok_or(DependencyError::Internal)?;
            inner
                .user_id_by_email_hmac
                .insert(self.email_hmac(email)?, user_id);
        }
        let Some(user_id) = inner.user_id_by_email_hmac.get(&found_hmac) else {
            return Ok(None);
        };
        let user = inner
            .user_profiles_by_id
            .get(user_id.as_str())
            .ok_or(DependencyError::Internal)?;
        if user.email != *email || user.user_id != *user_id {
            return Err(DependencyError::Internal);
        }
        Ok(Some(user.clone()))
    }

    async fn commit_magic_link_authentication(
        &self,
        command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        if command.session_expires_at_unix < command.now_unix {
            return Err(CommitMagicLinkAuthenticationError::Internal);
        }
        let session_hmac = self
            .session_hmac(&command.session_id)
            .map_err(|_| CommitMagicLinkAuthenticationError::Internal)?;
        let email_hmac = self
            .email_hmac(&command.magic_link.email)
            .map_err(|_| CommitMagicLinkAuthenticationError::Internal)?;
        let mut inner = self
            .lock_inner()
            .map_err(|_| CommitMagicLinkAuthenticationError::Internal)?;

        if let Some(previous) = inner
            .authentication_attempts
            .get(command.attempt_id.as_str())
        {
            return if previous == command {
                Ok(())
            } else {
                Err(CommitMagicLinkAuthenticationError::Internal)
            };
        }
        if let Some(error) = inner.next_error.take() {
            return Err(Self::authentication_error(error));
        }

        #[cfg(test)]
        if let Some(user_id) = inner.disable_user_before_next_commit.take() {
            let profile = inner
                .user_profiles_by_id
                .get_mut(&user_id)
                .ok_or(CommitMagicLinkAuthenticationError::Internal)?;
            profile.disabled = true;
        }

        let challenge = inner
            .magic_links_by_selector_hmac
            .get(command.magic_link.selector_lookup_hmac.as_storage_value())
            .ok_or(CommitMagicLinkAuthenticationError::Rejected)?;
        if challenge.consumed_at_unix.is_some()
            || challenge.expires_at_unix != command.magic_link.expires_at_unix
            || challenge.expires_at_unix < command.now_unix
            || challenge.email != command.magic_link.email
            || challenge.terms_version != command.magic_link.terms_version
            || challenge.privacy_version != command.magic_link.privacy_version
            || challenge.consented_at_unix != command.magic_link.consented_at_unix
            || challenge.consented_at_unix == 0
        {
            return Err(CommitMagicLinkAuthenticationError::Rejected);
        }

        let user_id = match &command.user {
            MagicLinkAuthenticationUser::Existing { user_id } => {
                let linked_user_id = inner
                    .user_id_by_email_hmac
                    .get(&email_hmac)
                    .ok_or(CommitMagicLinkAuthenticationError::UserConflict)?;
                let profile = inner
                    .user_profiles_by_id
                    .get(user_id.as_str())
                    .ok_or(CommitMagicLinkAuthenticationError::UserConflict)?;
                if linked_user_id != user_id
                    || profile.user_id != *user_id
                    || profile.email != command.magic_link.email
                    || profile.disabled
                {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                user_id.clone()
            }
            MagicLinkAuthenticationUser::Create { user_id } => {
                if inner.user_id_by_email_hmac.contains_key(&email_hmac)
                    || inner.user_profiles_by_id.contains_key(user_id.as_str())
                {
                    return Err(CommitMagicLinkAuthenticationError::UserConflict);
                }
                user_id.clone()
            }
        };

        let index_sk = format!("SESSION#{}#{session_hmac}", command.now_unix);
        if inner.sessions_by_hmac.contains_key(&session_hmac)
            || inner
                .user_session_index
                .get(user_id.as_str())
                .is_some_and(|entries| entries.iter().any(|entry| entry.sk == index_sk))
        {
            return Err(CommitMagicLinkAuthenticationError::SessionConflict);
        }

        #[cfg(test)]
        if core::mem::take(&mut inner.fail_next_authentication_pre_commit) {
            return Err(CommitMagicLinkAuthenticationError::DependencyUnavailable);
        }

        let session = SessionRecord {
            session_id: command.session_id.clone(),
            user_id: user_id.clone(),
            email: command.magic_link.email.clone(),
            created_at_unix: command.now_unix,
            revoked_at_unix: None,
        };
        if matches!(command.user, MagicLinkAuthenticationUser::Create { .. }) {
            let user = UserRecord {
                user_id: user_id.clone(),
                email: command.magic_link.email.clone(),
                disabled: false,
                terms_version: Some(command.magic_link.terms_version.clone()),
                privacy_version: Some(command.magic_link.privacy_version.clone()),
                consented_at_unix: Some(command.magic_link.consented_at_unix),
            };
            inner
                .user_id_by_email_hmac
                .insert(email_hmac, user_id.clone());
            inner
                .user_profiles_by_id
                .insert(user_id.as_str().to_owned(), user);
        }
        let challenge = inner
            .magic_links_by_selector_hmac
            .get_mut(command.magic_link.selector_lookup_hmac.as_storage_value())
            .ok_or(CommitMagicLinkAuthenticationError::Internal)?;
        challenge.consumed_at_unix = Some(command.now_unix);
        inner
            .user_session_index
            .entry(user_id.as_str().to_owned())
            .or_default()
            .push(UserSessionIndexEntry {
                sk: index_sk,
                created_at_unix: command.now_unix,
                expires_at_unix: command.session_expires_at_unix,
            });
        inner.sessions_by_hmac.insert(
            session_hmac,
            StoredSession {
                record: session,
                expires_at_unix: command.session_expires_at_unix,
                revoked_by: None,
            },
        );
        inner
            .authentication_attempts
            .insert(command.attempt_id.as_str().to_owned(), command.clone());
        Ok(())
    }
}
