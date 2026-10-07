use datadeft_magic_link_core::{LookupHmac, NormalizedEmail};
use datadeft_magic_link_service::{
    CommitMagicLinkAuthentication, CommitMagicLinkAuthenticationError, DependencyError,
    MagicLinkAuthenticationCandidate, MagicLinkAuthenticationRepository, UserRecord,
};

struct SmokeRepository;

impl MagicLinkAuthenticationRepository for SmokeRepository {
    async fn find_magic_link_for_authentication(
        &self,
        _selector_lookup_hmac: &LookupHmac,
    ) -> Result<Option<MagicLinkAuthenticationCandidate>, DependencyError> {
        Ok(None)
    }

    async fn find_user_for_authentication(
        &self,
        _email: &NormalizedEmail,
    ) -> Result<Option<UserRecord>, DependencyError> {
        Ok(None)
    }

    async fn commit_magic_link_authentication(
        &self,
        _command: &CommitMagicLinkAuthentication,
    ) -> Result<(), CommitMagicLinkAuthenticationError> {
        Ok(())
    }
}

fn assert_repository_implementation<T: MagicLinkAuthenticationRepository>() {}

#[test]
fn aggregate_repository_public_api_is_implementable() {
    assert_repository_implementation::<SmokeRepository>();
}
