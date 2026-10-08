//! Request and scanner-safe authentication orchestration.
//!
//! Request-source, network, global, malformed-input, and external-proof admission
//! controls are intentionally outside this service. Magic-link owns only its
//! email/selector limiter domains, user/session transaction, outbox, clock, and
//! randomness policy.

mod commit;
mod flow;
mod limits;
mod request;

use crate::config::MagicLinkServiceConfig;
use crate::error::{DependencyError, MagicLinkFlowError, MagicLinkServiceError};

pub use self::flow::MagicLinkFlowService;
pub use self::request::MagicLinkRequestService;

// Test modules reach helpers through `super::*`.
#[cfg(test)]
use self::commit::*;
#[cfg(test)]
use self::flow::*;

fn validate_config(config: &MagicLinkServiceConfig) -> Result<(), MagicLinkServiceError> {
    config
        .validate()
        .map_err(|_| MagicLinkServiceError::Internal)
}

const fn flow_error(public_error: MagicLinkServiceError) -> MagicLinkFlowError {
    MagicLinkFlowError::from_public_error(public_error)
}

fn map_dependency_error(error: DependencyError) -> MagicLinkServiceError {
    MagicLinkServiceError::from(error)
}

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod confirmation_tests;
#[cfg(test)]
mod landing_tests;
#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod test_support;
