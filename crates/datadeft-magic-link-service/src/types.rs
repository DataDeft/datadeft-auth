//! Framework-neutral service types.

mod ids;
mod messages;
mod records;

// The session-cookie purpose lives with the session-cookie framing in
// `session_body`. This module re-exports it here so `types::SessionCookie`
// paths keep working.
pub use crate::session_body::{
    DEFAULT_SESSION_ABSOLUTE_SECS, DEFAULT_SESSION_IDLE_SECS, HKDF_INFO_SESSION_COOKIE_V1,
    SessionCookie, TOKEN_TYPE_SESSION_COOKIE_V1,
};

pub use self::ids::*;
pub use self::messages::*;
pub use self::records::*;

/// Default magic-link bearer token lifetime: 10 minutes.
pub const DEFAULT_MAGIC_LINK_TTL_SECS: u64 = 10 * 60;
/// Conservative resource cap applied before parsing an untrusted raw magic-link token.
pub const MAX_RAW_MAGIC_LINK_TOKEN_BYTES: usize = 512;

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
