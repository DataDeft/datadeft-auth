//! Admin queries and mutations for account and session management.
//!
//! Consuming projects build their own admin UI and endpoints on top of
//! [`AuthAdminService`]. The library provides the data and the mutations; who
//! counts as an admin is the application's decision.
//!
//! Nothing is deleted. Revoking a session and disabling a user are status
//! changes, and every mutation appends an [`AdminEvent`] in the same atomic
//! write as the change itself, so the audit trail cannot miss an action.
//! Ending a session is final; users can be disabled and enabled again.

mod repository;
mod service;
mod types;

pub use self::repository::*;
pub use self::service::*;
pub use self::types::*;

/// Longest accepted [`AdminActor`] id, in bytes.
pub const MAX_ADMIN_ACTOR_ID_BYTES: usize = 128;
/// Longest accepted [`AdminActor`] reason, in bytes.
pub const MAX_ADMIN_REASON_BYTES: usize = 512;
/// Largest page any admin listing returns.
pub const MAX_ADMIN_PAGE_SIZE: u32 = 100;
/// Longest accepted [`PageCursor`], in bytes.
pub const MAX_PAGE_CURSOR_BYTES: usize = 1024;

const SESSION_HANDLE_PREFIX: &str = "sih_";
const SESSION_HANDLE_HEX_LEN: usize = 64;
const SESSION_DISPLAY_HEX_LEN: usize = 8;
const ADMIN_EVENT_ID_PREFIX: &str = "evt_";
const ADMIN_EVENT_ID_BYTES: usize = 16;

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
