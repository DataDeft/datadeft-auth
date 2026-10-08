//! Fixed-window rate-limit bucketing shared by the DynamoDB adapter and the
//! in-memory fake, so both agree on window boundaries.

/// Index of the fixed rate-limit window containing `now_unix`. A zero-second
/// window degenerates to a single bucket.
pub(crate) fn fixed_window_index(now_unix: u64, window_secs: u64) -> u64 {
    now_unix.checked_div(window_secs).unwrap_or(0)
}
