//! Millisecond-resolution injected clock value.

/// Milliseconds since the Unix epoch, as injected by the caller.
///
/// The PoW freshness window and the mint→verify timing signal both need
/// sub-second resolution: a native solver finishes a low-difficulty challenge
/// in tens of milliseconds while a browser worker takes seconds, and a
/// whole-seconds clock quantizes away exactly the band that separates the two
/// populations. The dedicated type makes the unit part of the signature: a
/// caller still holding seconds fails to compile instead of silently passing
/// values off by a factor of a thousand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(u64);

impl UnixMillis {
    /// Wrap a raw milliseconds-since-epoch count.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whole seconds since the Unix epoch, truncating the sub-second part.
    /// This is the value to hand to seconds-resolution APIs such as the
    /// proof-cookie mint.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }
}
