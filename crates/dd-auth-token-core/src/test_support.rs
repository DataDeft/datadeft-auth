//! Deterministic fixtures shared by the workspace's test suites.
//!
//! Available under `cfg(test)` and the explicit `test-support` feature only.
//! Never use it in default production builds. Deterministic RNGs are test fixtures.
//! Production code must inject an OS-backed CSPRNG (see the crate docs).

use rand_core::{CryptoRng, RngCore};

use crate::keyring::{KEY_BYTES, KeyId, KeyPurpose, KeyRing, KeySlot, RootSecret};

fn test_rng_error() -> rand_core::Error {
    // Any nonzero code will do. Fixtures only need the call to fail.
    rand_core::Error::from(
        core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
            .expect("rand_core custom error code is nonzero"),
    )
}

/// Byte-stream RNG: every drawn byte is the next value of a wrapping `u8`
/// counter, continuous across calls. Optionally fails the nth (1-indexed)
/// `try_fill_bytes` call; `fill_bytes` calls also advance the call counter.
pub struct CountingRng {
    next: u8,
    calls: usize,
    fail_at: Option<usize>,
}

impl CountingRng {
    /// Stream starting at `seed` and never failing.
    #[must_use]
    pub fn starting_at(seed: u8) -> Self {
        Self {
            next: seed,
            calls: 0,
            fail_at: None,
        }
    }

    /// Zero-seeded stream whose nth (1-indexed) `try_fill_bytes` call fails.
    #[must_use]
    pub fn failing_at(call: usize) -> Self {
        Self {
            next: 0,
            calls: 0,
            fail_at: Some(call),
        }
    }

    /// Number of fill calls made so far (both fallible and infallible).
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.calls += 1;
        self.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(test_rng_error());
        }
        self.fill(dest);
        Ok(())
    }
}

impl CryptoRng for CountingRng {}

/// Per-call pattern RNG: each call fills the whole buffer with a single value,
/// starting at `seed` and incrementing once per call.
pub struct PerCallRng {
    value: u8,
}

impl PerCallRng {
    /// First call fills with `seed`, the next with `seed + 1`, and so on.
    #[must_use]
    pub fn starting_at(seed: u8) -> Self {
        Self { value: seed }
    }
}

impl RngCore for PerCallRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.value);
        self.value = self.value.wrapping_add(1);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for PerCallRng {}

/// Fixed-buffer RNG: every fill must request exactly `N` bytes and receives
/// the same fixture bytes (e.g. a pinned Branca nonce).
pub struct FixedBytesRng<const N: usize>(pub [u8; N]);

impl<const N: usize> RngCore for FixedBytesRng<N> {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), N, "fixture expects exactly one N-byte draw");
        dest.copy_from_slice(&self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<const N: usize> CryptoRng for FixedBytesRng<N> {}

/// Fails the given 0-indexed `try_fill_bytes` call; fills `0x5a` otherwise.
pub struct FailOnCallRng {
    calls: usize,
    fail_on: usize,
}

impl FailOnCallRng {
    /// Fail the `call`th (0-indexed) `try_fill_bytes` invocation.
    #[must_use]
    pub fn failing_on(call: usize) -> Self {
        Self {
            calls: 0,
            fail_on: call,
        }
    }
}

impl RngCore for FailOnCallRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.try_fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let call = self.calls;
        self.calls += 1;
        if call == self.fail_on {
            return Err(test_rng_error());
        }
        dest.fill(0x5a);
        Ok(())
    }
}

impl CryptoRng for FailOnCallRng {}

/// Single-active-slot keyring for tests: root `[seed; 32]`, derived for
/// purpose `P` under `kid`, minting until `mint_until_unix` and verifying
/// until `verify_until_unix`.
#[must_use]
pub fn test_keyring_with_windows<P: KeyPurpose>(
    seed: u8,
    kid: &str,
    mint_until_unix: u64,
    verify_until_unix: u64,
) -> KeyRing<P> {
    let kid = KeyId::parse(kid).expect("test kid parses");
    let key = RootSecret::new([seed; KEY_BYTES])
        .derive_key::<P>(&kid)
        .expect("test key derives");
    KeyRing::new(vec![KeySlot::active_with_windows(
        kid,
        key,
        mint_until_unix,
        verify_until_unix,
    )])
    .expect("test keyring builds")
}

/// [`test_keyring_with_windows`] with effectively unbounded windows.
#[must_use]
pub fn test_keyring<P: KeyPurpose>(seed: u8, kid: &str) -> KeyRing<P> {
    let kid = KeyId::parse(kid).expect("test kid parses");
    let key = RootSecret::new([seed; KEY_BYTES])
        .derive_key::<P>(&kid)
        .expect("test key derives");
    KeyRing::new(vec![KeySlot::active(kid, key)]).expect("test keyring builds")
}
