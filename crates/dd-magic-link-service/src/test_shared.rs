//! Thread-safe interior-mutability cell for test doubles.
//!
//! A `Mutex`-backed stand-in for `RefCell`/`Cell` that exposes the same
//! `borrow`/`borrow_mut`/`get`/`set`/`take`/`replace` surface. Test doubles use
//! it so their trait impls satisfy the `Send` future bound in
//! [`crate::traits`]. The fake async methods never hold a guard across an await
//! point, so the returned futures stay `Send`.

use std::sync::{Mutex, MutexGuard};

pub(crate) struct Shared<T>(Mutex<T>);

impl<T> Shared<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    /// `RefCell::borrow` stand-in. The guard derefs to `T`.
    pub(crate) fn borrow(&self) -> MutexGuard<'_, T> {
        self.0.lock().expect("test shared cell poisoned")
    }

    /// `RefCell::borrow_mut` stand-in. The guard derefs mutably to `T`.
    pub(crate) fn borrow_mut(&self) -> MutexGuard<'_, T> {
        self.0.lock().expect("test shared cell poisoned")
    }

    /// `Cell::set` stand-in (any `T`).
    pub(crate) fn set(&self, value: T) {
        *self.0.lock().expect("test shared cell poisoned") = value;
    }

    /// `Cell::replace` stand-in.
    pub(crate) fn replace(&self, value: T) -> T {
        std::mem::replace(
            &mut self.0.lock().expect("test shared cell poisoned"),
            value,
        )
    }
}

impl<T: Copy> Shared<T> {
    /// `Cell::get` stand-in (requires `Copy`).
    pub(crate) fn get(&self) -> T {
        *self.0.lock().expect("test shared cell poisoned")
    }
}

impl<T: Default> Shared<T> {
    /// `Cell::take` stand-in (requires `Default`).
    pub(crate) fn take(&self) -> T {
        std::mem::take(&mut self.0.lock().expect("test shared cell poisoned"))
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
