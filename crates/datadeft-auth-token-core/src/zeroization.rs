//! Compile-time checks for zeroization of key-derived state.

// Fails to compile if the `zeroize` features of chacha20poly1305 or sha2 are
// dropped from Cargo.toml: both crates wipe key-derived state on drop only
// with them.
const _: () = {
    fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = zeroizes_on_drop::<chacha20poly1305::XChaCha20Poly1305>;
    let _ = zeroizes_on_drop::<sha2::Sha256>;
};
