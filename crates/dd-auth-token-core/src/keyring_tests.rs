//! Key material tests.

use super::*;

#[test]
fn root_secret_debug_does_not_contain_key_bytes() {
    let secret = RootSecret::new([0x2A; KEY_BYTES]);
    let debug = format!("{secret:?}");

    assert_eq!(debug, "RootSecret(..)");
    assert!(!debug.contains("2a"), "hex key bytes must not appear");
    assert!(!debug.contains("42"), "decimal key bytes must not appear");
    assert!(!debug.contains('*'), "ASCII key bytes must not appear");
    assert!(!debug.contains('['), "raw array debug must not appear");
}

#[test]
fn branca_key_debug_does_not_contain_key_bytes() {
    let key = BrancaKey::<()>::new([0x2A; KEY_BYTES]);
    let debug = format!("{key:?}");

    assert_eq!(debug, "BrancaKey(..)");
    assert!(!debug.contains("2a"), "hex key bytes must not appear");
    assert!(!debug.contains("42"), "decimal key bytes must not appear");
    assert!(!debug.contains('*'), "ASCII key bytes must not appear");
    assert!(!debug.contains('['), "raw array debug must not appear");
}

#[test]
fn root_secret_derives_deterministic_purpose_separated_keys() {
    let root = RootSecret::new([0x11; KEY_BYTES]);

    let session_a = root.derive_key::<SessionCookie>().expect("derive session");
    let session_b = root
        .derive_key::<SessionCookie>()
        .expect("derive session again");
    let pow = root.derive_key::<PowCookie>().expect("derive pow");

    assert_eq!(
        session_a.as_bytes(),
        session_b.as_bytes(),
        "same root+purpose is deterministic"
    );
    assert_ne!(
        session_a.as_bytes(),
        pow.as_bytes(),
        "different purpose info separates keys"
    );
    assert_ne!(
        session_a.as_bytes(),
        root.as_bytes(),
        "derived key is not raw root material"
    );
}
