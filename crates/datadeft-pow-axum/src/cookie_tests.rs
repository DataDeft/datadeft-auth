//! Proof-cookie policy tests.

use super::*;

#[test]
fn production_defaults_are_host_only_secure_and_three_hours() {
    let config = PowProofCookieConfig::production_defaults();
    let header = config
        .set_header("v1.kid.token")
        .expect("value encodes")
        .to_str()
        .expect("ascii")
        .to_owned();

    assert!(header.starts_with("dd_pow=v1.kid.token;"));
    assert!(header.contains("Path=/"));
    assert!(header.contains("HttpOnly"));
    assert!(header.contains("Secure"));
    assert!(header.contains("SameSite=Lax"));
    assert!(header.contains("Max-Age=10800"));
    assert!(!header.to_ascii_lowercase().contains("domain="));
}

#[test]
fn local_development_defaults_drop_secure() {
    let config = PowProofCookieConfig::local_development_defaults();
    let header = config.set_header("v1.kid.token").expect("value encodes");
    assert!(!header.to_str().expect("ascii").contains("Secure"));
}

#[test]
fn clear_header_expires_the_cookie() {
    let config = PowProofCookieConfig::production_defaults();
    let header = config.clear_header();
    let header = header.to_str().expect("ascii");
    assert!(header.contains("Max-Age=0"));
    assert!(header.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
}

#[test]
fn invalid_name_path_and_ttl_are_rejected() {
    assert_eq!(
        PowProofCookieConfig::production("Ct_Pow", "/", 10).err(),
        Some(PowCookieConfigError::InvalidName)
    );
    assert_eq!(
        PowProofCookieConfig::production("dd_pow", "auth", 10).err(),
        Some(PowCookieConfigError::InvalidPath)
    );
    assert_eq!(
        PowProofCookieConfig::production("dd_pow", "/", 0).err(),
        Some(PowCookieConfigError::InvalidTtl)
    );
    assert_eq!(
        PowProofCookieConfig::production(
            "dd_pow",
            "/",
            datadeft_pow_core::POW_PROOF_MAX_AGE_SECS + 1
        )
        .err(),
        Some(PowCookieConfigError::InvalidTtl)
    );
}

#[test]
fn same_site_none_requires_secure() {
    let insecure = PowProofCookieConfig::local_development_defaults();
    assert_eq!(
        insecure.with_same_site(SameSite::None).err(),
        Some(PowCookieConfigError::SameSiteNoneRequiresSecure)
    );
    let secure = PowProofCookieConfig::production_defaults();
    assert!(secure.with_same_site(SameSite::None).is_ok());
}

#[test]
fn set_header_rejects_illegal_cookie_value() {
    let config = PowProofCookieConfig::production_defaults();
    for bad in ["", "has space", "has;semicolon", "\"quoted"] {
        assert_eq!(config.set_header(bad).err(), Some(PowCookieError));
    }
}
