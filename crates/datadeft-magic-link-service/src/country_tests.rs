//! Country pinning policy: groups pin to their tag, everything else exactly.

use super::*;

#[test]
fn eu27_has_27_distinct_members_and_validates() {
    let group = CountryGroup::eu27();
    assert_eq!(group.tag(), "EU");
    assert_eq!(EU27_COUNTRIES.len(), 27);
    assert!(CountryPolicy::eu27().validate().is_ok());
    for country in EU27_COUNTRIES {
        assert!(group.contains(country), "{country}");
    }
    for outside in ["GB", "CH", "NO", "US", "UA", "EU"] {
        assert!(!group.contains(outside), "{outside}");
    }
}

#[test]
fn groups_pin_to_their_tag_and_other_countries_exactly() {
    let policy = CountryPolicy::eu27();
    assert_eq!(policy.pin("HU"), Some("EU"));
    assert_eq!(policy.pin("AT"), Some("EU"));
    assert_eq!(policy.pin("GB"), Some("GB"));
    assert_eq!(policy.pin("US"), Some("US"));
    assert_eq!(CountryPolicy::Exact.pin("HU"), Some("HU"));
    // An edge pseudo-code equal to a group tag is never a viewer country.
    assert_eq!(policy.pin("EU"), None);
    assert_eq!(policy.pin("XA"), None);
    // Under any policy: a session pinned to `EU` before a switch to exact
    // pinning must not match a request carrying the `EU` pseudo-code.
    assert_eq!(CountryPolicy::Exact.pin("EU"), None);
    assert_eq!(CountryPolicy::Exact.pin("ZZ"), None);
    // Kosovo and the unknown-country code are request values, pinned exactly.
    assert_eq!(CountryPolicy::Exact.pin("XK"), Some("XK"));
    assert_eq!(policy.pin("XK"), Some("XK"));
    assert_eq!(CountryPolicy::Exact.pin("XX"), Some("XX"));
    assert_eq!(CountryPolicy::default(), CountryPolicy::Exact);
}

#[test]
fn malformed_policies_are_refused() {
    assert_eq!(
        CountryGroup::new("eu", ["AT"]).unwrap_err(),
        CountryPolicyError::InvalidTag
    );
    // A tag must never be a real country: it would match that country too.
    for real in ["HU", "DE", "US", "AX"] {
        assert_eq!(
            CountryGroup::new(real, ["AT", "DE"]).unwrap_err(),
            CountryPolicyError::InvalidTag,
            "{real}"
        );
    }
    for request_value in ["XX", "XK"] {
        assert_eq!(
            CountryGroup::new(request_value, ["AT"]).unwrap_err(),
            CountryPolicyError::InvalidTag,
            "{request_value}"
        );
    }
    for reserved in ["EU", "AA", "QM", "QZ", "XA", "XZ", "ZZ"] {
        assert!(CountryGroup::new(reserved, ["AT"]).is_ok(), "{reserved}");
    }
    assert_eq!(
        CountryGroup::new("XY", Vec::<String>::new()).unwrap_err(),
        CountryPolicyError::InvalidMember
    );
    assert_eq!(
        CountryGroup::new("XY", ["AT", "aut"]).unwrap_err(),
        CountryPolicyError::InvalidMember
    );
    assert_eq!(
        CountryGroup::new("XY", ["AT", "AT"]).unwrap_err(),
        CountryPolicyError::DuplicateMember
    );
    let nordic = CountryGroup::new("XN", ["SE", "NO"]).expect("group");
    assert_eq!(
        CountryPolicy::Groups(vec![CountryGroup::eu27(), nordic]).validate(),
        Err(CountryPolicyError::OverlappingGroups)
    );
    // Disjoint groups under one tag would pin Hungary and the US alike.
    assert_eq!(
        CountryPolicy::Groups(vec![
            CountryGroup::new("XA", ["HU"]).expect("group"),
            CountryGroup::new("XA", ["US"]).expect("group"),
        ])
        .validate(),
        Err(CountryPolicyError::DuplicateTag)
    );
    let alpine = CountryGroup::new("XA", ["CH", "LI"]).expect("group");
    assert!(
        CountryPolicy::Groups(vec![CountryGroup::eu27(), alpine])
            .validate()
            .is_ok()
    );
}

#[test]
fn debug_lists_no_member_codes() {
    let debug = format!("{:?}", CountryGroup::eu27());
    assert!(debug.contains("27"), "{debug}");
    assert!(!debug.contains("HU"), "{debug}");
}
