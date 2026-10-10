//! Country pinning policy for sessions.
//!
//! A session issued with a trusted-edge country is pinned to it. With
//! [`CountryPolicy::Groups`], a country inside a group pins to the group's tag
//! instead, so the session keeps working anywhere in that group (for example
//! moving between EU countries). The same [`CountryPolicy::pin`] runs when the
//! session is bound at confirmation and on every validation, so the two can
//! never disagree. Countries outside every group stay pinned exactly.

use core::fmt;

/// Two-letter tag the EU-27 group pins to. Not an ISO 3166 country code that
/// a trusted edge sends for a viewer.
pub const EU27_GROUP_TAG: &str = "EU";

/// The 27 EU member states (ISO 3166-1 alpha-2), as of 2026.
pub const EU27_COUNTRIES: [&str; 27] = [
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
    "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

/// A named set of countries a session may move between.
#[derive(Clone, Eq, PartialEq)]
pub struct CountryGroup {
    tag: String,
    members: Vec<String>,
}

impl CountryGroup {
    /// The EU-27 group, pinned as `EU`.
    #[must_use]
    pub fn eu27() -> Self {
        Self {
            tag: EU27_GROUP_TAG.to_owned(),
            members: EU27_COUNTRIES
                .iter()
                .map(|code| (*code).to_owned())
                .collect(),
        }
    }

    /// A custom group. Every member must be two uppercase ASCII letters,
    /// members must be distinct, and there must be at least one. The tag must
    /// never name a real country, or a session pinned to it would also match
    /// that country's own traffic: use `EU` or an ISO 3166 user-assigned code
    /// (`AA`, `QM`–`QZ`, `XA`–`XZ`, `ZZ`).
    pub fn new<I, S>(tag: &str, members: I) -> Result<Self, CountryPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let group = Self {
            tag: tag.to_owned(),
            members: members.into_iter().map(Into::into).collect(),
        };
        group.validate()?;
        Ok(group)
    }

    /// The value sessions in this group are pinned to.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Whether `country` belongs to this group.
    #[must_use]
    pub fn contains(&self, country: &str) -> bool {
        self.members.iter().any(|member| member == country)
    }

    fn validate(&self) -> Result<(), CountryPolicyError> {
        if !is_group_tag(&self.tag) {
            return Err(CountryPolicyError::InvalidTag);
        }
        if self.members.is_empty() || !self.members.iter().all(|code| is_country_shape(code)) {
            return Err(CountryPolicyError::InvalidMember);
        }
        for (index, member) in self.members.iter().enumerate() {
            if self
                .members
                .iter()
                .skip(index + 1)
                .any(|other| other == member)
            {
                return Err(CountryPolicyError::DuplicateMember);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CountryGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountryGroup")
            .field("tag", &self.tag)
            .field("members", &self.members.len())
            .finish()
    }
}

/// How a session's country is pinned.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum CountryPolicy {
    /// Pin to the exact country (default).
    #[default]
    Exact,
    /// Pin a country inside a group to the group's tag; any other country
    /// exactly. Moving within a group keeps the session; leaving it ends it.
    Groups(Vec<CountryGroup>),
}

impl CountryPolicy {
    /// Exact pinning, except inside the EU-27 group.
    #[must_use]
    pub fn eu27() -> Self {
        Self::Groups(vec![CountryGroup::eu27()])
    }

    /// The value a session from `country` is pinned to: the tag of the group
    /// containing it, or the country itself.
    #[must_use]
    pub fn pin<'a>(&'a self, country: &'a str) -> &'a str {
        match self {
            Self::Exact => country,
            Self::Groups(groups) => groups
                .iter()
                .find(|group| group.contains(country))
                .map_or(country, CountryGroup::tag),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), CountryPolicyError> {
        let Self::Groups(groups) = self else {
            return Ok(());
        };
        for (index, group) in groups.iter().enumerate() {
            group.validate()?;
            for other in groups.iter().skip(index + 1) {
                if group.members.iter().any(|member| other.contains(member)) {
                    return Err(CountryPolicyError::OverlappingGroups);
                }
            }
        }
        Ok(())
    }
}

/// Invalid country policy. Carries no country codes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CountryPolicyError {
    /// A group tag is not `EU` or an ISO 3166 user-assigned code.
    InvalidTag,
    /// A group is empty or a member is not two uppercase ASCII letters.
    InvalidMember,
    /// A group lists a country twice.
    DuplicateMember,
    /// A country belongs to more than one group.
    OverlappingGroups,
}

impl fmt::Display for CountryPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTag => "country group tag must be EU or a user-assigned code",
            Self::InvalidMember => "country group members must be two uppercase letters",
            Self::DuplicateMember => "country group lists a country twice",
            Self::OverlappingGroups => "a country belongs to more than one group",
        })
    }
}

impl std::error::Error for CountryPolicyError {}

/// `EU`, or an ISO 3166-1 user-assigned alpha-2 code: never a real country.
fn is_group_tag(value: &str) -> bool {
    if value == EU27_GROUP_TAG {
        return true;
    }
    match value.as_bytes() {
        [b'A', b'A'] | [b'Z', b'Z'] => true,
        [b'Q', second] => (b'M'..=b'Z').contains(second),
        [b'X', second] => second.is_ascii_uppercase(),
        _ => false,
    }
}

fn is_country_shape(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

#[cfg(test)]
#[path = "country_tests.rs"]
mod tests;
