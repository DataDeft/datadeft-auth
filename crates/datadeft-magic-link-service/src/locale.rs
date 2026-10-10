//! Email locale: an app-configured allowlist resolved on the server.
//!
//! A request may carry a locale hint (for example from the page's language).
//! The hint never reaches a template: [`LocaleAllowlist::resolve`] maps it to
//! one of the configured locales, or to the default, and only that
//! [`Locale`] is handed to the outbox renderer. The locale is never stored.

use core::fmt;

/// Longest locale hint kept from a request; longer hints are ignored.
pub const MAX_LOCALE_HINT_BYTES: usize = 35;

/// One configured email locale: a language subtag (`hu`, `de`), optionally
/// with a region (`de-AT`). Only obtainable from a [`LocaleAllowlist`].
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Locale(String);

impl Locale {
    /// The tag, for example `hu` or `de-AT`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn language(&self) -> &str {
        self.0.split('-').next().unwrap_or_default()
    }
}

impl fmt::Debug for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locale({})", self.0)
    }
}

/// The locales an app sends email in, plus the default for every request
/// whose hint matches none of them.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocaleAllowlist {
    default: Locale,
    others: Vec<Locale>,
}

impl LocaleAllowlist {
    /// Build the allowlist. Tags are a two- or three-letter lowercase
    /// language, optionally `-` and a two-letter uppercase region
    /// (`hu`, `en`, `de-AT`).
    pub fn new<'a, I>(default: &str, others: I) -> Result<Self, LocaleError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let default = parse_tag(default)?;
        let mut list = Self {
            default,
            others: Vec::new(),
        };
        for tag in others {
            let locale = parse_tag(tag)?;
            if list.iter().any(|existing| *existing == locale) {
                return Err(LocaleError::Duplicate);
            }
            list.others.push(locale);
        }
        Ok(list)
    }

    /// The default locale.
    #[must_use]
    pub fn default_locale(&self) -> &Locale {
        &self.default
    }

    /// Resolve a request's hint: an exact tag match (case-insensitive), else
    /// the first configured locale with the hint's language, else the
    /// default. Never fails and never returns the hint itself.
    #[must_use]
    pub fn resolve(&self, hint: Option<&str>) -> Locale {
        let Some(hint) = hint.map(str::trim).filter(|hint| !hint.is_empty()) else {
            return self.default.clone();
        };
        if let Some(exact) = self
            .iter()
            .find(|locale| locale.as_str().eq_ignore_ascii_case(hint))
        {
            return exact.clone();
        }
        let language = hint.split(['-', '_']).next().unwrap_or_default();
        self.iter()
            .find(|locale| locale.language().eq_ignore_ascii_case(language))
            .unwrap_or(&self.default)
            .clone()
    }

    fn iter(&self) -> impl Iterator<Item = &Locale> {
        core::iter::once(&self.default).chain(&self.others)
    }
}

/// Invalid locale allowlist.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LocaleError {
    /// A tag is not `ll`, `lll`, `ll-RR` or `lll-RR`.
    InvalidTag,
    /// A tag is listed twice.
    Duplicate,
}

impl fmt::Display for LocaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTag => "locale tag must be like `hu` or `de-AT`",
            Self::Duplicate => "locale listed twice",
        })
    }
}

impl std::error::Error for LocaleError {}

/// Keep a request's locale hint only when it is short and plain ASCII.
pub(crate) fn bounded_hint(hint: &str) -> Option<String> {
    (hint.len() <= MAX_LOCALE_HINT_BYTES
        && hint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then(|| hint.to_owned())
}

fn parse_tag(tag: &str) -> Result<Locale, LocaleError> {
    let (language, region) = match tag.split_once('-') {
        Some((language, region)) => (language, Some(region)),
        None => (tag, None),
    };
    let language_ok =
        (2..=3).contains(&language.len()) && language.bytes().all(|byte| byte.is_ascii_lowercase());
    let region_ok = region.is_none_or(|region| {
        region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase())
    });
    if language_ok && region_ok {
        Ok(Locale(tag.to_owned()))
    } else {
        Err(LocaleError::InvalidTag)
    }
}

#[cfg(test)]
#[path = "locale_tests.rs"]
mod tests;
