//! The example's single locale table.
//!
//! The email locale allowlist, the per-locale redirect configs, the static
//! confirm-page routes, and the dev form's language options are all derived
//! from these rows, so a new UI language is one new row plus its translated
//! page — there is no second list to keep in sync.

pub(super) struct UiLocale {
    /// Allowlist tag. The first row is the default locale.
    pub(super) tag: &'static str,
    /// Name shown in the dev form's language selector.
    pub(super) name: &'static str,
    /// Route of this locale's static confirm page.
    pub(super) confirm_page_route: &'static str,
    /// The page itself. Each page carries its own translated strings —
    /// including the confirm script's status messages, as `data-*`
    /// attributes — so the shared script never branches on language.
    pub(super) confirm_page_html: &'static str,
}

/// Row 0 is the default locale, served for unknown or missing hints.
pub(super) const UI_LOCALES: &[UiLocale] = &[
    UiLocale {
        tag: "en",
        name: "English",
        confirm_page_route: "/login/confirm",
        confirm_page_html: include_str!("confirm.en.html"),
    },
    UiLocale {
        tag: "hu",
        name: "Magyar",
        confirm_page_route: "/hu/login/confirm",
        confirm_page_html: include_str!("confirm.hu.html"),
    },
];

/// The table row for an allowlist-resolved tag. The allowlist is built from
/// the table, so every resolved tag has a row; fall back to the default row
/// rather than panicking if the two ever diverge.
pub(super) fn locale_index(tag: &str) -> usize {
    UI_LOCALES
        .iter()
        .position(|locale| locale.tag == tag)
        .unwrap_or(0)
}
