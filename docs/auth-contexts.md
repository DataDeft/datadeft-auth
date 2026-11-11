# Localized confirmation and host cookies

These are opt-in 0.6.0 improvements. Existing deployments keep their cookie
names and single-page redirect configuration unless applications explicitly
change them. The local Axum example demonstrates English/Hungarian confirmation
pages. Existing secret loading, purpose-separated key derivation and rotation
are unchanged.

## Confirmation in the email's language

The service already resolves a request's locale hint through `LocaleAllowlist`.
Only that resolved `MagicLinkEmail::locale` reaches the outbox renderer, which
owns URL construction. No new locale storage or authentication claims are
needed for presentation-only language selection.

Use a small fixed route/page map, for example:

| Email locale | Emailed landing path | Static confirmation page |
| --- | --- | --- |
| `en` / default | `/auth/magic-link/open/en` | `/login/confirm` |
| `hu` | `/auth/magic-link/open/hu` | `/hu/login/confirm` |

Each landing handler selects its prevalidated configuration **before** calling
`magic_link_landing_redirect`. Configure each with `with_redirect_landing` and
its fixed `SameOriginRedirect` page. The flow-state and confirmation POST routes
can be shared. The confirm cookie's path must still cover those two routes.

The example implements this flow, emits the resolved locale in its development
outbox link and has both translated pages. Unknown hints use the English default.
Its router test covers the default, English, Hungarian and unknown-locale routes
through confirmation and an authenticated request.

Rules:

- Language is a presentation hint, not authorization or authenticated metadata.
  Editing the route can change the language, never the account or permissions.
- Never use successful link lookup or stored account data to select the page.
  Usable and unusable links on one route must redirect to the same page/status.
- Never put token material in Location or JavaScript. The initial landing token
  remains an HTTP-only server input. The separate flow-state response contains
  only the existing account display and confirmation value.
- Retain no-store, strict-origin referrer policy, framing denial, same-origin
  POST and an external same-origin script with no third-party assets.
- Use `textContent` for account display. Translations and destination paths come
  only from application configuration, never raw request strings.

If the application needs locale integrity rather than a display preference,
that is a separate requirement: propose authenticated metadata before treating
this hint as trusted. Do not silently add locale-dependent access rules.

## Opt-in `__Host-` session cookies

```rust,ignore
use datadeft_magic_link_axum::SessionCookieConfig;

let session_cookie = SessionCookieConfig::secure(&service_config)?
    .with_name("__Host-dd_session")?;
```

The exact case-sensitive prefix requires Secure, explicit Path=/ and no Domain
(the helpers are always host-only). The suffix remains lower snake_case and
the complete name must fit the existing 64-byte cap. Invalid name/path builder
orders fail with typed configuration errors. Set and clear headers have the
same attributes. Incoming selection uses the exact configured name, rejects
duplicates and never falls back to `dd_session`.

`dd_session` remains the default. `insecure_local` rejects prefixed names;
local HTTP uses the existing unprefixed cookie. The prefix is policy-gated,
not kind-gated: the default confirm cookie cannot take it because of its
narrow `/auth` path, and opting a confirm cookie in requires widening it to
`Path=/`, trading the narrow-scope recommendation for the prefix's host
binding — keep confirm cookies unprefixed unless that trade is deliberate.
Enabling the name requires reauthentication;
applications should separately expire the old cookie under its old attributes
as a deployment migration. Renaming a cookie is not server-side revocation.
