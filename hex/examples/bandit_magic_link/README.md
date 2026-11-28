# Bandit magic-link demo

An independent Mix consumer of the Elixir 0.8 draft in
[PR #45](https://github.com/DataDeft/datadeft-auth/pull/45). Try scanner-safe
sign-in, a protected page, and revoking the session on sign-out. **This is a
local review example, not a deployable authentication server.** It has no PoW,
real email delivery, production AWS transport, or persistent storage.

## Run it

Use a full repository checkout, Elixir ≥ 1.16, OTP ≥ 26, and the repository's
pinned Rust toolchain. From the repository root:

```sh
mise run bandit-verify
mise -C hex/examples/bandit_magic_link run serve
```

1. Open `http://127.0.0.1:4000/` (not `localhost`). The example binds only to
   loopback. Set `PORT` when starting it if 4000 is busy.
2. Accept both demo policies and request a link for `alice@example.test`.
3. Open `inbox.txt` at the **Private mailbox** path printed on startup. Open
   the URL in the file in your browser. This local file is owner-only and is
   never served by Bandit. Treat the link as a password: don't share it or paste
   it into a terminal, issue, or log. Only the fixed synthetic account receives
   a link. New deliveries replace the private file.
4. The browser redirects to a clean URL and displays the account. Open the link
   in a second browser without clicking **Continue sign in** if you want to see
   the scanner-safe behavior: opening it does not consume it or sign in.
5. Click **Continue sign in** to reach the protected page, and **Sign out** to
   revoke the session. A previously copied session cookie no longer works.

Restarting the example resets demo keys, quotas and data. A normal stop removes
its temporary mailbox. After a forced kill, delete the printed mailbox's
parent directory. Do not expose this demo through a proxy or tunnel.

## Verify the browser flow

The example has an optional Chromium smoke test; Node ≥ 20 and npm are needed
only for it. On Linux, install the official Playwright browser system
prerequisites if missing.

```sh
mise run bandit-verify
mise -C hex/examples/bandit_magic_link run browser-setup
mise -C hex/examples/bandit_magic_link run browser-test
```

The smoke starts its own loopback instance on an unused port. It checks a
scanner visit does not sign in, the clean redirect and masked account, rejection
of actual browser forms from a foreign origin, successful confirmation, replay
rejection, and revocation of the saved cookie on logout. It writes no token,
headers, screenshots, or traces to its output.

For app integration rather than this demo's routes or storage, see the
[Plug usage guide](../../datadeft_auth/USAGE.md#8-optional-plug-adapter).
