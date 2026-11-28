defmodule BanditMagicLink.Router do
  @moduledoc false
  @behaviour Plug

  import Plug.Conn
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Plug, as: Web

  @static_csp "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

  @request_page """
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>datadeft-auth Bandit demo</title>
      <script src="/request.js" defer></script>
    </head>
    <body>
      <main>
        <h1>datadeft-auth Bandit demo</h1>
        <p>This loopback example delivers only to the private local mailbox shown at startup.</p>
        <form id="request">
          <p>Demo account: <strong>alice@example.test</strong></p>
          <label><input type="checkbox" name="terms_accepted" required> Accept the demo terms</label>
          <label><input type="checkbox" name="privacy_accepted" required> Accept the demo privacy policy</label>
          <button type="submit">Request sign-in link</button>
        </form>
        <p id="status" aria-live="polite"></p>
      </main>
    </body>
  </html>
  """

  @request_script """
  const form = document.getElementById("request");
  const status = document.getElementById("status");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "Requesting link…";
    try {
      const response = await fetch("/auth/magic-link/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "alice@example.test",
          terms_accepted: form.elements.terms_accepted.checked,
          privacy_accepted: form.elements.privacy_accepted.checked
        })
      });
      status.textContent = response.ok
        ? "Request accepted. Open the private local mailbox to continue."
        : "The request could not be completed.";
    } catch {
      status.textContent = "The request could not be completed.";
    }
  });
  """

  @confirm_page """
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Confirm sign in</title>
      <script src="/auth/magic-link/confirm.js" defer></script>
    </head>
    <body>
      <main>
        <h1>Confirm sign in</h1>
        <p id="status" aria-live="polite">Checking your link…</p>
        <form id="confirm" action="/auth/magic-link/consume" method="post" hidden>
          <p>Sign in as <strong id="account"></strong>.</p>
          <input type="hidden" name="confirmation">
          <button type="submit">Continue sign in</button>
        </form>
      </main>
    </body>
  </html>
  """

  @confirm_script """
  const status = document.getElementById("status");
  const form = document.getElementById("confirm");
  (async () => {
    try {
      const response = await fetch("/auth/magic-link/flow-state", {
        credentials: "same-origin",
        cache: "no-store"
      });
      if (!response.ok) throw new Error("unavailable");
      const state = await response.json();
      if (!state.usable) {
        status.textContent = "This link cannot be used. Request a new one.";
        return;
      }
      document.getElementById("account").textContent = state.account;
      form.elements.confirmation.value = state.confirmation;
      form.hidden = false;
      status.textContent = "";
    } catch {
      status.textContent = "The service is busy. Reload this page in a moment.";
    }
  })();
  """

  @impl true
  def init(config), do: config

  @impl true
  def call(%Plug.Conn{scheme: :http, host: "127.0.0.1", port: port} = conn, {web, port}) do
    route(conn.method, conn.path_info, conn, web)
  end

  def call(conn, _), do: conn |> Web.security_headers() |> send_resp(400, "Invalid request.")

  defp route("GET", [], conn, _), do: static(conn, "text/html", @request_page)
  defp route("GET", ["request.js"], conn, _), do: static(conn, "text/javascript", @request_script)
  defp route("POST", ["auth", "magic-link", "request"], conn, web), do: Web.request(conn, web)
  defp route("GET", ["auth", "magic-link", "open"], conn, web), do: Web.open(conn, web)

  defp route("GET", ["auth", "magic-link", "confirm"], conn, _),
    do: static(conn, "text/html", @confirm_page)

  defp route("GET", ["auth", "magic-link", "confirm.js"], conn, _),
    do: static(conn, "text/javascript", @confirm_script)

  defp route("GET", ["auth", "magic-link", "flow-state"], conn, web),
    do: Web.flow_state(conn, web)

  defp route("POST", ["auth", "magic-link", "consume"], conn, web), do: Web.confirm(conn, web)
  defp route("GET", ["auth", "magic-link", "complete"], conn, web), do: me(conn, web)
  defp route("GET", ["me"], conn, web), do: me(conn, web)
  defp route("POST", ["auth", "logout"], conn, web), do: Web.logout(conn, web)

  defp route(_, _, conn, _),
    do: conn |> Web.security_headers() |> send_resp(404, "Not found.")

  defp static(conn, type, body) do
    conn
    |> Web.security_headers()
    |> put_resp_header("content-security-policy", @static_csp)
    |> put_resp_header("x-content-type-options", "nosniff")
    |> put_resp_content_type(type)
    |> send_resp(200, body)
  end

  defp me(conn, web) do
    case Web.authenticate(conn, web) do
      {:ok, conn, record} ->
        email = record.email |> Email.value() |> Plug.HTML.html_escape()

        conn
        |> put_resp_content_type("text/html")
        |> send_resp(200, [
          ~s(<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signed in</title></head>),
          ~s(<body><main><h1>Signed in</h1><p>Account: <strong>),
          email,
          ~s(</strong></p><form action="/auth/logout" method="post"><button>Sign out</button></form></main></body></html>)
        ])

      {:error, conn} ->
        conn
    end
  end
end
