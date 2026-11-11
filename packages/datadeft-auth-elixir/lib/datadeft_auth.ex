defmodule DatadeftAuth do
  @moduledoc """
  Framework-independent authentication using a supervised, separate Rust process.

  This first infrastructure packet implements process startup and health only.
  Authentication, AWS configuration and key initialization are not implemented yet.
  A healthy transport does not mean authentication is configured or available.

  Add `{DatadeftAuth, name: MyAuth}` to your application's supervision tree.
  The name doubles as the child id, so give each supervised instance a
  distinct name; unregistered (nil-name) instances share the default id and
  need hand-written child specs to coexist under one supervisor.
  Native work never runs inside BEAM. No request is automatically replayed after
  a timeout or worker failure.
  """

  alias DatadeftAuth.{Connection, DevMagicLink, Error, FlowState, Landing, Session, Validation}

  # Typespecs cannot reference module attributes; these literals mirror the
  # limits in Connection's @int_options validation table.
  @typedoc "Validated bound of the :request_timeout option, in milliseconds."
  @type request_timeout :: 1..60_000
  @typedoc "Validated bound of the :max_pending option."
  @type max_pending :: 1..1024
  @typedoc "Validated bound of the :restart_delay option, in milliseconds."
  @type restart_delay :: 1..5000

  @typedoc """
  Authentication configuration sent to the executable on every (re)connect.
  Without one the transport is health-only and every auth call returns a
  configuration error. The executable validates the content fail-closed:

  - `mode: :fake` uses the crate-shipped in-memory store/outbox (tests and
    local development); `:aws` is staged and currently refused.
  - `service` carries `terms_version`/`privacy_version` plus optional
    lifetimes, `enforce_country`, `account_display`, `default_locale` and
    `locales`.
  - `email` carries `link_base_url` (the token is appended), `subject`,
    `text` and optional `html`; bodies must contain `{magic_link_url}`.
  - `secrets` carries `active_document` (and optionally
    `previous_document`): the auth secret document JSON strings, trusted
    deployment configuration delivered once over the private pipe.
  """
  @type config :: %{
          required(:mode) => :fake | :aws,
          required(:service) => map(),
          required(:email) => map(),
          required(:secrets) => map()
        }

  @typedoc """
  Transport options. A nil name, executable or config selects the default,
  same as omitting the key. Executable paths and the config are trusted
  deployment configuration.
  """
  @type option ::
          {:name, atom()}
          | {:executable, String.t() | nil}
          | {:config, config() | nil}
          | {:request_timeout, request_timeout()}
          | {:max_pending, max_pending()}
          | {:restart_delay, restart_delay()}

  @typedoc "Optional transport settings; duplicate and unknown keys are rejected."
  @type options :: [option()]

  @typedoc "Transport health only, not authentication or AWS readiness."
  @type status_result :: {:ok, :transport_ready} | {:error, Error.t()}

  @doc "Starts the transport owner. Readiness is asynchronous and checked with status/1."
  @spec start_link(options()) :: GenServer.on_start()
  def start_link(opts \\ []), do: Connection.start_link(opts)

  @doc false
  @spec child_spec(options()) :: Supervisor.child_spec()
  def child_spec(opts) do
    # Only nil selects the default id: false is a valid registered name.
    id =
      case Keyword.get(opts, :name) do
        nil -> __MODULE__
        name -> name
      end

    %{id: id, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Checks transport health only; returns a fixed diagnostic error when unavailable."
  @spec status(GenServer.server()) :: status_result()
  def status(server), do: call(server, :status)

  @doc """
  Requests a magic-link email. The public response to the requester must stay
  the same generic acceptance whatever the returned reason label says; the
  label (for example `"magic_link_request_sent"`) is for internal logs and
  metrics only and never carries identifiers.

  Options: `terms_accepted`, `privacy_accepted` (both default false; consent
  is the application's statement, not a default) and `locale` (a hint
  resolved against the configured allowlist).
  """
  @spec request_link(GenServer.server(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def request_link(server, email, opts \\ []) when is_binary(email) and is_list(opts) do
    payload = %{
      email: email,
      terms_accepted: Keyword.get(opts, :terms_accepted, false),
      privacy_accepted: Keyword.get(opts, :privacy_accepted, false),
      locale: Keyword.get(opts, :locale)
    }

    call(server, {:auth, :request_link, payload})
  end

  @doc """
  Scanner-safe landing for an emailed token: validates without consuming and
  returns the flow secrets to store client-side. The answer is uniform for
  every unusable link state; render the same page either way.
  """
  @spec landing(GenServer.server(), String.t()) :: {:ok, Landing.t()} | {:error, Error.t()}
  def landing(server, token) when is_binary(token),
    do: call(server, {:auth, :landing, %{token: token}})

  @doc """
  Reads the flow state bound to a confirm cookie (redirect-landing mode).
  On `usable: false` clear the confirm cookie.
  """
  @spec flow_state(GenServer.server(), String.t()) :: {:ok, FlowState.t()} | {:error, Error.t()}
  def flow_state(server, confirm_cookie) when is_binary(confirm_cookie),
    do: call(server, {:auth, :flow_state, %{confirm_cookie: confirm_cookie}})

  @doc """
  Confirms a landing: consumes the link and creates the session atomically.
  `country` is the trusted-edge signal, never client input. On `:rejected`
  or `:bad_request` clear the confirm cookie; on `:unavailable` preserve it
  for an identical retry after backoff.
  """
  @spec confirm(GenServer.server(), String.t(), String.t(), keyword()) ::
          {:ok, Session.t()} | {:error, Error.t()}
  def confirm(server, confirm_cookie, confirmation, opts \\ [])
      when is_binary(confirm_cookie) and is_binary(confirmation) and is_list(opts) do
    payload = %{
      confirm_cookie: confirm_cookie,
      confirmation: confirmation,
      country: Keyword.get(opts, :country)
    }

    call(server, {:auth, :confirm, payload})
  end

  @doc """
  Validates a session cookie (read-only) and re-issues it when due. Send a
  returned `refreshed_cookie` with the normal session cookie settings on a
  `no-store` response. `valid: false` means sign in again; clear the cookie.
  """
  @spec validate_session(GenServer.server(), String.t(), keyword()) ::
          {:ok, Validation.t()} | {:error, Error.t()}
  def validate_session(server, session_cookie, opts \\ [])
      when is_binary(session_cookie) and is_list(opts) do
    payload = %{session_cookie: session_cookie, country: Keyword.get(opts, :country)}
    call(server, {:auth, :validate_session, payload})
  end

  @doc """
  Revokes the session server-side. Clear the session cookie only after
  `{:ok, %{revoked: true}}` or `revoked: false` (already invalid); on
  `:unavailable` keep it and retry. Protect the calling route against CSRF.
  """
  @spec logout(GenServer.server(), String.t(), keyword()) ::
          {:ok, %{revoked: boolean()}} | {:error, Error.t()}
  def logout(server, session_cookie, opts \\ [])
      when is_binary(session_cookie) and is_list(opts) do
    payload = %{session_cookie: session_cookie, country: Keyword.get(opts, :country)}

    case call(server, {:auth, :logout, payload}) do
      {:ok, revoked} when is_boolean(revoked) -> {:ok, %{revoked: revoked}}
      other -> other
    end
  end

  @doc """
  Fake-mode test helper: the newest outbox email's landing URL for an
  address. Refused outside `mode: :fake`; never call it in production code.
  """
  @spec fake_last_magic_link(GenServer.server(), String.t()) ::
          {:ok, DevMagicLink.t()} | {:error, Error.t()}
  def fake_last_magic_link(server, email) when is_binary(email),
    do: call(server, {:auth, :fake_last_magic_link, %{email: email}})

  defp call(server, request) do
    GenServer.call(server, request, :infinity)
  catch
    :exit, _ -> {:error, %Error{code: :unavailable}}
  end
end
