defmodule DatadeftAuth do
  @moduledoc """
  Framework-independent authentication using a supervised, separate Rust process.

  The transport plus the magic-link/session and PoW APIs are implemented,
  backed by either the crate-shipped in-memory store (`mode: :fake`) or
  DynamoDB/SES with Secrets Manager key loading (`mode: :aws`). This is not a
  production authentication release; see the README for the open gates.
  A healthy transport does not mean authentication is configured or available.

  Add `{DatadeftAuth, name: MyAuth}` to your application's supervision tree.
  The name doubles as the child id, so give each supervised instance a
  distinct name; unregistered (nil-name) instances share the default id and
  need hand-written child specs to coexist under one supervisor.
  Native work never runs inside BEAM. No request is automatically replayed after
  a timeout or worker failure.
  """

  alias DatadeftAuth.{
    Connection,
    DevMagicLink,
    Error,
    FlowState,
    Landing,
    PowChallenge,
    PowVerification,
    Session,
    Validation
  }

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
    local development); `mode: :aws` uses DynamoDB, SES and Secrets Manager
    through the deployment-role credential chain and requires the `aws` key.
  - `service` carries `terms_version`/`privacy_version` plus optional
    lifetimes, `enforce_country`, `account_display`, `default_locale` and
    `locales`.
  - `email` carries `link_base_url` (the token is appended), `subject`,
    `text` and optional `html`; bodies must contain `{magic_link_url}` and
    the subject must not (Subject headers are routinely logged in transit,
    and the URL carries the bearer token).
  - `secrets`: fake mode takes `active_document` (and optionally
    `previous_document`), the auth secret document JSON strings delivered
    once over the private pipe. AWS mode takes `active_ref`/`previous_ref`
    (`name_or_arn` with `stage` or `version_id`) so key material never
    enters BEAM; inline documents are allowed only together with a local
    `endpoint_url`.
  - `aws` (AWS mode only) carries `region`, `table`, `from_email`, optional
    `reply_to`, and the test-only `endpoint_url`/`fake_outbox` pair for
    DynamoDB Local runs.
  - `pow` (optional) enables the proof-of-work admission gate: `difficulty`
    (leading zero hex characters, 1..64; document your production floor) and
    `proof_budget_per_solve` (admissions one solve buys over the proof's
    lifetime, shared across nodes), plus optional `challenge_max_age_secs`
    (default 120) and `proof_ttl_secs` (default 10800). Without this key the
    pow operations return a configuration error.
  """
  @type config :: %{
          required(:mode) => :fake | :aws,
          required(:service) => map(),
          required(:email) => map(),
          required(:secrets) => map(),
          optional(:aws) => map(),
          optional(:pow) => map()
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
  def request_link(server, email, opts \\ [])

  def request_link(server, email, opts) when is_binary(email) and is_list(opts) do
    if valid_options?(opts, [:terms_accepted, :privacy_accepted, :locale]) do
      payload = %{
        email: email,
        terms_accepted: Keyword.get(opts, :terms_accepted, false),
        privacy_accepted: Keyword.get(opts, :privacy_accepted, false),
        locale: Keyword.get(opts, :locale)
      }

      call(server, {:auth, :request_link, payload})
    else
      bad_request()
    end
  end

  def request_link(_, _, _), do: bad_request()

  @doc """
  Scanner-safe landing for an emailed token: validates without consuming and
  returns the flow secrets to store client-side. The answer is uniform for
  every unusable link state; render the same page either way.
  """
  @spec landing(GenServer.server(), String.t()) :: {:ok, Landing.t()} | {:error, Error.t()}
  def landing(server, token) when is_binary(token),
    do: call(server, {:auth, :landing, %{token: token}})

  def landing(_, _), do: bad_request()

  @doc """
  Reads the flow state bound to a confirm cookie (redirect-landing mode).
  On `usable: false` clear the confirm cookie.
  """
  @spec flow_state(GenServer.server(), String.t()) :: {:ok, FlowState.t()} | {:error, Error.t()}
  def flow_state(server, confirm_cookie) when is_binary(confirm_cookie),
    do: call(server, {:auth, :flow_state, %{confirm_cookie: confirm_cookie}})

  def flow_state(_, _), do: bad_request()

  @doc """
  Confirms a landing: consumes the link and creates the session atomically.
  `country` is the trusted-edge signal, never client input. On `:rejected`
  or `:bad_request` clear the confirm cookie. On `:unavailable`, `:timeout`
  or transport failure, preserve it but do not assume rollback or blindly call
  confirm again: a fresh public call is not an identical commit retry. Durable
  reconciliation is an unresolved production gate.
  """
  @spec confirm(GenServer.server(), String.t(), String.t(), keyword()) ::
          {:ok, Session.t()} | {:error, Error.t()}
  def confirm(server, confirm_cookie, confirmation, opts \\ [])

  def confirm(server, confirm_cookie, confirmation, opts)
      when is_binary(confirm_cookie) and is_binary(confirmation) and is_list(opts) do
    if valid_options?(opts, [:country]) do
      payload = %{
        confirm_cookie: confirm_cookie,
        confirmation: confirmation,
        country: Keyword.get(opts, :country)
      }

      call(server, {:auth, :confirm, payload})
    else
      bad_request()
    end
  end

  def confirm(_, _, _, _), do: bad_request()

  @doc """
  Validates a session cookie (read-only) and re-issues it when due. Send a
  returned `refreshed_cookie` with the normal session cookie settings on a
  `no-store` response. `valid: false` means sign in again; clear the cookie.
  """
  @spec validate_session(GenServer.server(), String.t(), keyword()) ::
          {:ok, Validation.t()} | {:error, Error.t()}
  def validate_session(server, session_cookie, opts \\ [])

  def validate_session(server, session_cookie, opts)
      when is_binary(session_cookie) and is_list(opts) do
    if valid_options?(opts, [:country]) do
      payload = %{session_cookie: session_cookie, country: Keyword.get(opts, :country)}
      call(server, {:auth, :validate_session, payload})
    else
      bad_request()
    end
  end

  def validate_session(_, _, _), do: bad_request()

  @doc """
  Revokes the session server-side. Clear the session cookie only after
  `{:ok, %{revoked: true}}` or `revoked: false` (already invalid); on
  `:unavailable` keep it and retry. Protect the calling route against CSRF.

  Pass the same `country` trusted-edge signal you pass to
  `validate_session/3`: logout validates the session before revoking it, so
  a missing or mismatched signal on a country-pinned session answers
  `revoked: false` while the server-side session stays live.
  """
  @spec logout(GenServer.server(), String.t(), keyword()) ::
          {:ok, %{revoked: boolean()}} | {:error, Error.t()}
  def logout(server, session_cookie, opts \\ [])

  def logout(server, session_cookie, opts)
      when is_binary(session_cookie) and is_list(opts) do
    if valid_options?(opts, [:country]) do
      payload = %{session_cookie: session_cookie, country: Keyword.get(opts, :country)}
      call(server, {:auth, :logout, payload})
    else
      bad_request()
    end
  end

  def logout(_, _, _), do: bad_request()

  @doc """
  Mints a proof-of-work challenge for the application's `pow/create` route.
  Serialize the struct as JSON for the shipping browser client verbatim.
  Requires the `pow` configuration key.
  """
  @spec pow_challenge(GenServer.server()) :: {:ok, PowChallenge.t()} | {:error, Error.t()}
  def pow_challenge(server), do: call(server, {:auth, :pow_challenge, %{}})

  @doc """
  Verifies a posted solution (the client's `{chg, sol, non, tim, tag}` JSON
  as a map). On `admitted: true` set the returned `proof_cookie` as the
  `dd_pow` cookie (HttpOnly, Secure, the configured proof TTL). On
  `admitted: false` answer with one generic "solve a new challenge" response
  whatever check failed.
  """
  @spec pow_verify(GenServer.server(), map()) ::
          {:ok, PowVerification.t()} | {:error, Error.t()}
  def pow_verify(server, solution) when is_map(solution) do
    with {:ok, payload} <- solution_payload(solution) do
      call(server, {:auth, :pow_verify, payload})
    end
  end

  def pow_verify(_, _), do: bad_request()

  @doc """
  Admits one gated request by its proof cookie, spending one unit of the
  solve's shared lifetime budget. `admitted: false` (an unusable proof or an
  exhausted budget) means answer "solve a new challenge"; a failing budget
  store is `{:error, %Error{code: :unavailable}}` and must refuse the
  request — never admit on failure.
  """
  @spec pow_admit(GenServer.server(), String.t()) ::
          {:ok, %{admitted: boolean()}} | {:error, Error.t()}
  def pow_admit(server, proof_cookie) when is_binary(proof_cookie),
    do: call(server, {:auth, :pow_admit, %{proof_cookie: proof_cookie}})

  def pow_admit(_, _), do: bad_request()

  # The five client-echoed solution fields, from string or atom keys, with
  # anything extra or missing refused here instead of as a process fault.
  # A client-echoed `dif` is tolerated and dropped: the executable always
  # verifies at its configured difficulty, never at client input. A key
  # present under both spellings is refused rather than silently collapsed
  # to whichever value normalization visits last.
  defp solution_payload(solution) do
    normalized =
      Map.new(solution, fn
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        {key, value} -> {key, value}
      end)

    fields = Map.take(normalized, ~w(chg sol non tim tag))

    if map_size(normalized) == map_size(solution) and map_size(fields) == 5 and
         map_size(Map.drop(normalized, ~w(chg sol non tim tag dif))) == 0 and
         Enum.all?(fields, fn {_, value} -> is_binary(value) end) do
      {:ok, fields}
    else
      {:error, %Error{code: :bad_request}}
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

  def fake_last_magic_link(_, _), do: bad_request()

  # Validate before encoding: malformed caller data must neither raise in the
  # owner nor become a fatal protocol fault in the child.
  defp call(server, {:auth, _operation, payload} = request) do
    if valid_payload?(payload), do: server_call(server, request), else: bad_request()
  end

  defp call(server, request), do: server_call(server, request)

  defp valid_options?(opts, allowed) do
    Keyword.keyword?(opts) and length(opts) <= length(allowed) and
      Enum.all?(Keyword.keys(opts), &(&1 in allowed)) and
      length(opts) == length(Enum.uniq_by(opts, &elem(&1, 0)))
  end

  defp valid_payload?(payload) do
    Enum.all?(payload, fn
      {key, value} when key in [:terms_accepted, :privacy_accepted] ->
        is_boolean(value)

      {key, nil} when key in [:locale, :country] ->
        true

      {_key, value} when is_binary(value) ->
        byte_size(value) <= DatadeftAuth.Protocol.max_frame() and String.valid?(value)

      _ ->
        false
    end)
  end

  defp bad_request, do: {:error, %Error{code: :bad_request}}

  defp server_call(server, request) do
    GenServer.call(server, request, :infinity)
  catch
    :exit, _ -> {:error, %Error{code: :unavailable}}
  end
end
