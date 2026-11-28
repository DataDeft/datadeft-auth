defmodule DatadeftAuth.MagicLink.Service.Flow do
  @moduledoc """
  Scanner-safe magic-link landing, flow-state reads, and atomic confirmation.
  This service does not enforce HTTP origin, CSRF or headers. The adapter must
  show the account, never confirm on GET, and accept only a same-origin POST
  before calling confirm. Never log token, cookie, confirmation or account data.
  """

  alias DatadeftAuth.MagicLink.Core.{ConfirmCookie, Email, Lookup, LookupKey, Token}

  alias DatadeftAuth.MagicLink.Service.{
    AuthenticationAttemptId,
    AuthenticationExpectation,
    Challenge,
    CommitAuthentication,
    CountryPolicy,
    SessionCookie,
    SessionId,
    User,
    UserId
  }

  alias DatadeftAuth.Token.Keyring

  defmodule Landing do
    @moduledoc "Read-only landing result. The flow cookie and account are sensitive."
    @derive {Inspect, only: [:cookie_max_age_secs]}
    @enforce_keys [:flow, :account, :cookie_max_age_secs]
    defstruct [:flow, :account, :cookie_max_age_secs]

    @type t :: %__MODULE__{
            flow: ConfirmCookie.Minted.t(),
            account: String.t(),
            cookie_max_age_secs: pos_integer()
          }
  end

  defmodule State do
    @moduledoc "Read-only confirmation page data. Do not log or cache."
    @derive {Inspect, only: []}
    @enforce_keys [:account, :confirmation]
    defstruct [:account, :confirmation]
    @type t :: %__MODULE__{account: String.t(), confirmation: binary()}
  end

  defmodule Authenticated do
    @moduledoc "Successful atomic confirmation. Send the cookie only on a no-store response."
    @derive {Inspect, only: [:user_created]}
    @enforce_keys [:session_cookie, :session_id, :user_id, :user_created, :country]
    defstruct [:session_cookie, :session_id, :user_id, :user_created, :country]

    @type t :: %__MODULE__{
            session_cookie: binary(),
            session_id: SessionId.t(),
            user_id: UserId.t(),
            user_created: boolean(),
            country: String.t() | nil
          }
  end

  @enforce_keys [:lookup_key, :cookie_keys, :versions, :io, :policy]
  defstruct [:lookup_key, :cookie_keys, :versions, :io, :policy]
  @opaque t :: %__MODULE__{}
  @type reason :: :magic_link_unavailable | :bad_request | :unavailable | :internal
  @type failure :: {:error, reason()}
  @type dependencies :: %{
          required(:repository) => {module(), term()},
          required(:limiter) => {module(), term()},
          required(:clock) => (-> {:ok, non_neg_integer()} | {:error, atom()})
        }
  @u64_max 18_446_744_073_709_551_615
  @u32_max 4_294_967_295
  @defaults [
    previous_lookup_key: nil,
    country_policy: :exact,
    enforce_country: false,
    account_display: :masked,
    magic_link_ttl: 600,
    flow_ttl: 300,
    session_absolute: 2_592_000,
    landing_limit: {30, 600},
    consume_limit: 5
  ]

  @doc """
  Configure the flow with independent lookup, confirm and session keys, the same
  consent versions and challenge TTL as the request issuer, and injected
  repository, limiter, and clock. The repository implements
  find_magic_link_for_authentication/2, find_user_for_authentication/2, and
  commit_magic_link_authentication/2. The limiter implements check_rate_limit/5.

  Options are previous_lookup_key, country_policy, enforce_country,
  account_display (:masked or :full), magic_link_ttl, flow_ttl, session_absolute,
  landing_limit ({count, seconds}), and consume_limit. TTLs are in seconds.
  """
  @spec new(
          LookupKey.t(),
          {Keyring.t(), Keyring.t()},
          {String.t(), String.t()},
          dependencies(),
          keyword()
        ) ::
          {:ok, t()} | {:error, :invalid_config}
  def new(key, keys, versions, io, opts \\ [])

  def new(
        %LookupKey{bytes: <<_::256>>} = key,
        {%Keyring{purpose: :confirm}, %Keyring{purpose: :session}} = keys,
        {terms, privacy} = versions,
        %{repository: repo, limiter: limiter, clock: clock} = io,
        opts
      )
      when is_binary(terms) and is_binary(privacy) and is_function(clock, 0) and is_list(opts) do
    with true <- String.valid?(terms) and String.valid?(privacy),
         true <-
           dependency?(repo,
             find_magic_link_for_authentication: 2,
             find_user_for_authentication: 2,
             commit_magic_link_authentication: 2
           ),
         true <- dependency?(limiter, check_rate_limit: 5),
         {:ok, policy} <- Keyword.validate(opts, @defaults),
         true <- valid_policy?(policy) do
      {:ok,
       %__MODULE__{
         lookup_key: key,
         cookie_keys: keys,
         versions: versions,
         io: io,
         policy: Map.new(policy)
       }}
    else
      _ -> {:error, :invalid_config}
    end
  end

  def new(_, _, _, _, _), do: {:error, :invalid_config}

  @doc "Throttle and inspect a link, without consuming it or creating an account or session."
  @spec land(t(), term()) :: {:ok, Landing.t()} | failure()
  def land(%__MODULE__{} = service, raw_token) do
    with {:ok, now} <- clock(service),
         {:ok, token} <- Token.parse(raw_token),
         {:ok, selector} <- Lookup.selector(service.lookup_key, token),
         :ok <- throttle(service, :landing, selector, now),
         {:ok, selector, verifier, row} <- landing_candidate(service, selector, token),
         {:ok, row} <- verify_candidate(row, verifier),
         :ok <- challenge_live(service, row, now),
         {:ok, account} <- Lookup.email(service.lookup_key, row.email),
         expiry = min(row.expires_at_unix, now + service.policy.flow_ttl),
         {confirm_keys, _} = service.cookie_keys,
         {:ok, flow} <-
           ConfirmCookie.mint(
             confirm_keys,
             {selector, verifier, account},
             expiry,
             now,
             &entropy/1
           ) do
      {:ok,
       %Landing{
         flow: flow,
         account: account_display(service, row.email),
         cookie_max_age_secs: expiry - now
       }}
    else
      error -> flow_error(error)
    end
  end

  @doc "Read bound confirmation page data. Throttled and side-effect-free except for the limiter."
  @spec read_state(t(), term()) :: {:ok, State.t()} | failure()
  def read_state(%__MODULE__{} = service, cookie) do
    {keys, _} = service.cookie_keys

    with {:ok, now} <- clock(service),
         {:ok, state} <- ConfirmCookie.read(keys, cookie, now, service.policy.flow_ttl),
         :ok <- throttle(service, :landing, state.selector, now),
         {:ok, row} <- read_challenge(service, state.selector),
         {:ok, row} <- verify_candidate(row, state.verifier),
         :ok <- challenge_live(service, row, now),
         :ok <- match_account(service, row, state.account) do
      {:ok,
       %State{
         account: account_display(service, row.email),
         confirmation: ConfirmCookie.confirmation(state)
       }}
    else
      error -> flow_error(error)
    end
  end

  @doc "Verify the separately submitted nonce and atomically consume the challenge and create a session."
  @spec confirm(t(), term(), term(), binary() | nil) :: {:ok, Authenticated.t()} | failure()
  def confirm(%__MODULE__{} = service, cookie, nonce, country) do
    {keys, _} = service.cookie_keys

    with :ok <- country_shape(country),
         {:ok, now} <- clock(service),
         {:ok, country} <- pin_country(service, country),
         {:ok, state} <- ConfirmCookie.verify(keys, cookie, nonce, now, service.policy.flow_ttl),
         :ok <- throttle(service, :consume, state.selector, now),
         {:ok, expected, user} <- load_authentication(service, state, now),
         {:ok, session_id, attempt_id, session_cookie} <- plan_session(service, country, now) do
      command = %CommitAuthentication{
        magic_link: expected,
        user: user,
        now_unix: now,
        attempt_id: attempt_id,
        session_id: session_id,
        session_expires_at_unix: now + service.policy.session_absolute
      }

      submit(service, state, country, command, session_cookie, 2)
    else
      error -> flow_error(error)
    end
  end

  @doc "Preserve temporary flow state only for retryable unavailability; clear on terminal failure."
  @spec temporary_state_action(reason()) :: :clear | :preserve
  def temporary_state_action(:unavailable), do: :preserve
  def temporary_state_action(_), do: :clear

  defp submit(service, state, country, command, cookie, remaining_replans) do
    case commit(service, command, 3) do
      :ok ->
        {branch, user_id} = command.user

        {:ok,
         %Authenticated{
           session_cookie: cookie,
           session_id: command.session_id,
           user_id: user_id,
           user_created: branch == :create,
           country: country
         }}

      {:error, :user_conflict} when remaining_replans > 0 ->
        with {:ok, expected, user} <- load_authentication(service, state, command.now_unix),
             {:ok, attempt_id} <- new_id(AuthenticationAttemptId, "aid-", 16) do
          next = %{command | magic_link: expected, user: user, attempt_id: attempt_id}
          submit(service, state, country, next, cookie, remaining_replans - 1)
        else
          error -> flow_error(error)
        end

      {:error, :session_conflict} when remaining_replans > 0 ->
        with {:ok, session_id, attempt_id, session_cookie} <-
               plan_session(service, country, command.now_unix) do
          next = %{command | session_id: session_id, attempt_id: attempt_id}
          submit(service, state, country, next, session_cookie, remaining_replans - 1)
        else
          error -> flow_error(error)
        end

      {:error, conflict} when conflict in [:session_conflict, :user_conflict] ->
        {:error, :unavailable}

      {:error, :rejected} ->
        {:error, :magic_link_unavailable}

      {:error, :unavailable} ->
        {:error, :unavailable}

      _ ->
        {:error, :internal}
    end
  end

  defp commit(%{io: %{repository: {repo, state}}} = service, command, remaining_attempts) do
    case repo.commit_magic_link_authentication(state, command) do
      {:error, :unavailable} when remaining_attempts > 1 ->
        commit(service, command, remaining_attempts - 1)

      result ->
        result
    end
  end

  defp load_authentication(%{io: %{repository: {repo, context}}} = service, state, now) do
    with {:ok, row} <- read_challenge(service, state.selector),
         {:ok, row} <- verify_candidate(row, state.verifier),
         :ok <- match_account(service, row, state.account),
         :ok <- challenge_live(service, row, now),
         {:ok, user} <- dependency(repo.find_user_for_authentication(context, row.email)),
         {:ok, user} <- plan_user(user, row.email) do
      {:ok,
       %AuthenticationExpectation{
         selector_lookup_hmac: state.selector,
         email: row.email,
         expires_at_unix: row.expires_at_unix,
         terms_version: row.terms_version,
         privacy_version: row.privacy_version,
         consented_at_unix: row.consented_at_unix
       }, user}
    end
  end

  defp plan_user(nil, _) do
    with {:ok, id} <- new_id(UserId, "usr-", 16), do: {:ok, {:create, id}}
  end

  defp plan_user(%User{email: email, disabled: false, user_id: %UserId{} = id}, email),
    do: {:ok, {:existing, id}}

  defp plan_user(_, _), do: {:error, :magic_link_unavailable}

  defp plan_session(%{cookie_keys: {_, ring}}, country, now) do
    with {:ok, id} <- new_id(SessionId, "sid-", 32),
         {:ok, cookie} <- SessionCookie.mint(ring, id, country, now, now),
         {:ok, attempt_id} <- new_id(AuthenticationAttemptId, "aid-", 16) do
      {:ok, id, attempt_id, cookie}
    end
  end

  defp new_id(module, prefix, count) do
    with {:ok, bytes} <- entropy(count),
         do: module.parse(prefix <> Base.encode16(bytes, case: :lower))
  end

  defp landing_candidate(service, selector, token) do
    with {:ok, verifier} <- Lookup.verifier(service.lookup_key, token),
         {:ok, row} <- read_challenge(service, selector) do
      if is_nil(row) and not is_nil(service.policy.previous_lookup_key) do
        previous = service.policy.previous_lookup_key

        with {:ok, selector} <- Lookup.selector(previous, token),
             {:ok, verifier} <- Lookup.verifier(previous, token),
             {:ok, row} <- read_challenge(service, selector),
             do: {:ok, selector, verifier, row}
      else
        {:ok, selector, verifier, row}
      end
    end
  end

  defp read_challenge(%{io: %{repository: {repo, state}}}, selector),
    do: dependency(repo.find_magic_link_for_authentication(state, selector))

  defp verify_candidate(nil, verifier) do
    _ = Lookup.matches?(verifier, verifier)
    {:error, :magic_link_unavailable}
  end

  defp verify_candidate(%Challenge{} = row, verifier) do
    if Lookup.matches?(row.verifier_hash, verifier),
      do: {:ok, row},
      else: {:error, :magic_link_unavailable}
  end

  defp verify_candidate(_, _), do: {:error, :internal}

  defp challenge_live(
         %{versions: {terms, privacy}},
         %Challenge{
           consumed_at_unix: nil,
           expires_at_unix: expires,
           terms_version: terms,
           privacy_version: privacy,
           consented_at_unix: consented
         },
         now
       )
       when is_integer(expires) and expires <= @u64_max and expires > now and
              is_integer(consented) and
              consented in 1..@u64_max,
       do: :ok

  defp challenge_live(_, _, _), do: {:error, :magic_link_unavailable}

  defp match_account(service, row, expected) do
    with {:ok, actual} <- Lookup.email(service.lookup_key, row.email) do
      if Lookup.matches?(actual, expected), do: :ok, else: {:error, :magic_link_unavailable}
    end
  end

  defp account_display(%{policy: %{account_display: :full}}, email), do: Email.value(email)

  defp account_display(_, email) do
    [<<first::utf8, _::binary>>, domain] = :binary.split(Email.value(email), "@")
    <<first::utf8>> <> "•••••@" <> domain
  end

  defp country_shape(nil), do: :ok
  defp country_shape(<<a, b>>) when a in ?A..?Z and b in ?A..?Z, do: :ok
  defp country_shape(_), do: {:error, :bad_request}

  defp pin_country(%{policy: %{country_policy: policy, enforce_country: required}}, country) do
    case CountryPolicy.pin(policy, country) do
      nil when required -> {:error, :magic_link_unavailable}
      pinned -> {:ok, pinned}
    end
  end

  defp throttle(%{io: %{limiter: {limiter, context}}, policy: policy}, stage, selector, now) do
    {limit, seconds} =
      case stage do
        :landing -> policy.landing_limit
        :consume -> {policy.consume_limit, policy.magic_link_ttl}
      end

    key = "magic-link:" <> Atom.to_string(stage) <> ":selector:" <> Lookup.storage_value(selector)

    case dependency(limiter.check_rate_limit(context, key, limit, seconds, now)) do
      {:ok, :allowed} -> :ok
      {:ok, :denied} -> {:error, :magic_link_unavailable}
      {:error, _} = error -> error
      _ -> {:error, :internal}
    end
  end

  defp clock(%{io: %{clock: clock}}) do
    case dependency(clock.()) do
      {:ok, now} when is_integer(now) and now in 0..@u64_max -> {:ok, now}
      {:error, _} = error -> error
      _ -> {:error, :internal}
    end
  end

  defp dependency({:ok, _} = success), do: success

  defp dependency({:error, reason})
       when reason in [:unavailable, :rate_limited, :conditional_write_failed],
       do: {:error, :unavailable}

  defp dependency(_), do: {:error, :internal}

  defp flow_error({:error, :invalid_token}), do: {:error, :magic_link_unavailable}

  defp flow_error({:error, error} = result)
       when error in [:magic_link_unavailable, :bad_request, :unavailable], do: result

  defp flow_error({:error, reason}) when reason in [:key_expired, :entropy_unavailable],
    do: {:error, :unavailable}

  defp flow_error(_), do: {:error, :internal}

  defp valid_policy?(opts) do
    previous = opts[:previous_lookup_key]
    country = opts[:country_policy]

    (is_nil(previous) or match?(%LookupKey{bytes: <<_::256>>}, previous)) and
      (country == :exact or is_struct(country, CountryPolicy)) and
      is_boolean(opts[:enforce_country]) and opts[:account_display] in [:masked, :full] and
      positive_bounded?(opts[:magic_link_ttl], @u64_max) and
      positive_bounded?(opts[:flow_ttl], 300) and
      positive_bounded?(opts[:session_absolute], 2_592_000) and
      positive_bounded?(opts[:consume_limit], @u32_max) and valid_window?(opts[:landing_limit])
  end

  defp valid_window?({count, seconds}),
    do: positive_bounded?(count, @u32_max) and positive_bounded?(seconds, @u64_max)

  defp valid_window?(_), do: false
  defp positive_bounded?(value, max), do: is_integer(value) and value > 0 and value <= max

  defp dependency?({module, _}, callbacks) when is_atom(module),
    do:
      Code.ensure_loaded?(module) and
        Enum.all?(callbacks, fn {name, arity} -> function_exported?(module, name, arity) end)

  defp dependency?(_, _), do: false

  defp entropy(bytes) do
    {:ok, :crypto.strong_rand_bytes(bytes)}
  rescue
    _ -> {:error, :entropy_unavailable}
  end
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Flow do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Flow<redacted>"
end
