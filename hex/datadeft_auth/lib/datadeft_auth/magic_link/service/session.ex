defmodule DatadeftAuth.MagicLink.Service.Session do
  @moduledoc """
  Framework-neutral server-side session admission, explicit sliding refresh and
  logout-specific validation. Injectable clock and repository; never does HTTP.

  Only normal validation authorizes access. Logout verification skips idle and
  country checks but preserves all absolute and authoritative storage checks.
  Revoke before clearing the cookie in a CSRF-protected, same-origin handler.
  """
  alias DatadeftAuth.MagicLink.Service.{
    CountryPolicy,
    SessionCookie,
    SessionId,
    SessionRecord,
    UserId
  }

  alias DatadeftAuth.Token.Keyring

  defmodule Validated do
    @moduledoc false
    @enforce_keys [:record, :cookie, :validated_at]
    defstruct [:record, :cookie, :validated_at]

    @opaque t :: %__MODULE__{
              record: SessionRecord.t(),
              cookie: SessionCookie.t(),
              validated_at: non_neg_integer()
            }
  end

  @enforce_keys [:keyring, :repository, :clock, :ages, :country_policy]
  defstruct [:keyring, :repository, :clock, :ages, :country_policy]

  @opaque t :: %__MODULE__{
            keyring: Keyring.t(),
            repository: {module(), term()},
            clock: clock(),
            ages: ages(),
            country_policy: CountryPolicy.t()
          }
  @type ages :: {pos_integer(), pos_integer()}
  @type clock :: (-> {:ok, non_neg_integer()} | {:error, atom()})
  @type failure :: {:error, :invalid_session | :unavailable | :internal}
  @u64_max 18_446_744_073_709_551_615
  @skew 60

  @spec new(Keyring.t(), {module(), term()}, clock(), ages(), CountryPolicy.t()) ::
          {:ok, t()} | {:error, :invalid_config}
  def new(keyring, repository, clock, ages \\ {86_400, 2_592_000}, policy \\ :exact)

  def new(
        %Keyring{purpose: :session} = keys,
        {module, _} = repository,
        clock,
        {idle, absolute} = ages,
        policy
      )
      when is_atom(module) and is_function(clock, 0) and is_integer(idle) and is_integer(absolute) and
             idle > 0 and idle <= absolute and absolute <= 2_592_000 do
    if (policy == :exact or match?(%CountryPolicy{}, policy)) and Code.ensure_loaded?(module) and
         Enum.all?(
           [:find_session, :is_session_owner_active, :revoke_session],
           &function_exported?(module, &1, 3)
         ) do
      {:ok,
       %__MODULE__{
         keyring: keys,
         repository: repository,
         clock: clock,
         ages: ages,
         country_policy: policy
       }}
    else
      {:error, :invalid_config}
    end
  end

  def new(_, _, _, _, _), do: {:error, :invalid_config}

  @doc "Validate authenticated cookie, trusted-edge country pin, live session, and account status. Read-only."
  @spec validate(t(), binary(), binary() | nil) :: {:ok, Validated.t()} | failure()
  def validate(%__MODULE__{} = service, cookie, country),
    do: check(service, cookie, {:authenticate, country})

  @doc "Obtain only a revocation target, not a result usable by refresh or admission."
  @spec validate_for_logout(t(), binary()) :: {:ok, SessionRecord.t()} | failure()
  def validate_for_logout(%__MODULE__{} = service, cookie) do
    with {:ok, %Validated{record: record}} <- check(service, cookie, :logout),
         do: {:ok, record}
  end

  @doc "Read the authoritative record from a successful normal validation."
  @spec record(Validated.t()) :: SessionRecord.t()
  def record(%Validated{record: record}), do: record

  @doc "Revoke server state. Call with the ID from logout validation, before clearing cookies."
  @spec revoke(t(), SessionId.t()) :: :ok | failure()
  def revoke(%__MODULE__{repository: {module, repo}} = service, %SessionId{} = id) do
    with {:ok, now} <- now(service) do
      case module.revoke_session(repo, id, now) do
        :ok -> :ok
        {:error, reason} -> dependency_error(reason)
        _ -> {:error, :internal}
      end
    end
  end

  @doc """
  Refresh a normally validated cookie in the same request, preserving its initial
  issue time, session ID and country. Returns nil until half the idle age elapses.
  Never log the resulting cookie; send it only on a no-store response.
  """
  @spec refresh(t(), Validated.t()) :: {:ok, binary() | nil} | failure()
  def refresh(
        %__MODULE__{ages: {idle, absolute}} = service,
        %Validated{cookie: cookie, validated_at: validated_at}
      ) do
    with {:ok, now} <- now(service) do
      cond do
        now < validated_at or now - validated_at > @skew ->
          {:error, :invalid_session}

        cookie.issued_at_unix > now or max(0, now - cookie.last_activity_unix) < div(idle, 2) ->
          {:ok, nil}

        now - cookie.issued_at_unix >= absolute ->
          {:ok, nil}

        true ->
          case SessionCookie.mint(
                 service.keyring,
                 cookie.session_id,
                 cookie.country,
                 now,
                 cookie.issued_at_unix
               ) do
            {:ok, value} -> {:ok, value}
            {:error, :unavailable} -> {:error, :unavailable}
            {:error, _} -> {:error, :internal}
          end
      end
    end
  end

  def refresh(_, _), do: {:error, :invalid_session}

  defp check(%{repository: {module, repo}, ages: {idle, absolute}} = service, value, use) do
    ages = if use == :logout, do: {absolute, absolute}, else: {idle, absolute}

    with {:ok, now} <- now(service),
         {:ok, cookie} <- SessionCookie.open(service.keyring, value, now, ages),
         true <- country_matches?(service.country_policy, cookie.country, use),
         {:ok, %SessionRecord{} = row} <- module.find_session(repo, cookie.session_id, now),
         true <- live?(row, cookie.session_id, now, absolute),
         {:ok, true} <- module.is_session_owner_active(repo, row.user_id, row.created_at_unix) do
      {:ok, %Validated{record: row, cookie: cookie, validated_at: now}}
    else
      {:error, :invalid_token} -> {:error, :invalid_session}
      {:error, reason} -> dependency_error(reason)
      {:ok, none} when none in [nil, false] -> {:error, :invalid_session}
      false -> {:error, :invalid_session}
      _ -> {:error, :internal}
    end
  end

  defp live?(
         %SessionRecord{
           session_id: %SessionId{} = stored,
           revoked_at_unix: nil,
           user_id: %UserId{},
           created_at_unix: created
         },
         id,
         now,
         absolute
       )
       when is_integer(created) and created in 0..@u64_max do
    case SessionId.parse(SessionId.value(stored)) do
      {:ok, parsed} ->
        :crypto.hash_equals(SessionId.value(parsed), SessionId.value(id)) and
          created - now <= @skew and now - created <= absolute

      _ ->
        false
    end
  end

  defp live?(_, _, _, _), do: false

  defp country_matches?(_, _, :logout), do: true
  defp country_matches?(_, nil, _), do: true

  defp country_matches?(policy, bound, {:authenticate, request}),
    do: CountryPolicy.pin(policy, request) == bound

  defp now(%__MODULE__{clock: clock}) do
    case clock.() do
      {:ok, now} when is_integer(now) and now in 0..@u64_max -> {:ok, now}
      {:error, reason} -> dependency_error(reason)
      _ -> {:error, :internal}
    end
  end

  defp dependency_error(reason) when reason in [:unavailable, :rate_limited],
    do: {:error, :unavailable}

  defp dependency_error(_), do: {:error, :internal}
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Session do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Session<redacted>"
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Session.Validated do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Session.Validated<redacted>"
end
