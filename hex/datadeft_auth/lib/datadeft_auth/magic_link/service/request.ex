defmodule DatadeftAuth.MagicLink.Service.Request do
  @moduledoc """
  Issue Rust-compatible magic links with independent keyed request/outbox
  limits. Render the same generic accepted HTTP response for sent and
  throttled. Edge/IP/global controls belong to the consuming app.

  Dependencies are supplied as a map. The repository is a {module, state}
  implementing put_magic_link_if_absent/2; the limiter implements
  check_rate_limit/5; the outbox implements enqueue_magic_link/2 (accepting a
  Mail, returning :ok or a fixed dependency error). The clock returns
  {:ok, unix_seconds}. Limiter callbacks must support concurrent calls and
  bound their own IO; every bucket must be charged even on denial.
  """
  alias DatadeftAuth.MagicLink.Core.{Email, Lookup, LookupKey, Token}
  alias DatadeftAuth.MagicLink.Service.{Challenge, LocaleAllowlist, Mail, Session}

  @u64_max 18_446_744_073_709_551_615
  @u32_max 4_294_967_295
  @buckets [
    {"request:email:short", :email_short_window, 3, 900},
    {"request:email:daily", :email_daily, 10, 86_400},
    {"outbox:email:hourly", :outbox_hourly, 3, 3600},
    {"outbox:email:daily", :outbox_daily, 10, 86_400}
  ]

  @enforce_keys [:lookup_key, :versions, :io, :ttl, :buckets, :locales]
  defstruct [:lookup_key, :versions, :io, :ttl, :buckets, :locales]
  @opaque t :: %__MODULE__{}
  @type throttle :: :email_short_window | :email_daily | :outbox_hourly | :outbox_daily
  @type dependency :: {module(), term()}
  @type dependencies :: %{
          required(:repository) => dependency(),
          required(:limiter) => dependency(),
          required(:outbox) => dependency(),
          required(:clock) => Session.clock()
        }
  @type failure :: {:error, :bad_request | :unavailable | :outbox_unavailable | :internal}

  @doc """
  Configure consent versions and injected IO. Optional keys: :ttl (default
  600 seconds), :locales (a LocaleAllowlist), and :rate_limits (a map from
  throttle bucket to {positive_limit, positive_window_seconds}).
  """
  @spec new(LookupKey.t(), {String.t(), String.t()}, dependencies(), keyword()) ::
          {:ok, t()} | {:error, :invalid_config}
  def new(key, versions, io, opts \\ [])

  def new(
        %LookupKey{bytes: bytes} = key,
        {terms, privacy} = versions,
        %{repository: repo, limiter: limiter, outbox: outbox, clock: clock} = io,
        opts
      )
      when is_binary(bytes) and byte_size(bytes) == 32 and is_binary(terms) and
             is_binary(privacy) and is_function(clock, 0) and is_list(opts) do
    with true <- String.valid?(terms) and String.valid?(privacy),
         true <-
           dependency?(repo, :put_magic_link_if_absent, 2) and
             dependency?(limiter, :check_rate_limit, 5) and
             dependency?(outbox, :enqueue_magic_link, 2),
         {:ok, opts} <- Keyword.validate(opts, ttl: 600, locales: nil, rate_limits: %{}),
         ttl when is_integer(ttl) and ttl in 1..@u64_max <- opts[:ttl],
         locales when is_nil(locales) or is_struct(locales, LocaleAllowlist) <- opts[:locales],
         {:ok, buckets} <- configure_buckets(opts[:rate_limits]) do
      {:ok,
       %__MODULE__{
         lookup_key: key,
         versions: versions,
         io: io,
         ttl: ttl,
         buckets: buckets,
         locales: locales
       }}
    else
      _ -> {:error, :invalid_config}
    end
  end

  def new(_, _, _, _), do: {:error, :invalid_config}

  @doc "Require both consents, check limits, store a challenge, then hand it to the outbox."
  @spec request(t(), term(), term(), term(), term()) ::
          {:ok, :sent | {:throttled, throttle()}} | failure()
  def request(service, email, terms_accepted, privacy_accepted, hint \\ nil)

  def request(%__MODULE__{} = service, email, true, true, hint) do
    case Email.normalize(email) do
      {:ok, email} -> issue(service, email, hint)
      {:error, _} -> {:error, :bad_request}
    end
  end

  def request(%__MODULE__{}, _, _, _, _), do: {:error, :bad_request}

  defp issue(service, email, hint) do
    with {:ok, now} <- call_clock(service.io.clock),
         expires = now + service.ttl,
         true <- expires <= @u64_max,
         {:ok, lookup} <- Lookup.email(service.lookup_key, email),
         :allowed <- charge_all(service, Lookup.storage_value(lookup), now),
         {:ok, token} <- Token.generate(&entropy/1),
         {:ok, selector} <- Lookup.selector(service.lookup_key, token),
         {:ok, verifier} <- Lookup.verifier(service.lookup_key, token) do
      {terms, privacy} = service.versions

      record = %Challenge{
        email: email,
        selector_lookup_hmac: selector,
        verifier_hash: verifier,
        expires_at_unix: expires,
        consented_at_unix: now,
        terms_version: terms,
        privacy_version: privacy
      }

      message = %Mail{
        email: email,
        token: token,
        expires_at_unix: expires,
        locale: locale(service.locales, hint)
      }

      persist_then_deliver(service.io, record, message)
    else
      {:throttled, _} = throttled -> {:ok, throttled}
      {:error, :entropy_unavailable} -> {:error, :unavailable}
      {:error, reason} -> dependency_error(reason)
      _ -> {:error, :internal}
    end
  end

  defp persist_then_deliver(%{repository: {repo, state}, outbox: {outbox, target}}, record, mail) do
    case repo.put_magic_link_if_absent(state, record) do
      :ok ->
        case outbox.enqueue_magic_link(target, mail) do
          :ok ->
            {:ok, :sent}

          {:error, reason}
          when reason in [:unavailable, :rate_limited, :conditional_write_failed] ->
            {:error, :outbox_unavailable}

          _ ->
            {:error, :internal}
        end

      {:error, reason} ->
        dependency_error(reason)

      _ ->
        {:error, :internal}
    end
  end

  defp charge_all(%{io: %{limiter: {limiter, state}}, buckets: buckets}, lookup, now) do
    buckets
    |> Task.async_stream(
      fn {path, bucket, limit, window} ->
        {bucket,
         limiter_check(limiter, state, "magic-link:" <> path <> ":" <> lookup, limit, window, now)}
      end,
      max_concurrency: length(buckets),
      timeout: :infinity
    )
    |> Enum.reduce(:allowed, &account/2)
  end

  defp limiter_check(limiter, state, key, limit, window, now) do
    limiter.check_rate_limit(state, key, limit, window, now)
  rescue
    _ -> {:error, :internal}
  catch
    _, _ -> {:error, :internal}
  end

  defp account(_, {:error, _} = error), do: error
  defp account({:ok, {_, {:error, reason}}}, _), do: dependency_error(reason)
  defp account({:ok, {bucket, {:ok, :denied}}}, :allowed), do: {:throttled, bucket}
  defp account({:ok, {_, {:ok, decision}}}, prior) when decision in [:allowed, :denied], do: prior
  defp account(_, _), do: {:error, :internal}

  defp call_clock(clock) do
    case clock.() do
      {:ok, now} when is_integer(now) and now in 0..@u64_max -> {:ok, now}
      {:error, reason} -> dependency_error(reason)
      _ -> {:error, :internal}
    end
  end

  defp configure_buckets(overrides) when is_map(overrides) do
    bucket_names = Enum.map(@buckets, &elem(&1, 1))

    if Enum.all?(overrides, fn
         {name, {limit, window}}
         when is_integer(limit) and limit in 1..@u32_max and
                is_integer(window) and window in 1..@u64_max ->
           name in bucket_names

         _ ->
           false
       end) do
      {:ok,
       Enum.map(@buckets, fn {path, name, limit, window} ->
         {limit, window} = Map.get(overrides, name, {limit, window})
         {path, name, limit, window}
       end)}
    else
      {:error, :invalid_config}
    end
  end

  defp configure_buckets(_), do: {:error, :invalid_config}

  defp dependency?({module, _}, callback, arity) when is_atom(module),
    do: Code.ensure_loaded?(module) and function_exported?(module, callback, arity)

  defp dependency?(_, _, _), do: false

  defp dependency_error(reason)
       when reason in [:unavailable, :rate_limited, :conditional_write_failed],
       do: {:error, :unavailable}

  defp dependency_error(_), do: {:error, :internal}

  defp locale(nil, _), do: nil
  defp locale(list, hint), do: LocaleAllowlist.resolve(list, hint)

  defp entropy(bytes) do
    {:ok, :crypto.strong_rand_bytes(bytes)}
  rescue
    _ -> {:error, :entropy_unavailable}
  end
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Request do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Request<redacted>"
end
