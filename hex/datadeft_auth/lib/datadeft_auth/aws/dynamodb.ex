defmodule DatadeftAuth.AWS.DynamoDB do
  @moduledoc """
  Rust-compatible DynamoDB adapter, implemented incrementally.

  Currently provides account lookup with storage-key rotation/rekeying,
  fixed-window limits and lifetime PoW budgets. Authentication commits are not
  implemented yet; do not use this partial adapter for a production cutover.
  The client is an explicit `{module, state}` implementing
  `DatadeftAuth.AWS.DynamoDB.Client`; no production HTTP client is bundled yet.
  """

  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey

  @enforce_keys [:table, :storage_key, :client, :cleanup_grace_secs]
  defstruct [:table, :storage_key, :client, :cleanup_grace_secs, previous_storage_key: nil]

  @opaque t :: %__MODULE__{
            table: String.t(),
            storage_key: StorageKey.t(),
            previous_storage_key: StorageKey.t() | nil,
            client: {module(), term()},
            cleanup_grace_secs: non_neg_integer()
          }
  @type decision :: {:ok, :allowed | :denied} | {:error, atom()}
  @u64_max 18_446_744_073_709_551_615
  @u32_max 4_294_967_295
  @table_name ~r/\A[A-Za-z0-9_.-]+\z/
  @condition "attribute_not_exists(#count) OR #count < :limit"

  @spec new(String.t(), StorageKey.t(), {module(), term()}, non_neg_integer()) ::
          {:ok, t()} | {:error, :invalid_config}
  def new(table, key, client, cleanup_grace_secs \\ 86_400)

  def new(table, %StorageKey{} = key, {module, _} = client, grace)
      when is_binary(table) and byte_size(table) in 3..255 and is_atom(module) and
             is_integer(grace) and grace >= 0 and grace <= @u64_max do
    if Regex.match?(@table_name, table) and StorageKey.same?(key, key) and
         Code.ensure_loaded?(module) and function_exported?(module, :request, 3) do
      {:ok,
       %__MODULE__{table: table, storage_key: key, client: client, cleanup_grace_secs: grace}}
    else
      {:error, :invalid_config}
    end
  end

  def new(_, _, _, _), do: {:error, :invalid_config}

  @doc "Configure a verify/read-only previous storage key for a rotation window."
  @spec with_previous_storage_key(t(), StorageKey.t()) :: {:ok, t()} | {:error, :invalid_config}
  def with_previous_storage_key(%__MODULE__{} = store, %StorageKey{} = key) do
    if StorageKey.same?(key, key) do
      previous = if StorageKey.same?(store.storage_key, key), do: nil, else: key
      {:ok, %{store | previous_storage_key: previous}}
    else
      {:error, :invalid_config}
    end
  end

  def with_previous_storage_key(_, _), do: {:error, :invalid_config}

  @doc "Idempotently rekey email lookups before retiring the previous storage key."
  @spec rekey_email_lookups(t()) :: {:ok, non_neg_integer()} | {:error, atom()}
  def rekey_email_lookups(%__MODULE__{} = store),
    do: DatadeftAuth.AWS.DynamoDB.Rotation.rekey(store)

  @doc "Read a normalized account through its keyed lookup and authoritative profile."
  @spec find_user_for_authentication(t(), DatadeftAuth.MagicLink.Core.Email.t()) ::
          {:ok, DatadeftAuth.MagicLink.Service.User.t() | nil}
          | {:error, :unavailable | :internal}
  def find_user_for_authentication(%__MODULE__{} = store, email),
    do: DatadeftAuth.AWS.DynamoDB.Users.find(store, email)

  @doc "Admit at most `limit` uses over the proof's entire lifetime, across nodes."
  @spec check_lifetime_limit(
          t(),
          String.t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer()
        ) ::
          decision()
  def check_lifetime_limit(%__MODULE__{} = store, key, limit, expires, now)
      when is_integer(limit) and limit >= 0 and limit <= @u32_max and
             is_integer(expires) and expires >= 0 and expires <= @u64_max and
             is_integer(now) and now >= 0 and now <= @u64_max do
    with {:ok, key} <- Keys.lifetime_rate(key) do
      if limit == 0 or expires <= now do
        {:ok, :denied}
      else
        increment(
          store,
          key,
          limit,
          "SET #entity_type = if_not_exists(#entity_type, :entity), #expires = if_not_exists(#expires, :expires), #ttl = if_not_exists(#ttl, :ttl) ADD #count :one",
          %{
            "#entity_type" => "entity_type",
            "#expires" => "expires_at_unix",
            "#ttl" => "ttl",
            "#count" => "count"
          },
          %{
            ":entity" => %{"S" => "lifetime_counter"},
            ":expires" => number(expires),
            ":ttl" => number(saturating_add(expires, store.cleanup_grace_secs))
          }
        )
      end
    end
  end

  def check_lifetime_limit(_, _, _, _, _), do: {:error, :invalid_input}

  @doc "Admit a bounded fixed-window attempt; a zero-second window uses bucket zero."
  @spec check_rate_limit(t(), String.t(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          decision()
  def check_rate_limit(%__MODULE__{} = store, key, limit, window_secs, now)
      when is_integer(limit) and limit >= 0 and limit <= @u32_max and
             is_integer(window_secs) and window_secs >= 0 and window_secs <= @u64_max and
             is_integer(now) and now >= 0 and now <= @u64_max do
    with {:ok, key} <- Keys.rate(store.storage_key, key, window_secs, now) do
      if limit == 0 do
        {:ok, :denied}
      else
        start = if window_secs == 0, do: 0, else: div(now, window_secs) * window_secs
        expires = saturating_add(start, window_secs)

        increment(
          store,
          key,
          limit,
          "SET #entity_type = if_not_exists(#entity_type, :entity), #window_start = if_not_exists(#window_start, :window_start), #window_expires = if_not_exists(#window_expires, :window_expires), #ttl = if_not_exists(#ttl, :ttl) ADD #count :one",
          %{
            "#entity_type" => "entity_type",
            "#window_start" => "window_start_unix",
            "#window_expires" => "window_expires_unix",
            "#ttl" => "ttl",
            "#count" => "count"
          },
          %{
            ":entity" => %{"S" => "rate_counter"},
            ":window_start" => number(start),
            ":window_expires" => number(expires),
            ":ttl" => number(saturating_add(expires, store.cleanup_grace_secs))
          }
        )
      end
    end
  end

  def check_rate_limit(_, _, _, _, _), do: {:error, :invalid_input}

  defp increment(store, key, limit, update, names, values) do
    {module, state} = store.client

    input = %{
      "TableName" => store.table,
      "Key" => key,
      "UpdateExpression" => update,
      "ConditionExpression" => @condition,
      "ExpressionAttributeNames" => names,
      "ExpressionAttributeValues" =>
        Map.merge(values, %{":limit" => number(limit), ":one" => number(1)})
    }

    case module.request(state, "UpdateItem", input) do
      {:ok, output} when is_map(output) -> {:ok, :allowed}
      {:error, :conditional_write_failed} -> {:ok, :denied}
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  defp number(value), do: %{"N" => Integer.to_string(value)}
  defp saturating_add(left, right), do: min(left + right, @u64_max)
end

defimpl Inspect, for: DatadeftAuth.AWS.DynamoDB do
  def inspect(_, _), do: "#DatadeftAuth.AWS.DynamoDB<redacted>"
end
