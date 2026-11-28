defmodule DatadeftAuth.Token.Keyring do
  @moduledoc """
  Loaded cookie keys bound to their purpose and key ID. Exactly one active slot
  mints; other slots verify only. An active slot must verify through the full
  maximum cookie lifetime after its last minting instant.

  Roots must be independent 32-byte secrets loaded by the application. Slots are
  `{:active, kid, root, mint_until, verify_until}` or
  `{:verify_only, kid, root, verify_until}`. Times are Unix seconds, inclusive.
  Inspection is redacted; BEAM memory cannot guarantee zeroization.
  """

  @enforce_keys [:purpose, :active, :slots]
  defstruct [:purpose, :active, :slots]
  @type purpose :: :session | :confirm | :pow_proof
  @type slot ::
          {:active, binary(), binary(), non_neg_integer(), non_neg_integer()}
          | {:verify_only, binary(), binary(), non_neg_integer()}
  @opaque t :: %__MODULE__{purpose: purpose(), active: binary(), slots: map()}
  @u64_max 18_446_744_073_709_551_615

  @spec new(purpose(), [slot()]) :: {:ok, t()} | {:error, :keyring_misconfigured}
  def new(purpose, slots) when purpose in [:session, :confirm, :pow_proof] and is_list(slots) do
    result =
      Enum.reduce_while(slots, {:ok, nil, %{}}, fn slot, {:ok, active, keys} ->
        case add_slot(slot, purpose, active, keys) do
          {:ok, _, _} = result -> {:cont, result}
          :error -> {:halt, :error}
        end
      end)

    case result do
      {:ok, active, keys} when is_binary(active) ->
        {:ok, %__MODULE__{purpose: purpose, active: active, slots: keys}}

      _ ->
        {:error, :keyring_misconfigured}
    end
  end

  def new(_, _), do: {:error, :keyring_misconfigured}

  @doc false
  def purpose(%__MODULE__{purpose: purpose}), do: purpose

  @doc false
  def parameters(:session), do: {"auth/session-v1", "session-v1", 128, 73, 2_592_000}
  def parameters(:confirm), do: {"auth/magic-link-confirm-v1", "ml-confirm-v1", 256, 133, 300}
  def parameters(:pow_proof), do: {"auth/pow-proof-v1", "pow-proof-v1", 65, 34, 86_400}

  @doc false
  def valid_kid?(kid) when is_binary(kid) and byte_size(kid) in 1..64,
    do: Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, kid)

  def valid_kid?(_), do: false

  @doc false
  def minting_key(%__MODULE__{active: kid, slots: slots}, now) do
    case Map.fetch(slots, kid) do
      {:ok, {key, mint_until, _}} when is_integer(mint_until) and now <= mint_until ->
        {:ok, kid, key}

      _ ->
        {:error, :key_expired}
    end
  end

  @doc false
  def verification_key(%__MODULE__{slots: slots}, kid, now) do
    case Map.fetch(slots, kid) do
      {:ok, {key, _, verify_until}} when now <= verify_until -> {:ok, key}
      _ -> {:error, :invalid_token}
    end
  end

  defp add_slot({:active, kid, root, mint, verify}, purpose, nil, keys) do
    {_, _, _, _, lifetime} = parameters(purpose)

    if u64?(mint) and u64?(verify) and mint + lifetime <= verify,
      do: insert_slot(purpose, kid, root, mint, verify, kid, keys),
      else: :error
  end

  defp add_slot({:verify_only, kid, root, verify}, purpose, active, keys) do
    if u64?(verify),
      do: insert_slot(purpose, kid, root, nil, verify, active, keys),
      else: :error
  end

  defp add_slot(_, _, _, _), do: :error

  defp insert_slot(purpose, kid, root, mint, verify, active, keys) do
    {info, typ, cap, largest, _} = parameters(purpose)

    if valid_kid?(kid) and byte_size(kid) + byte_size(typ) + 7 + largest <= cap and
         is_binary(root) and byte_size(root) == 32 and not Map.has_key?(keys, kid) do
      # RFC 5869: absent salt is HashLen zero bytes; 32 output bytes take one block.
      prk = :crypto.mac(:hmac, :sha256, <<0::256>>, root)
      key = :crypto.mac(:hmac, :sha256, prk, [info, <<0>>, kid, <<1>>])
      {:ok, active, Map.put(keys, kid, {key, mint, verify})}
    else
      :error
    end
  end

  defp u64?(value), do: is_integer(value) and value in 0..@u64_max
end

defimpl Inspect, for: DatadeftAuth.Token.Keyring do
  def inspect(_, _), do: "#DatadeftAuth.Token.Keyring<redacted>"
end
