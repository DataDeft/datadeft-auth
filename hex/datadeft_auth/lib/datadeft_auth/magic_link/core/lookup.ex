defmodule DatadeftAuth.MagicLink.Core.Lookup do
  @moduledoc """
  Role-bound, keyed magic-link lookup material. Only explicit accessors expose
  storage strings or flow-binding bytes; inspect is redacted. Compare stored
  secret-derived values with `matches?/2`, never structural equality.
  """
  alias DatadeftAuth.MagicLink.Core.{Email, LookupKey, Token}
  @enforce_keys [:kind, :bytes]
  defstruct [:kind, :bytes]
  @type kind :: :email | :selector | :verifier
  @opaque t :: %__MODULE__{kind: kind(), bytes: binary()}

  @spec email(LookupKey.t(), Email.t()) :: {:ok, t()} | {:error, atom()}
  def email(key, %Email{} = email) do
    with {:ok, email} <- Email.from_normalized(Email.value(email)) do
      derive(key, :email, Email.value(email))
    end
  end

  @spec selector(LookupKey.t(), Token.t()) :: {:ok, t()} | {:error, atom()}
  def selector(key, %Token{} = token) do
    with {:ok, _} <- Token.parse(Token.value(token)) do
      derive(key, :selector, Token.selector(token))
    end
  end

  @spec verifier(LookupKey.t(), Token.t()) :: {:ok, t()} | {:error, atom()}
  def verifier(key, %Token{} = token) do
    with {:ok, _} <- Token.parse(Token.value(token)) do
      derive(key, :verifier, Token.verifier(token))
    end
  end

  @spec parse(kind(), term()) :: {:ok, t()} | {:error, :invalid_token}
  def parse(kind, <<encoded_prefix::binary-size(3), "_", hex::binary-size(64)>>)
      when kind in [:email, :selector, :verifier] do
    with true <- encoded_prefix == prefix(kind),
         {:ok, bytes} <- Base.decode16(hex, case: :lower) do
      {:ok, %__MODULE__{kind: kind, bytes: bytes}}
    else
      _ -> {:error, :invalid_token}
    end
  end

  def parse(_, _), do: {:error, :invalid_token}

  @doc "Canonical storage representation; do not log."
  @spec storage_value(t()) :: String.t()
  def storage_value(%__MODULE__{kind: kind, bytes: bytes}),
    do: prefix(kind) <> "_" <> Base.encode16(bytes, case: :lower)

  @doc "Sensitive fixed-size bytes for typed flow bindings; do not log."
  @spec binding(t()) :: binary()
  def binding(%__MODULE__{bytes: bytes}), do: bytes

  @spec matches?(t(), t()) :: boolean()
  def matches?(%__MODULE__{kind: kind, bytes: left}, %__MODULE__{kind: kind, bytes: right})
      when is_binary(left) and byte_size(left) == 32 and is_binary(right) and
             byte_size(right) == 32,
      do: :crypto.hash_equals(left, right)

  def matches?(_, _), do: false

  defp derive(key, kind, value) do
    with {:ok, bytes} <- LookupKey.mac(key, prefix(kind), value) do
      {:ok, %__MODULE__{kind: kind, bytes: bytes}}
    end
  end

  defp prefix(:email), do: "emh"
  defp prefix(:selector), do: "mlh"
  defp prefix(:verifier), do: "mlv"
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.Lookup do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.Lookup<redacted>"
end
