defmodule DatadeftAuth.AWS.StorageKey do
  @moduledoc """
  A loaded 32-byte storage HMAC key, bound to Rust's AWS storage domain.

  Inspect is redacted. BEAM does not provide deterministic secret zeroization.
  This key is distinct from the magic-link lookup key and cookie roots.
  """

  @enforce_keys [:bytes]
  defstruct [:bytes]

  @opaque t :: %__MODULE__{bytes: binary()}
  @domain "magic-link-aws-storage-v1"

  @spec new(term()) :: {:ok, t()} | {:error, :bad_key_length}
  def new(bytes) when is_binary(bytes) and byte_size(bytes) == 32,
    do: {:ok, %__MODULE__{bytes: bytes}}

  def new(_), do: {:error, :bad_key_length}

  @doc false
  @spec hmac(t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, :invalid_framing}
  def hmac(%__MODULE__{bytes: bytes}, prefix, value)
      when is_binary(bytes) and byte_size(bytes) == 32 and is_binary(prefix) and
             is_binary(value) do
    if String.valid?(prefix) and String.valid?(value) and
         :binary.match(prefix, <<0>>) == :nomatch do
      digest = :crypto.mac(:hmac, :sha256, bytes, [@domain, <<0>>, prefix, <<0>>, value])
      {:ok, prefix <> "_" <> Base.encode16(digest, case: :lower)}
    else
      {:error, :invalid_framing}
    end
  end

  def hmac(_, _, _), do: {:error, :invalid_framing}

  @doc false
  @spec same?(t(), t()) :: boolean()
  def same?(%__MODULE__{bytes: left}, %__MODULE__{bytes: right})
      when is_binary(left) and byte_size(left) == 32 and is_binary(right) and
             byte_size(right) == 32,
      do: :crypto.hash_equals(left, right)

  def same?(_, _), do: false
end

defimpl Inspect, for: DatadeftAuth.AWS.StorageKey do
  def inspect(_, _), do: "#DatadeftAuth.AWS.StorageKey<redacted>"
end
