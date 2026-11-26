defmodule DatadeftAuth.MagicLink.Core.LookupKey do
  @moduledoc "Loaded magic-link HMAC key; distinct from storage and cookie keys."
  @enforce_keys [:bytes]
  defstruct [:bytes]
  @opaque t :: %__MODULE__{bytes: binary()}

  @spec new(term()) :: {:ok, t()} | {:error, :bad_key_length}
  def new(bytes) when is_binary(bytes) and byte_size(bytes) == 32,
    do: {:ok, %__MODULE__{bytes: bytes}}

  def new(_), do: {:error, :bad_key_length}

  @doc false
  def mac(%__MODULE__{bytes: key}, prefix, value)
      when is_binary(key) and byte_size(key) == 32 and prefix in ["emh", "mlh", "mlv"] and
             is_binary(value) do
    {:ok, :crypto.mac(:hmac, :sha256, key, ["magic-link-lookup-v1", <<0>>, prefix, <<0>>, value])}
  end

  def mac(_, _, _), do: {:error, :invalid_token}
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.LookupKey do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.LookupKey<redacted>"
end
