defmodule DatadeftAuth.MagicLink.Service.UserId do
  @moduledoc "Canonical Rust-compatible user identifier. Redacted on inspection."
  @enforce_keys [:value]
  defstruct [:value]

  @opaque t :: %__MODULE__{value: String.t()}

  @spec parse(term()) :: {:ok, t()} | {:error, :invalid_user_id}
  def parse("usr-" <> hex = value) when byte_size(hex) == 32 do
    if Regex.match?(~r/\A[0-9a-f]+\z/, hex),
      do: {:ok, %__MODULE__{value: value}},
      else: {:error, :invalid_user_id}
  end

  def parse(_), do: {:error, :invalid_user_id}

  @doc "Explicit identifier access for storage and application use. Do not log."
  @spec value(t()) :: String.t()
  def value(%__MODULE__{value: value}), do: value
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.UserId do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.UserId<redacted>"
end
