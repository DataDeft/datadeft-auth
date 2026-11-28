defmodule DatadeftAuth.MagicLink.Service.SessionId do
  @moduledoc "Canonical Rust-compatible SessionId. Explicit access only; inspect is redacted."
  @enforce_keys [:value]
  defstruct [:value]
  @opaque t :: %__MODULE__{value: String.t()}

  @spec parse(term()) :: {:ok, t()} | {:error, :invalid_session_id}
  def parse("sid-" <> hex = value) when byte_size(hex) == 64 do
    if Regex.match?(~r/\A[0-9a-f]+\z/, hex),
      do: {:ok, %__MODULE__{value: value}},
      else: {:error, :invalid_session_id}
  end

  def parse(_), do: {:error, :invalid_session_id}

  @doc "Sensitive explicit storage/transport access. Never log."
  @spec value(t()) :: String.t()
  def value(%__MODULE__{value: value}), do: value
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.SessionId do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.SessionId<redacted>"
end
