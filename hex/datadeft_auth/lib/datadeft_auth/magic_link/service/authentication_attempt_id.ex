defmodule DatadeftAuth.MagicLink.Service.AuthenticationAttemptId do
  @moduledoc "Canonical Rust-compatible AuthenticationAttemptId. Explicit access only; inspect is redacted."
  @enforce_keys [:value]
  defstruct [:value]
  @opaque t :: %__MODULE__{value: String.t()}

  @spec parse(term()) :: {:ok, t()} | {:error, :invalid_attempt_id}
  def parse("aid-" <> hex = value) when byte_size(hex) == 32 do
    if Regex.match?(~r/\A[0-9a-f]+\z/, hex),
      do: {:ok, %__MODULE__{value: value}},
      else: {:error, :invalid_attempt_id}
  end

  def parse(_), do: {:error, :invalid_attempt_id}

  @doc "Sensitive explicit storage/transport access. Never log."
  @spec value(t()) :: String.t()
  def value(%__MODULE__{value: value}), do: value
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.AuthenticationAttemptId do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.AuthenticationAttemptId<redacted>"
end
