defmodule DatadeftAuth.MagicLink.Core.Token do
  @moduledoc """
  Exact `mlv1.<128-bit selector hex>.<256-bit verifier hex>` bearer grammar.
  Core generation accepts an injected entropy function. Production adapters must
  supply two independent CSPRNG draws; never derive either half from the other.
  """
  @enforce_keys [:selector, :verifier]
  defstruct [:selector, :verifier]
  @opaque t :: %__MODULE__{selector: String.t(), verifier: String.t()}

  @spec parse(term()) :: {:ok, t()} | {:error, :invalid_token}
  def parse(<<"mlv1.", selector::binary-size(32), ".", verifier::binary-size(64)>>) do
    if lower_hex?(selector) and lower_hex?(verifier),
      do: {:ok, %__MODULE__{selector: selector, verifier: verifier}},
      else: {:error, :invalid_token}
  end

  def parse(_), do: {:error, :invalid_token}

  @spec generate((pos_integer() -> {:ok, binary()} | {:error, term()})) ::
          {:ok, t()} | {:error, :entropy_unavailable}
  def generate(entropy) when is_function(entropy, 1) do
    with {:ok, selector} when is_binary(selector) and byte_size(selector) == 16 <- entropy.(16),
         {:ok, verifier} when is_binary(verifier) and byte_size(verifier) == 32 <- entropy.(32) do
      {:ok,
       %__MODULE__{
         selector: Base.encode16(selector, case: :lower),
         verifier: Base.encode16(verifier, case: :lower)
       }}
    else
      _ -> {:error, :entropy_unavailable}
    end
  end

  @doc "Render only for email delivery. Never log or persist raw bearer material."
  @spec value(t()) :: String.t()
  def value(%__MODULE__{selector: selector, verifier: verifier}),
    do: "mlv1." <> selector <> "." <> verifier

  @doc false
  def selector(%__MODULE__{selector: selector}), do: selector
  @doc false
  def verifier(%__MODULE__{verifier: verifier}), do: verifier

  defp lower_hex?(value), do: Regex.match?(~r/\A[0-9a-f]+\z/, value)
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.Token do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.Token<redacted>"
end
