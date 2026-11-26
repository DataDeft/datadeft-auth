defmodule DatadeftAuth.MagicLink.Core.Email do
  @moduledoc """
  Exact Rust-compatible email identity: trim Unicode White_Space, then
  ASCII-lowercase the whole address, including the local part. No alias folding.

  Stored values must pass `from_normalized/1`, which validates without repairing.
  Only ASCII address syntax is supported; lengths are measured in bytes.
  """

  @enforce_keys [:value]
  defstruct [:value]

  @opaque t :: %__MODULE__{value: String.t()}
  @type error :: {:error, :invalid_email}

  # Rust str::trim uses Unicode White_Space, not all invisible characters.
  @trim ~r/\A[\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+|[\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+\z/u
  @local ~r/\A[a-z0-9!#$%&'*+\-\/=?^_`{|}~.]+\z/
  @label ~r/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/

  @spec normalize(term()) :: {:ok, t()} | error()
  def normalize(input) when is_binary(input) do
    if String.valid?(input) do
      trimmed = Regex.replace(@trim, input, "")

      if byte_size(trimmed) <= 254,
        do: from_normalized(String.downcase(trimmed, :ascii)),
        else: {:error, :invalid_email}
    else
      {:error, :invalid_email}
    end
  end

  def normalize(_), do: {:error, :invalid_email}

  @spec from_normalized(term()) :: {:ok, t()} | error()
  def from_normalized(value) when is_binary(value) and byte_size(value) in 3..254 do
    case :binary.split(value, "@", [:global]) do
      [local, domain] ->
        if valid_local?(local) and valid_domain?(domain),
          do: {:ok, %__MODULE__{value: value}},
          else: {:error, :invalid_email}

      _ ->
        {:error, :invalid_email}
    end
  end

  def from_normalized(_), do: {:error, :invalid_email}

  @doc "Explicit access for email delivery, identity lookup and persistence. Do not log."
  @spec value(t()) :: String.t()
  def value(%__MODULE__{value: value}), do: value

  defp valid_local?(local) do
    byte_size(local) in 1..64 and Regex.match?(@local, local) and
      not String.starts_with?(local, ".") and not String.ends_with?(local, ".") and
      not String.contains?(local, "..")
  end

  defp valid_domain?(domain) do
    byte_size(domain) in 1..253 and String.contains?(domain, ".") and
      Enum.all?(:binary.split(domain, ".", [:global]), fn label ->
        byte_size(label) in 1..63 and Regex.match?(@label, label)
      end)
  end
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.Email do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.Email<redacted>"
end
