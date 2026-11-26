defmodule DatadeftAuth.Token.Base62 do
  @moduledoc """
  Rust-compatible big-integer Base62 over `0-9A-Za-z`.

  Leading zero bytes are lost. Leading `0` digits are accepted by this primitive;
  token parsers must reject those noncanonical spellings and enforce input caps
  before decoding. Use hex/base64 for arbitrary byte strings.
  """
  @alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  @spec encode(binary()) :: String.t()
  def encode(bytes) when is_binary(bytes) do
    bytes |> :binary.decode_unsigned() |> digits([]) |> IO.iodata_to_binary()
  end

  @spec decode(term()) :: {:ok, binary()} | {:error, :invalid_base62}
  def decode(encoded) when is_binary(encoded), do: number(encoded, 0)
  def decode(_), do: {:error, :invalid_base62}

  defp digits(0, acc), do: acc

  defp digits(value, acc),
    do: digits(div(value, 62), [:binary.at(@alphabet, rem(value, 62)) | acc])

  defp number(<<>>, 0), do: {:ok, <<>>}
  defp number(<<>>, integer), do: {:ok, :binary.encode_unsigned(integer)}

  defp number(<<byte, rest::binary>>, integer) when byte in ?0..?9,
    do: number(rest, integer * 62 + byte - ?0)

  defp number(<<byte, rest::binary>>, integer) when byte in ?A..?Z,
    do: number(rest, integer * 62 + byte - ?A + 10)

  defp number(<<byte, rest::binary>>, integer) when byte in ?a..?z,
    do: number(rest, integer * 62 + byte - ?a + 36)

  defp number(_, _), do: {:error, :invalid_base62}
end
