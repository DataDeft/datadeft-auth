defmodule DatadeftAuth.Token.BoundCookie do
  @moduledoc false
  alias DatadeftAuth.Token.{Branca, Keyring}

  @u32_max 4_294_967_295
  @u64_max 18_446_744_073_709_551_615
  @default_skew 60
  @enforce_keys [:kid, :timestamp, :iat, :nonce, :body]
  defstruct [:kid, :timestamp, :iat, :nonce, :body]

  def mint(body, ring, timestamp, iat, now, skew \\ @default_skew)

  def mint(body, %Keyring{} = ring, timestamp, iat, now, skew) do
    {_, typ, cap, _, _} = Keyring.parameters(Keyring.purpose(ring))

    with true <- u32?(timestamp) and u32?(iat) and u64?(now) and skew?(skew),
         true <- iat <= timestamp and abs(timestamp - now) <= skew,
         {:ok, kid, key} <- Keyring.minting_key(ring, now),
         {:ok, payload} <- frame(typ, kid, iat, body, cap),
         {:ok, token} <- Branca.encode(payload, key, timestamp) do
      {:ok, "v1." <> kid <> "." <> token}
    else
      false -> {:error, :invalid_timestamp}
      {:error, _} = error -> error
    end
  end

  def mint(_, _, _, _, _, _), do: {:error, :invalid_input}

  def open(value, ring, now, ages, skew \\ @default_skew)

  def open(value, %Keyring{} = ring, now, {idle, absolute}, skew) do
    {_, typ, cap, _, lifetime} = Keyring.parameters(Keyring.purpose(ring))

    if u64?(now) and skew?(skew) and age?(idle, lifetime) and age?(absolute, lifetime) do
      # Rust's pre-decrypt cap is ceil((header + payload + tag) * log(256)/log(62)).
      token_cap = ceil((45 + cap) * (:math.log(256) / :math.log(62)))

      with {:ok, kid, token} <- unwrap(value, token_cap),
           {:ok, key} <- Keyring.verification_key(ring, kid, now),
           {:ok, {timestamp, nonce, payload}} <- Branca.decode(token, key),
           true <- fresh?(timestamp, now, idle, skew),
           {:ok, iat, body} <- unframe(payload, typ, kid),
           true <- iat <= timestamp and fresh?(iat, now, absolute, skew) do
        {:ok, %__MODULE__{kid: kid, timestamp: timestamp, iat: iat, nonce: nonce, body: body}}
      else
        _ -> {:error, :invalid_token}
      end
    else
      {:error, :invalid_timestamp}
    end
  end

  def open(_, _, _, _, _), do: {:error, :invalid_token}

  defp frame(typ, kid, iat, body, cap) when is_binary(body) do
    if 7 + byte_size(typ) + byte_size(kid) + byte_size(body) <= cap do
      {:ok,
       <<1, iat::32, byte_size(typ), typ::binary, byte_size(kid), kid::binary, body::binary>>}
    else
      {:error, :payload_too_large}
    end
  end

  defp frame(_, _, _, _, _), do: {:error, :invalid_input}

  defp unframe(
         <<1, iat::32, tl, typ::binary-size(tl), kl, kid::binary-size(kl), body::binary>>,
         typ,
         kid
       ),
       do: {:ok, iat, body}

  defp unframe(_, _, _), do: {:error, :invalid_token}

  defp unwrap("v1." <> rest, token_cap) when byte_size(rest) <= 65 + token_cap do
    case :binary.split(rest, ".") do
      [kid, token] when byte_size(token) >= 1 and byte_size(token) <= token_cap ->
        if Keyring.valid_kid?(kid) and :binary.match(token, ".") == :nomatch,
          do: {:ok, kid, token},
          else: {:error, :invalid_token}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp unwrap(_, _), do: {:error, :invalid_token}

  defp fresh?(time, now, age, skew), do: time - now <= skew and now - time <= age
  defp u32?(v), do: is_integer(v) and v in 0..@u32_max
  defp u64?(v), do: is_integer(v) and v in 0..@u64_max
  defp skew?(v), do: is_integer(v) and v in 0..300
  defp age?(v, limit), do: is_integer(v) and v in 0..limit
end

defimpl Inspect, for: DatadeftAuth.Token.BoundCookie do
  def inspect(_, _), do: "#DatadeftAuth.Token.BoundCookie<redacted>"
end
