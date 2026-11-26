defmodule DatadeftAuth.AWS.DynamoDB.Keys do
  @moduledoc false

  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.MagicLink.Core.Email

  @u64_max 18_446_744_073_709_551_615
  @rate_key ~r/\A[A-Za-z0-9:_-]+\z/
  @lifetime_domain "magic-link-aws-lifetime-counter-v1"

  @spec user_email(StorageKey.t(), Email.t()) :: {:ok, map()} | {:error, atom()}
  def user_email(key, %Email{} = email) do
    # Validate even a manually constructed struct before it addresses storage.
    with {:ok, validated} <- Email.from_normalized(Email.value(email)),
         {:ok, hmac} <- StorageKey.hmac(key, "emh", Email.value(validated)) do
      {:ok, attributes("USER#" <> hmac, "PROFILE")}
    end
  end

  @spec rate(StorageKey.t(), String.t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, map()} | {:error, atom()}
  def rate(key, value, window_secs, now_unix)
      when is_integer(window_secs) and window_secs >= 0 and window_secs <= @u64_max and
             is_integer(now_unix) and now_unix >= 0 and now_unix <= @u64_max do
    if valid_rate_key?(value) do
      index = if window_secs == 0, do: 0, else: div(now_unix, window_secs)

      with {:ok, hmac} <- StorageKey.hmac(key, "rlh", value <> ":" <> Integer.to_string(index)) do
        {:ok, attributes("RL#" <> hmac, "COUNTER")}
      end
    else
      {:error, :invalid_key}
    end
  end

  def rate(_, _, _, _), do: {:error, :invalid_key}

  @spec lifetime_rate(String.t()) :: {:ok, map()} | {:error, :invalid_key}
  def lifetime_rate(value) do
    if valid_rate_key?(value) do
      hash = :crypto.hash(:sha256, [@lifetime_domain, <<0>>, value])
      {:ok, attributes("RL#lt_" <> Base.encode16(hash, case: :lower), "COUNTER")}
    else
      {:error, :invalid_key}
    end
  end

  defp valid_rate_key?(value) do
    is_binary(value) and byte_size(value) in 1..256 and Regex.match?(@rate_key, value)
  end

  defp attributes(pk, sk), do: %{"pk" => %{"S" => pk}, "sk" => %{"S" => sk}}
end
