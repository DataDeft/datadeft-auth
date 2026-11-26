defmodule DatadeftAuth.AWS.DynamoDB.MagicLinks do
  @moduledoc false
  alias DatadeftAuth.AWS.DynamoDB.{Items, Rotation}
  alias DatadeftAuth.MagicLink.Core.{Email, Lookup}
  alias DatadeftAuth.MagicLink.Service.Challenge
  @u64_max 18_446_744_073_709_551_615

  def put(store, %Challenge{} = record) do
    with :ok <- validate(record),
         {:ok, key} <- key(record.selector_lookup_hmac) do
      item =
        Map.merge(key, %{
          "entity_type" => %{"S" => "magic_link"},
          "email_normalized" => %{"S" => Email.value(record.email)},
          "verifier_hash" => %{"S" => Lookup.storage_value(record.verifier_hash)},
          "expires_at_unix" => number(record.expires_at_unix),
          "terms_version" => %{"S" => record.terms_version},
          "privacy_version" => %{"S" => record.privacy_version},
          "consented_at_unix" => number(record.consented_at_unix),
          "ttl" => number(min(record.expires_at_unix + store.cleanup_grace_secs, @u64_max))
        })

      {module, state} = store.client

      case module.request(state, "PutItem", %{
             "TableName" => store.table,
             "Item" => item,
             "ConditionExpression" => "attribute_not_exists(pk)"
           }) do
        {:ok, output} when is_map(output) -> :ok
        {:error, :conditional_write_failed} -> {:error, :conditional_write_failed}
        {:error, :unavailable} -> {:error, :unavailable}
        _ -> {:error, :internal}
      end
    end
  end

  def put(_, _), do: {:error, :invalid_input}

  def find(store, lookup) do
    with {:ok, key} <- key(lookup),
         {:ok, item} <- Rotation.get(store, key) do
      if is_nil(item), do: {:ok, nil}, else: decode(item, lookup)
    end
  end

  def key(%Lookup{kind: :selector, bytes: bytes} = lookup)
      when is_binary(bytes) and byte_size(bytes) == 32 do
    {:ok,
     %{"pk" => %{"S" => "ML#" <> Lookup.storage_value(lookup)}, "sk" => %{"S" => "CHALLENGE"}}}
  end

  def key(_), do: {:error, :invalid_input}

  defp validate(record) do
    with %Lookup{kind: :verifier, bytes: bytes} when is_binary(bytes) and byte_size(bytes) == 32 <-
           record.verifier_hash,
         %Email{} <- record.email,
         {:ok, _} <- Email.from_normalized(Email.value(record.email)),
         true <- u64?(record.expires_at_unix) and u64?(record.consented_at_unix),
         true <- is_binary(record.terms_version) and is_binary(record.privacy_version),
         true <- String.valid?(record.terms_version) and String.valid?(record.privacy_version) do
      :ok
    else
      _ -> {:error, :invalid_input}
    end
  end

  defp decode(item, lookup) do
    with {:ok, "magic_link"} <- Items.required_string(item, "entity_type"),
         {:ok, raw_hash} <- Items.required_string(item, "verifier_hash"),
         {:ok, verifier} <- Lookup.parse(:verifier, raw_hash),
         {:ok, raw_email} <- Items.required_string(item, "email_normalized"),
         {:ok, email} <- Email.from_normalized(raw_email),
         {:ok, expires} <- Items.required_u64(item, "expires_at_unix"),
         {:ok, consumed} <- Items.optional_u64(item, "consumed_at_unix"),
         {:ok, terms} <- Items.required_string(item, "terms_version"),
         {:ok, privacy} <- Items.required_string(item, "privacy_version"),
         {:ok, consented} <- Items.required_u64(item, "consented_at_unix") do
      {:ok,
       %Challenge{
         selector_lookup_hmac: lookup,
         verifier_hash: verifier,
         email: email,
         expires_at_unix: expires,
         consumed_at_unix: consumed,
         terms_version: terms,
         privacy_version: privacy,
         consented_at_unix: consented
       }}
    else
      _ -> {:error, :internal}
    end
  end

  defp u64?(value), do: is_integer(value) and value >= 0 and value <= @u64_max
  defp number(value), do: %{"N" => Integer.to_string(value)}
end
