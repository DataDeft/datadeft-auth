defmodule DatadeftAuth.AWS.DynamoDB.Users do
  @moduledoc false

  alias DatadeftAuth.AWS.DynamoDB.Items
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.User
  alias DatadeftAuth.MagicLink.Service.UserId

  def find(store, email) do
    with {:ok, key} <- Keys.user_email(store.storage_key, email),
         {:ok, lookup} <- get(store, key) do
      case lookup do
        nil -> {:ok, nil}
        item -> read_profile(store, email, item)
      end
    else
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  defp read_profile(store, email, lookup) do
    with {:ok, "user_email_lookup"} <- Items.required_string(lookup, "entity_type"),
         {:ok, stored_email} <- Items.required_string(lookup, "email_normalized"),
         {:ok, ^email} <- Email.from_normalized(stored_email),
         {:ok, id} <- Items.required_string(lookup, "user_id"),
         {:ok, id} <- UserId.parse(id),
         {:ok, profile} when is_map(profile) <-
           get(store, %{
             "pk" => %{"S" => "USERID#" <> UserId.value(id)},
             "sk" => %{"S" => "PROFILE"}
           }),
         {:ok, user} <- decode_profile(profile, id, email) do
      {:ok, user}
    else
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  defp decode_profile(profile, expected_id, expected_email) do
    with {:ok, "user_profile"} <- Items.required_string(profile, "entity_type"),
         {:ok, raw_id} <- Items.required_string(profile, "user_id"),
         {:ok, ^expected_id} <- UserId.parse(raw_id),
         {:ok, raw_email} <- Items.required_string(profile, "email_normalized"),
         {:ok, ^expected_email} <- Email.from_normalized(raw_email),
         {:ok, disabled} <- Items.required_bool(profile, "disabled"),
         {:ok, terms} <- Items.optional_string(profile, "terms_version"),
         {:ok, privacy} <- Items.optional_string(profile, "privacy_version"),
         {:ok, consented} <- Items.optional_u64(profile, "consented_at_unix") do
      {:ok,
       %User{
         user_id: expected_id,
         email: expected_email,
         disabled: disabled,
         terms_version: terms,
         privacy_version: privacy,
         consented_at_unix: consented
       }}
    else
      _ -> {:error, :internal}
    end
  end

  defp get(store, key) do
    {module, state} = store.client

    case module.request(state, "GetItem", %{
           "TableName" => store.table,
           "Key" => key,
           "ConsistentRead" => true
         }) do
      {:ok, %{"Item" => item}} when is_map(item) -> {:ok, item}
      {:ok, output} when is_map(output) and not is_map_key(output, "Item") -> {:ok, nil}
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end
end
