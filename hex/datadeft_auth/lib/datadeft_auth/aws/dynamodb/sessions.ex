defmodule DatadeftAuth.AWS.DynamoDB.Sessions do
  @moduledoc false
  alias DatadeftAuth.AWS.DynamoDB.{Items, Keys, Rotation}
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.{SessionId, SessionRecord, UserId}

  @u64_max 18_446_744_073_709_551_615

  def find(store, %SessionId{} = id, now) when is_integer(now) and now in 0..@u64_max do
    with {:ok, item, _} <- Rotation.get_with_fallback(store, &key(&1, id)) do
      if is_nil(item), do: {:ok, nil}, else: live_record(item, id, now)
    else
      {:error, :unavailable} = error -> error
      _ -> {:error, :internal}
    end
  end

  def find(_, _, _), do: {:error, :internal}

  def revoke(store, %SessionId{} = id, now) when is_integer(now) and now in 0..@u64_max do
    case revoke_under(store, store.storage_key, id, now) do
      {:error, :conditional_write_failed} when not is_nil(store.previous_storage_key) ->
        revoke_under(store, store.previous_storage_key, id, now)

      result ->
        result
    end
  end

  def revoke(_, _, _), do: {:error, :internal}

  def owner_active(store, %UserId{} = id, created)
      when is_integer(created) and created in 0..@u64_max do
    with {:ok, id} <- UserId.parse(UserId.value(id)),
         {:ok, item} <- Rotation.get(store, Keys.profile(id)) do
      if is_nil(item), do: {:ok, false}, else: active_profile(item, UserId.value(id), created)
    else
      {:error, :unavailable} = error -> error
      _ -> {:error, :internal}
    end
  end

  def owner_active(_, _, _), do: {:error, :internal}

  defp live_record(item, id, now) do
    if Items.optional_string(item, "entity_type") == {:ok, "session"} do
      with {:ok, revoked} <- Items.optional_u64(item, "revoked_at_unix") do
        if revoked do
          {:ok, nil}
        else
          with {:ok, expires} <- Items.required_u64(item, "expires_at_unix") do
            if expires < now, do: {:ok, nil}, else: decode_record(item, id)
          end
        end
      end
    else
      {:ok, nil}
    end
  end

  defp decode_record(item, id) do
    with {:ok, raw_user} <- Items.required_string(item, "user_id"),
         {:ok, user} <- UserId.parse(raw_user),
         {:ok, raw_email} <- Items.required_string(item, "email_normalized"),
         {:ok, email} <- Email.from_normalized(raw_email),
         {:ok, created} <- Items.required_u64(item, "created_at_unix") do
      {:ok,
       %SessionRecord{
         session_id: id,
         user_id: user,
         email: email,
         created_at_unix: created,
         revoked_at_unix: nil
       }}
    else
      _ -> {:error, :internal}
    end
  end

  defp active_profile(item, id, created) do
    with {:ok, watermark} <- Items.optional_u64(item, "sessions_valid_after_unix") do
      {:ok,
       Items.optional_string(item, "entity_type") == {:ok, "user_profile"} and
         Items.optional_string(item, "user_id") == {:ok, id} and
         Items.required_bool(item, "disabled") == {:ok, false} and
         (is_nil(watermark) or created >= watermark)}
    end
  end

  defp revoke_under(store, storage_key, id, now) do
    case key(storage_key, id) do
      {:ok, key} ->
        {module, state} = store.client

        case module.request(state, "UpdateItem", %{
               "TableName" => store.table,
               "Key" => key,
               "UpdateExpression" => "SET revoked_at_unix = :now",
               "ConditionExpression" =>
                 "attribute_exists(pk) AND attribute_not_exists(revoked_at_unix)",
               "ExpressionAttributeValues" => %{":now" => %{"N" => Integer.to_string(now)}}
             }) do
          {:ok, output} when is_map(output) ->
            :ok

          {:error, error} when error in [:conditional_write_failed, :unavailable] ->
            {:error, error}

          _ ->
            {:error, :internal}
        end

      _ ->
        {:error, :internal}
    end
  end

  defp key(storage_key, id) do
    with {:ok, hmac} <- Keys.session_hmac(storage_key, id), do: {:ok, Keys.session(hmac)}
  end
end
