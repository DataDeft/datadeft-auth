defmodule DatadeftAuth.AWS.DynamoDB.Rotation do
  @moduledoc false

  alias DatadeftAuth.AWS.DynamoDB.Items
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.UserId

  def get_with_fallback(store, key_for) do
    with {:ok, key} <- key_for.(store.storage_key),
         {:ok, item} <- get(store, key) do
      if is_nil(item) and not is_nil(store.previous_storage_key) do
        with {:ok, previous_key} <- key_for.(store.previous_storage_key),
             {:ok, previous} <- get(store, previous_key) do
          {:ok, previous, not is_nil(previous)}
        end
      else
        {:ok, item, false}
      end
    end
  end

  def get(store, key) do
    case request(store, "GetItem", %{"Key" => key, "ConsistentRead" => true}) do
      {:ok, %{"Item" => item}} when is_map(item) -> {:ok, item}
      {:ok, output} when not is_map_key(output, "Item") -> {:ok, nil}
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  def lookup_item(key, email, id) do
    with {:ok, attributes} <- Keys.user_email(key, email) do
      {:ok,
       Map.merge(attributes, %{
         "entity_type" => %{"S" => "user_email_lookup"},
         "user_id" => %{"S" => UserId.value(id)},
         "email_normalized" => %{"S" => Email.value(email)}
       })}
    end
  end

  def put_lookup(store, email, id) do
    with {:ok, item} <- lookup_item(store.storage_key, email, id) do
      case request(store, "PutItem", %{
             "Item" => item,
             "ConditionExpression" => "attribute_not_exists(pk)"
           }) do
        {:ok, _} -> {:ok, true}
        {:error, :conditional_write_failed} -> {:ok, false}
        error -> error
      end
    end
  end

  def rekey(store), do: scan(store, nil, 0)

  defp scan(store, start_key, count) do
    input = %{
      "FilterExpression" => "entity_type = :user_profile",
      "ProjectionExpression" => "user_id, email_normalized",
      "ExpressionAttributeValues" => %{":user_profile" => %{"S" => "user_profile"}}
    }

    input = if is_nil(start_key), do: input, else: Map.put(input, "ExclusiveStartKey", start_key)

    with {:ok, output} <- request(store, "Scan", input),
         {:ok, count} <- rekey_items(store, Map.get(output, "Items", []), count) do
      case Map.get(output, "LastEvaluatedKey") do
        nil -> {:ok, count}
        key when is_map(key) and map_size(key) == 0 -> {:ok, count}
        key when is_map(key) -> scan(store, key, count)
        _ -> {:error, :internal}
      end
    end
  end

  defp rekey_items(store, items, count) when is_list(items) do
    Enum.reduce_while(items, {:ok, count}, fn item, {:ok, count} ->
      case rekey_item(store, item) do
        {:ok, written?} ->
          {:cont, {:ok, min(count + if(written?, do: 1, else: 0), 18_446_744_073_709_551_615)}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp rekey_items(_, _, _), do: {:error, :internal}

  defp rekey_item(store, item) when is_map(item) do
    with {:ok, raw_email} <- Items.required_string(item, "email_normalized"),
         {:ok, email} <- Email.from_normalized(raw_email),
         {:ok, raw_id} <- Items.required_string(item, "user_id"),
         {:ok, id} <- UserId.parse(raw_id) do
      put_lookup(store, email, id)
    else
      _ -> {:error, :internal}
    end
  end

  defp rekey_item(_, _), do: {:error, :internal}

  defp request(store, operation, input) do
    {module, state} = store.client

    case module.request(state, operation, Map.put(input, "TableName", store.table)) do
      {:ok, output} when is_map(output) -> {:ok, output}
      {:error, :unavailable} -> {:error, :unavailable}
      {:error, :conditional_write_failed} -> {:error, :conditional_write_failed}
      _ -> {:error, :internal}
    end
  end
end
