defmodule DatadeftAuth.AWS.DynamoDB.Authentication do
  @moduledoc false
  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.AWS.DynamoDB.{Keys, MagicLinks}
  alias DatadeftAuth.MagicLink.Core.Email

  alias DatadeftAuth.MagicLink.Service.{
    AuthenticationAttemptId,
    AuthenticationExpectation,
    CommitAuthentication,
    SessionId,
    UserId
  }

  @u64_max 18_446_744_073_709_551_615
  @challenge_condition "entity_type = :magic_link AND attribute_not_exists(consumed_at_unix) AND expires_at_unix = :expected_expiry AND expires_at_unix >= :now AND email_normalized = :expected_email AND terms_version = :expected_terms AND privacy_version = :expected_privacy AND consented_at_unix = :expected_consent AND consented_at_unix > :zero"

  def commit(store, command) do
    with {:ok, request} <- build(store, command) do
      {module, state} = store.client

      case module.request(state, "TransactWriteItems", request) do
        {:ok, output} when is_map(output) -> :ok
        {:error, {:transaction_canceled, codes}} -> {:error, cancellation(codes)}
        {:error, :unavailable} -> {:error, :unavailable}
        _ -> {:error, :internal}
      end
    end
  end

  def build(
        store,
        %CommitAuthentication{
          magic_link: %AuthenticationExpectation{} = expected,
          user: {branch, %UserId{} = user},
          session_id: %SessionId{} = session,
          attempt_id: %AuthenticationAttemptId{} = attempt
        } = command
      )
      when branch in [:create, :existing] do
    with {:ok, _} <- UserId.parse(UserId.value(user)),
         {:ok, _} <- SessionId.parse(SessionId.value(session)),
         {:ok, _} <- AuthenticationAttemptId.parse(AuthenticationAttemptId.value(attempt)),
         :ok <- validate(command),
         {:ok, challenge_key} <- MagicLinks.key(expected.selector_lookup_hmac),
         {:ok, hmac} <- StorageKey.hmac(store.storage_key, "sih", SessionId.value(session)),
         {:ok, user_actions} <- user_actions(store, command, branch, user) do
      challenge =
        action("Update", store, %{
          "Key" => challenge_key,
          "UpdateExpression" => "SET consumed_at_unix = :now",
          "ConditionExpression" => @challenge_condition,
          "ExpressionAttributeValues" => %{
            ":magic_link" => string("magic_link"),
            ":expected_expiry" => number(expected.expires_at_unix),
            ":now" => number(command.now_unix),
            ":expected_email" => string(Email.value(expected.email)),
            ":expected_terms" => string(expected.terms_version),
            ":expected_privacy" => string(expected.privacy_version),
            ":expected_consent" => number(expected.consented_at_unix),
            ":zero" => number(0)
          }
        })

      # Permanent audit rows: never put raw session IDs, attempt IDs or TTL on these items.
      session_item =
        Map.merge(key("SESSION#" <> hmac, "SESSION"), %{
          "entity_type" => string("session"),
          "user_id" => string(UserId.value(user)),
          "email_normalized" => string(Email.value(expected.email)),
          "created_at_unix" => number(command.now_unix),
          "expires_at_unix" => number(command.session_expires_at_unix)
        })

      index_item =
        Map.merge(
          key(
            "USER#" <> UserId.value(user),
            "SESSION#" <> Integer.to_string(command.now_unix) <> "#" <> hmac
          ),
          %{
            "entity_type" => string("user_session_index"),
            "created_at_unix" => number(command.now_unix),
            "expires_at_unix" => number(command.session_expires_at_unix)
          }
        )

      {:ok,
       %{
         "ClientRequestToken" => AuthenticationAttemptId.value(attempt),
         "TransactItems" =>
           [challenge, put(store, session_item), put(store, index_item)] ++ user_actions
       }}
    else
      _ -> {:error, :internal}
    end
  end

  def build(_, _), do: {:error, :internal}

  defp user_actions(store, command, :existing, user) do
    expected = command.magic_link

    with {:ok, email_key} <- Keys.user_email(store.storage_key, expected.email) do
      {:ok,
       [
         action("ConditionCheck", store, %{
           "Key" => email_key,
           "ConditionExpression" =>
             "entity_type = :email_lookup AND email_normalized = :expected_email AND user_id = :expected_user",
           "ExpressionAttributeValues" => %{
             ":email_lookup" => string("user_email_lookup"),
             ":expected_email" => string(Email.value(expected.email)),
             ":expected_user" => string(UserId.value(user))
           }
         }),
         action("ConditionCheck", store, %{
           "Key" => key("USERID#" <> UserId.value(user), "PROFILE"),
           "ConditionExpression" =>
             "entity_type = :user_profile AND user_id = :expected_user AND email_normalized = :expected_email AND disabled = :false",
           "ExpressionAttributeValues" => %{
             ":user_profile" => string("user_profile"),
             ":expected_user" => string(UserId.value(user)),
             ":expected_email" => string(Email.value(expected.email)),
             ":false" => %{"BOOL" => false}
           }
         })
       ]}
    end
  end

  defp user_actions(store, command, :create, user) do
    expected = command.magic_link

    fields = %{
      "user_id" => string(UserId.value(user)),
      "email_normalized" => string(Email.value(expected.email))
    }

    profile =
      key("USERID#" <> UserId.value(user), "PROFILE")
      |> Map.merge(fields)
      |> Map.merge(%{
        "entity_type" => string("user_profile"),
        "disabled" => %{"BOOL" => false},
        "terms_version" => string(expected.terms_version),
        "privacy_version" => string(expected.privacy_version),
        "consented_at_unix" => number(expected.consented_at_unix)
      })

    keys =
      if is_nil(store.previous_storage_key),
        do: [store.storage_key],
        else: [store.storage_key, store.previous_storage_key]

    Enum.reduce_while(keys, {:ok, [put(store, profile)]}, fn storage_key, {:ok, actions} ->
      case Keys.user_email(storage_key, expected.email) do
        {:ok, email_key} ->
          item =
            email_key |> Map.merge(fields) |> Map.put("entity_type", string("user_email_lookup"))

          {:cont, {:ok, actions ++ [put(store, item)]}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp validate(command) do
    expected = command.magic_link

    with %Email{} <- expected.email,
         {:ok, _} <- Email.from_normalized(Email.value(expected.email)),
         true <-
           Enum.all?(
             [
               command.now_unix,
               command.session_expires_at_unix,
               expected.expires_at_unix,
               expected.consented_at_unix
             ],
             &u64?/1
           ),
         true <- command.session_expires_at_unix >= command.now_unix,
         true <- valid_string?(expected.terms_version) and valid_string?(expected.privacy_version) do
      :ok
    else
      _ -> {:error, :internal}
    end
  end

  # Same fixed action positions as Rust, including variable-length user tail.
  defp cancellation(codes) when is_list(codes) and length(codes) in 5..6 do
    cond do
      Enum.any?(codes, &(&1 not in [nil, "None", "ConditionalCheckFailed"])) -> :unavailable
      Enum.at(codes, 0) == "ConditionalCheckFailed" -> :rejected
      Enum.any?(Enum.drop(codes, 3), &(&1 == "ConditionalCheckFailed")) -> :user_conflict
      Enum.any?(Enum.slice(codes, 1, 2), &(&1 == "ConditionalCheckFailed")) -> :session_conflict
      true -> :internal
    end
  end

  defp cancellation(_), do: :internal

  defp action(kind, store, fields), do: %{kind => Map.put(fields, "TableName", store.table)}

  defp put(store, item),
    do:
      action("Put", store, %{"Item" => item, "ConditionExpression" => "attribute_not_exists(pk)"})

  defp key(pk, sk), do: %{"pk" => string(pk), "sk" => string(sk)}
  defp number(value), do: %{"N" => Integer.to_string(value)}
  defp string(value), do: %{"S" => value}
  defp u64?(value), do: is_integer(value) and value >= 0 and value <= @u64_max
  defp valid_string?(value), do: is_binary(value) and String.valid?(value)
end
