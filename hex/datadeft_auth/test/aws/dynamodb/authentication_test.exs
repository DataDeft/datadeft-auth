defmodule DatadeftAuth.AWS.DynamoDB.AuthenticationTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.AWS.{DynamoDB, StorageKey}
  alias DatadeftAuth.AWS.DynamoDB.Authentication
  alias DatadeftAuth.MagicLink.Core.{Email, Lookup}

  alias DatadeftAuth.MagicLink.Service.{
    AuthenticationAttemptId,
    AuthenticationExpectation,
    CommitAuthentication,
    SessionId,
    UserId
  }

  defmodule Client do
    def request({owner, response}, operation, input) do
      send(owner, {:request, operation, input})
      response
    end
  end

  defp fixture(response \\ {:ok, %{}}) do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, store} = DynamoDB.new("synthetic-auth", key, {Client, {self(), response}})
    {:ok, email} = Email.normalize("elixir@example.test")
    {:ok, selector} = Lookup.parse(:selector, "mlh_" <> String.duplicate("a", 64))
    {:ok, user} = UserId.parse("usr-" <> String.duplicate("b", 32))
    {:ok, session} = SessionId.parse("sid-" <> String.duplicate("c", 64))
    {:ok, attempt} = AuthenticationAttemptId.parse("aid-" <> String.duplicate("d", 32))

    expectation = %AuthenticationExpectation{
      selector_lookup_hmac: selector,
      email: email,
      expires_at_unix: 200,
      terms_version: "terms-v1",
      privacy_version: "privacy-v1",
      consented_at_unix: 100
    }

    {store,
     %CommitAuthentication{
       magic_link: expectation,
       now_unix: 150,
       attempt_id: attempt,
       user: {:create, user},
       session_id: session,
       session_expires_at_unix: 300
     }}
  end

  test "one transaction binds every immutable field and derives keyed session/index/user rows" do
    {store, command} = fixture()
    assert DynamoDB.commit_magic_link_authentication(store, command) == :ok
    assert_receive {:request, "TransactWriteItems", request}
    assert request["ClientRequestToken"] == AuthenticationAttemptId.value(command.attempt_id)

    assert [
             %{"Update" => challenge},
             %{"Put" => session},
             %{"Put" => index},
             %{"Put" => profile},
             %{"Put" => email}
           ] = request["TransactItems"]

    for expected <- [
          "attribute_not_exists(consumed_at_unix)",
          "expires_at_unix = :expected_expiry",
          "expires_at_unix >= :now",
          "email_normalized = :expected_email",
          "terms_version = :expected_terms",
          "privacy_version = :expected_privacy",
          "consented_at_unix = :expected_consent",
          "consented_at_unix > :zero"
        ] do
      assert String.contains?(challenge["ConditionExpression"], expected)
    end

    assert challenge["UpdateExpression"] == "SET consumed_at_unix = :now"

    assert {:ok, hmac} =
             StorageKey.hmac(store.storage_key, "sih", SessionId.value(command.session_id))

    assert session["Item"]["pk"] == %{"S" => "SESSION#" <> hmac}
    assert index["Item"]["sk"] == %{"S" => "SESSION#150#" <> hmac}
    assert profile["Item"]["pk"] == %{"S" => "USERID#usr-" <> String.duplicate("b", 32)}
    assert index["Item"]["pk"] == %{"S" => "USER#usr-" <> String.duplicate("b", 32)}
    assert profile["Item"]["disabled"] == %{"BOOL" => false}
    assert email["Item"]["entity_type"] == %{"S" => "user_email_lookup"}

    for put <- [session, index, profile, email] do
      assert put["ConditionExpression"] == "attribute_not_exists(pk)"
      refute Map.has_key?(put["Item"], "ttl")
      refute Map.has_key?(put["Item"], "attempt_id")
      refute Map.has_key?(put["Item"], "session_id")
    end

    refute Map.has_key?(challenge["ExpressionAttributeValues"], ":verifier_hash")
    assert inspect(command) == "#DatadeftAuth.MagicLink.Service.CommitAuthentication<redacted>"
  end

  test "new accounts claim current and previous email keys, with no duplicate action for equal keys" do
    {store, command} = fixture()
    {:ok, previous} = StorageKey.new(:binary.copy(<<0x22>>, 32))
    {:ok, rotated} = DynamoDB.with_previous_storage_key(store, previous)
    assert {:ok, %{"TransactItems" => actions}} = Authentication.build(rotated, command)
    assert length(actions) == 6
    [current, old] = Enum.take(actions, -2)
    refute current["Put"]["Item"]["pk"] == old["Put"]["Item"]["pk"]
    {:ok, equal} = DynamoDB.with_previous_storage_key(store, store.storage_key)
    assert {:ok, %{"TransactItems" => actions}} = Authentication.build(equal, command)
    assert length(actions) == 5
  end

  test "existing account is checked for exact linkage and enabled authoritative profile; no consent overwrite" do
    {store, command} = fixture()
    {:create, user} = command.user

    assert {:ok,
            %{
              "TransactItems" => [
                _,
                _,
                _,
                %{"ConditionCheck" => email},
                %{"ConditionCheck" => profile}
              ]
            }} = Authentication.build(store, %{command | user: {:existing, user}})

    assert email["ConditionExpression"] ==
             "entity_type = :email_lookup AND email_normalized = :expected_email AND user_id = :expected_user"

    assert profile["ConditionExpression"] ==
             "entity_type = :user_profile AND user_id = :expected_user AND email_normalized = :expected_email AND disabled = :false"

    assert profile["ExpressionAttributeValues"][":false"] == %{"BOOL" => false}
  end

  test "positional cancellation attribution, precedence and outages match Rust" do
    for {codes, expected} <- [
          {["ConditionalCheckFailed", "None", "None", "None", "None"], :rejected},
          {["None", "ConditionalCheckFailed", "None", "None", "None"], :session_conflict},
          {["None", "None", "None", "ConditionalCheckFailed", "None"], :user_conflict},
          {["None", "ConditionalCheckFailed", "None", "ConditionalCheckFailed", "None"],
           :user_conflict},
          {["ConditionalCheckFailed", "None", "None", "ConditionalCheckFailed", "None"],
           :rejected},
          {["ConditionalCheckFailed", "None", "None", "TransactionConflict", "None"],
           :unavailable},
          {["None", "None", "None", "None", "None"], :internal},
          {[], :internal}
        ] do
      {store, command} = fixture({:error, {:transaction_canceled, codes}})
      assert DynamoDB.commit_magic_link_authentication(store, command) == {:error, expected}
    end

    {store, command} = fixture({:error, :unavailable})
    assert DynamoDB.commit_magic_link_authentication(store, command) == {:error, :unavailable}
  end

  test "invalid/forged plans fail before IO and exact plans build deterministically" do
    {store, command} = fixture()

    for invalid <- [
          %{command | session_expires_at_unix: 149},
          %{command | now_unix: -1},
          %{command | user: {:create, nil}},
          %{command | magic_link: %{command.magic_link | consented_at_unix: -1}}
        ] do
      assert DynamoDB.commit_magic_link_authentication(store, invalid) == {:error, :internal}
    end

    refute_receive {:request, _, _}
    assert Authentication.build(store, command) == Authentication.build(store, command)
  end
end
