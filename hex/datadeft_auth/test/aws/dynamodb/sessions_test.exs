defmodule DatadeftAuth.AWS.DynamoDB.SessionsTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.AWS.{DynamoDB, StorageKey}
  alias DatadeftAuth.MagicLink.Service.{SessionId, SessionRecord, UserId}

  @sid "sid-" <> String.duplicate("a", 64)
  @uid "usr-" <> String.duplicate("b", 32)
  @row %{
    "entity_type" => %{"S" => "session"},
    "user_id" => %{"S" => @uid},
    "email_normalized" => %{"S" => "member@example.test"},
    "created_at_unix" => %{"N" => "100"},
    "expires_at_unix" => %{"N" => "200"}
  }
  @profile %{
    "entity_type" => %{"S" => "user_profile"},
    "user_id" => %{"S" => @uid},
    "disabled" => %{"BOOL" => false},
    "sessions_valid_after_unix" => %{"N" => "100"}
  }

  defmodule Client do
    def request(agent, operation, input) do
      Agent.get_and_update(agent, fn {owner, [response | remaining]} ->
        send(owner, {operation, input})
        {response, {owner, remaining}}
      end)
    end
  end

  test "live lookup reads consistently by HMAC, falls back on miss and expires inclusively" do
    {:ok, id} = SessionId.parse(@sid)
    {store, current, previous} = store([{:ok, %{}}, {:ok, %{"Item" => @row}}])

    assert {:ok,
            %SessionRecord{session_id: ^id, created_at_unix: 100, revoked_at_unix: nil} = found} =
             DynamoDB.find_session(store, id, 200)

    assert UserId.value(found.user_id) == @uid
    refute inspect(found) =~ @sid
    assert_receive {"GetItem", %{"Key" => ^current, "ConsistentRead" => true}}
    assert_receive {"GetItem", %{"Key" => ^previous, "ConsistentRead" => true}}
    {store, _, _} = store([{:ok, %{"Item" => @row}}])
    assert {:ok, nil} = DynamoDB.find_session(store, id, 201)
  end

  test "revoked, corrupt or unavailable current rows never fall back" do
    {:ok, id} = SessionId.parse(@sid)

    for {result, expected} <- [
          {{:ok, %{"Item" => Map.put(@row, "revoked_at_unix", %{"N" => "120"})}}, {:ok, nil}},
          {{:ok, %{"Item" => Map.put(@row, "expires_at_unix", %{"S" => "200"})}},
           {:error, :internal}},
          {{:ok, %{"Item" => Map.put(@row, "email_normalized", %{"S" => "Bad@example.test"})}},
           {:error, :internal}},
          {{:error, :unavailable}, {:error, :unavailable}}
        ] do
      {store, current, _} = store([result])
      assert DynamoDB.find_session(store, id, 150) == expected
      assert_receive {"GetItem", %{"Key" => ^current}}
    end
  end

  test "revocation updates only an existing unrevoked row and retries only confirmed condition failures" do
    {:ok, id} = SessionId.parse(@sid)
    {store, current, previous} = store([{:error, :conditional_write_failed}, {:ok, %{}}])
    assert :ok = DynamoDB.revoke_session(store, id, 155)

    assert_receive {"UpdateItem",
                    %{
                      "Key" => ^current,
                      "UpdateExpression" => "SET revoked_at_unix = :now",
                      "ConditionExpression" =>
                        "attribute_exists(pk) AND attribute_not_exists(revoked_at_unix)",
                      "ExpressionAttributeValues" => %{":now" => %{"N" => "155"}}
                    }}

    assert_receive {"UpdateItem", %{"Key" => ^previous}}
    {store, _, _} = store([{:error, :unavailable}])
    assert {:error, :unavailable} = DynamoDB.revoke_session(store, id, 155)

    {store, _, _} =
      store([{:error, :conditional_write_failed}, {:error, :conditional_write_failed}])

    assert {:error, :conditional_write_failed} = DynamoDB.revoke_session(store, id, 155)
  end

  test "owner checks exact profile, disabled flag and re-enable watermark on every use" do
    {:ok, uid} = UserId.parse(@uid)

    for {row, time, expected} <- [
          {@profile, 100, {:ok, true}},
          {@profile, 99, {:ok, false}},
          {nil, 100, {:ok, false}},
          {Map.put(@profile, "disabled", %{"BOOL" => true}), 100, {:ok, false}},
          {Map.delete(@profile, "disabled"), 100, {:ok, false}},
          {Map.put(@profile, "user_id", %{"S" => "different"}), 100, {:ok, false}},
          {Map.put(@profile, "sessions_valid_after_unix", %{"S" => "100"}), 100,
           {:error, :internal}}
        ] do
      response = if row, do: %{"Item" => row}, else: %{}
      {store, _, _} = store([{:ok, response}])
      assert DynamoDB.is_session_owner_active(store, uid, time) == expected

      assert_receive {"GetItem",
                      %{"ConsistentRead" => true, "Key" => %{"pk" => %{"S" => "USERID#" <> @uid}}}}
    end
  end

  defp store(responses) do
    owner = self()
    agent = start_supervised!({Agent, fn -> {owner, responses} end}, id: make_ref())
    {:ok, current} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, previous} = StorageKey.new(:binary.copy(<<0x33>>, 32))
    {:ok, store} = DynamoDB.new("synthetic-auth", current, {Client, agent})
    {:ok, store} = DynamoDB.with_previous_storage_key(store, previous)
    {store, key(current), key(previous)}
  end

  defp key(key) do
    {:ok, hmac} = StorageKey.hmac(key, "sih", @sid)
    %{"pk" => %{"S" => "SESSION#" <> hmac}, "sk" => %{"S" => "SESSION"}}
  end
end
