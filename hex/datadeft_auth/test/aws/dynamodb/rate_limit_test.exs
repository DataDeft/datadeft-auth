defmodule DatadeftAuth.AWS.DynamoDB.RateLimitTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.DynamoDB
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey

  defmodule Client do
    def request({owner, result}, operation, input) do
      send(owner, {:request, operation, input})
      result
    end
  end

  defp store(result \\ {:ok, %{}}, grace \\ 86_400) do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, store} = DynamoDB.new("synthetic-auth", key, {Client, {self(), result}}, grace)
    store
  end

  test "lifetime admission uses the exact rotation-independent key and conditional increment" do
    assert DynamoDB.check_lifetime_limit(store(), "pow:budget:abc", 3, 200, 100) ==
             {:ok, :allowed}

    assert_receive {:request, "UpdateItem", input}
    assert {:ok, expected_key} = Keys.lifetime_rate("pow:budget:abc")
    assert input["Key"] == expected_key
    assert input["TableName"] == "synthetic-auth"
    assert input["ConditionExpression"] == "attribute_not_exists(#count) OR #count < :limit"

    assert input["UpdateExpression"] ==
             "SET #entity_type = if_not_exists(#entity_type, :entity), #expires = if_not_exists(#expires, :expires), #ttl = if_not_exists(#ttl, :ttl) ADD #count :one"

    assert input["ExpressionAttributeNames"] == %{
             "#entity_type" => "entity_type",
             "#expires" => "expires_at_unix",
             "#ttl" => "ttl",
             "#count" => "count"
           }

    assert input["ExpressionAttributeValues"] == %{
             ":entity" => %{"S" => "lifetime_counter"},
             ":expires" => %{"N" => "200"},
             ":ttl" => %{"N" => "86600"},
             ":one" => %{"N" => "1"},
             ":limit" => %{"N" => "3"}
           }
  end

  test "a conditional failure denies; other failures stay fail-closed typed errors" do
    for {result, expected} <- [
          {{:error, :conditional_write_failed}, {:ok, :denied}},
          {{:error, :unavailable}, {:error, :unavailable}},
          {{:error, :internal}, {:error, :internal}}
        ] do
      assert DynamoDB.check_lifetime_limit(store(result), "pow:test", 3, 200, 100) == expected
      assert_receive {:request, "UpdateItem", _}
    end
  end

  test "zero limits and expired proofs never write" do
    for {limit, expires, now} <- [{0, 200, 100}, {3, 100, 100}, {3, 99, 100}] do
      assert DynamoDB.check_lifetime_limit(store(), "pow:test", limit, expires, now) ==
               {:ok, :denied}
    end

    refute_receive {:request, _, _}
  end

  test "TTL arithmetic saturates at Rust u64 maximum" do
    max = 18_446_744_073_709_551_615
    assert DynamoDB.check_lifetime_limit(store(), "pow:test", 3, max, 100) == {:ok, :allowed}
    assert_receive {:request, _, input}
    assert input["ExpressionAttributeValues"][":ttl"] == %{"N" => Integer.to_string(max)}
  end

  test "fixed windows and cleanup TTL match the Rust adapter" do
    assert DynamoDB.check_rate_limit(store(), "req:test", 3, 60, 119) == {:ok, :allowed}
    assert_receive {:request, _, input}
    assert input["ExpressionAttributeValues"][":window_start"] == %{"N" => "60"}
    assert input["ExpressionAttributeValues"][":window_expires"] == %{"N" => "120"}
    assert input["ExpressionAttributeValues"][":ttl"] == %{"N" => "86520"}
    assert input["ExpressionAttributeValues"][":entity"] == %{"S" => "rate_counter"}

    assert DynamoDB.check_rate_limit(store(), "req:test", 3, 0, 119) == {:ok, :allowed}
    assert_receive {:request, _, zero}
    assert zero["ExpressionAttributeValues"][":window_start"] == %{"N" => "0"}
    assert zero["ExpressionAttributeValues"][":window_expires"] == %{"N" => "0"}
  end

  test "out-of-range inputs fail without touching storage" do
    for {limit, expires, now} <- [
          {-1, 200, 100},
          {4_294_967_296, 200, 100},
          {3, -1, 100},
          {3, 200, -1}
        ] do
      assert DynamoDB.check_lifetime_limit(store(), "pow:test", limit, expires, now) ==
               {:error, :invalid_input}
    end

    refute_receive {:request, _, _}
  end

  test "store config is validated and inspection never reveals client state or key" do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert DynamoDB.new("bad table", key, {Client, self()}) == {:error, :invalid_config}
    assert DynamoDB.new("valid", key, {Client, self()}, -1) == {:error, :invalid_config}
    assert inspect(store()) == "#DatadeftAuth.AWS.DynamoDB<redacted>"
  end
end
