defmodule DatadeftAuth.Compatibility.DynamoDBTest do
  use ExUnit.Case, async: false

  alias DatadeftAuth.AWS.DynamoDB
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.Test.LocalDynamo
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.UserId

  @moduletag :dynamodb
  @moduletag timeout: 180_000

  test "Rust and Elixir share accounts, counters, atomic admission and lifetime expiry" do
    endpoint = System.fetch_env!("DYNAMODB_LOCAL_ENDPOINT")
    table = "compatibility-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    assert {:ok, _} =
             LocalDynamo.request(endpoint, "CreateTable", %{
               "TableName" => table,
               "AttributeDefinitions" => [
                 %{"AttributeName" => "pk", "AttributeType" => "S"},
                 %{"AttributeName" => "sk", "AttributeType" => "S"}
               ],
               "KeySchema" => [
                 %{"AttributeName" => "pk", "KeyType" => "HASH"},
                 %{"AttributeName" => "sk", "KeyType" => "RANGE"}
               ],
               "BillingMode" => "PAY_PER_REQUEST"
             })

    on_exit(fn -> LocalDynamo.request(endpoint, "DeleteTable", %{"TableName" => table}) end)

    assert {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert {:ok, store} = DynamoDB.new(table, key, {LocalDynamo, endpoint})

    assert DynamoDB.check_lifetime_limit(store, "pow:compatibility:sequential", 3, 200, 100) ==
             {:ok, :allowed}

    assert DynamoDB.check_rate_limit(store, "req:compatibility", 2, 60, 119) == {:ok, :allowed}

    barrier = Path.join(System.tmp_dir!(), table)
    File.mkdir_p!(barrier)
    on_exit(fn -> File.rm_rf!(barrier) end)

    # Rust uses its existing store, not a second implementation in test glue.
    # It rotates the storage key for lifetime counters and races for one budget.
    rust =
      Task.async(fn ->
        System.cmd(
          "cargo",
          [
            "test",
            "-p",
            "datadeft-magic-link-aws",
            "--features",
            "aws",
            "--test",
            "dynamodb_local",
            "shared_elixir_counters",
            "--",
            "--ignored",
            "--exact",
            "--nocapture"
          ],
          cd: Path.expand("../../../..", __DIR__),
          env: [
            {"DYNAMODB_LOCAL_ENDPOINT", endpoint},
            {"DD_AUTH_COMPATIBILITY_TABLE", table},
            {"DD_AUTH_COMPATIBILITY_BARRIER", barrier}
          ],
          stderr_to_stdout: true
        )
      end)

    wait_ready(Path.join(barrier, "ready"), 1_000)
    File.write!(Path.join(barrier, "release"), "release")

    elixir_allowed =
      1..12
      |> Task.async_stream(
        fn _ ->
          DynamoDB.check_lifetime_limit(store, "pow:compatibility:race", 5, 200, 100)
        end,
        max_concurrency: 12
      )
      |> Enum.count(fn
        {:ok, {:ok, :allowed}} -> true
        {:ok, {:ok, :denied}} -> false
        other -> flunk("unexpected admission result: #{inspect(other)}")
      end)

    assert {output, 0} = Task.await(rust, 150_000)
    assert [_, rust_allowed] = Regex.run(~r/compatibility_rust_allowed=(\d+)/, output)
    assert elixir_allowed + String.to_integer(rust_allowed) == 5

    assert [_, rust_user_id] = Regex.run(~r/compatibility_user_id=(usr-[0-9a-f]{32})/, output)
    assert {:ok, email} = Email.normalize(" SHARED@EXAMPLE.TEST ")
    assert {:ok, user} = DynamoDB.find_user_for_authentication(store, email)
    assert UserId.value(user.user_id) == rust_user_id
    assert user.email == email
    refute user.disabled
    assert user.terms_version == "terms-v1"
    assert user.privacy_version == "privacy-v1"
    assert user.consented_at_unix > 0

    # Rotate in Elixir while Rust-created accounts still live under the old
    # storage key. Login lookup migrates one row; the scan rekeys a dormant one.
    assert {:ok, next_key} = StorageKey.new(:binary.copy(<<0x33>>, 32))
    assert {:ok, current_only} = DynamoDB.new(table, next_key, {LocalDynamo, endpoint})
    assert {:ok, rotating} = DynamoDB.with_previous_storage_key(current_only, key)
    assert {:ok, ^user} = DynamoDB.find_user_for_authentication(rotating, email)
    assert {:ok, ^user} = DynamoDB.find_user_for_authentication(current_only, email)
    assert DynamoDB.rekey_email_lookups(rotating) == {:ok, 1}
    assert DynamoDB.rekey_email_lookups(rotating) == {:ok, 0}
    assert {:ok, dormant_email} = Email.normalize("dormant@example.test")
    assert {:ok, dormant} = DynamoDB.find_user_for_authentication(current_only, dormant_email)
    assert [_, dormant_id] = Regex.run(~r/compatibility_dormant_id=(usr-[0-9a-f]{32})/, output)
    assert UserId.value(dormant.user_id) == dormant_id

    assert DynamoDB.check_lifetime_limit(store, "pow:compatibility:sequential", 3, 999, 100) ==
             {:ok, :allowed}

    assert DynamoDB.check_lifetime_limit(store, "pow:compatibility:sequential", 3, 999, 100) ==
             {:ok, :denied}

    assert DynamoDB.check_rate_limit(store, "req:compatibility", 2, 60, 119) == {:ok, :denied}

    assert {:ok, sequential} = Keys.lifetime_rate("pow:compatibility:sequential")
    assert {:ok, %{"Item" => item}} = get(endpoint, table, sequential)
    assert item["count"] == %{"N" => "3"}
    assert item["expires_at_unix"] == %{"N" => "200"}
    assert item["ttl"] == %{"N" => "86600"}

    assert {:ok, race} = Keys.lifetime_rate("pow:compatibility:race")
    assert {:ok, %{"Item" => item}} = get(endpoint, table, race)
    assert item["count"] == %{"N" => "5"}
  end

  test "local-only test client refuses non-loopback endpoints" do
    assert LocalDynamo.request("https://example.test", "UpdateItem", %{}) == {:error, :internal}
  end

  defp wait_ready(path, attempts) do
    assert attempts > 0, "Rust did not reach the shared-budget barrier"

    unless File.exists?(path) do
      Process.sleep(10)
      wait_ready(path, attempts - 1)
    end
  end

  defp get(endpoint, table, key) do
    LocalDynamo.request(endpoint, "GetItem", %{
      "TableName" => table,
      "Key" => key,
      "ConsistentRead" => true
    })
  end
end
