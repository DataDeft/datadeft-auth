defmodule DatadeftAuth.Compatibility.DynamoDBTest do
  use ExUnit.Case, async: false

  alias DatadeftAuth.AWS.DynamoDB
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.Test.LocalDynamo
  alias DatadeftAuth.Token.Keyring
  alias DatadeftAuth.MagicLink.Core.{ConfirmCookie, Email, Lookup, LookupKey, Token}

  alias DatadeftAuth.MagicLink.Service.{
    AuthenticationAttemptId,
    AuthenticationExpectation,
    Challenge,
    CommitAuthentication,
    CountryPolicy,
    Flow,
    LocaleAllowlist,
    Request,
    Session,
    SessionCookie,
    SessionId,
    UserId
  }

  @moduletag :dynamodb
  @moduletag timeout: 180_000

  defmodule Mailbox do
    def enqueue_magic_link(pid, mail) do
      send(pid, {:mail, mail})
      :ok
    end
  end

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

    assert {:ok, lookup_key} = LookupKey.new(:binary.copy(<<0x42>>, 32))
    assert_request_quotas(store, lookup_key)
    elixir_record = challenge("ab", "cd", "elixir@example.test", lookup_key)
    assert DynamoDB.put_magic_link_if_absent(store, elixir_record) == :ok

    assert DynamoDB.put_magic_link_if_absent(store, elixir_record) ==
             {:error, :conditional_write_failed}

    assert {:ok, next_key} = StorageKey.new(:binary.copy(<<0x33>>, 32))
    assert {:ok, current_only} = DynamoDB.new(table, next_key, {LocalDynamo, endpoint})
    assert {:ok, rotating} = DynamoDB.with_previous_storage_key(current_only, key)
    elixir_command = plan(elixir_record, "a", "b")
    assert DynamoDB.commit_magic_link_authentication(rotating, elixir_command) == :ok
    assert DynamoDB.commit_magic_link_authentication(rotating, elixir_command) == :ok

    assert DynamoDB.commit_magic_link_authentication(rotating, %{
             elixir_command
             | session_expires_at_unix: 301
           }) == {:error, :internal}

    assert DynamoDB.commit_magic_link_authentication(rotating, %{
             elixir_command
             | attempt_id: attempt_id()
           }) == {:error, :rejected}

    assert {:ok, initial_session} =
             DynamoDB.find_session(rotating, elixir_command.session_id, 300)

    assert {:ok, true} = DynamoDB.is_session_owner_active(rotating, initial_session.user_id, 150)
    assert {:ok, nil} = DynamoDB.find_session(rotating, elixir_command.session_id, 301)

    root = :binary.copy(<<0x7E>>, 32)
    assert {:ok, keyring} = Keyring.new(:session, [{:active, "test", root, 200, 2_592_200}])

    assert {:ok, session_service} =
             Session.new(keyring, {DynamoDB, rotating}, fn -> {:ok, 160} end, {100, 150})

    assert {:ok, session_cookie} =
             SessionCookie.mint(keyring, elixir_command.session_id, "HU", 150, 150)

    assert {:ok, validated} = Session.validate(session_service, session_cookie, "HU")
    assert Session.record(validated) == initial_session

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

    wait_ready(Path.join(barrier, "ready"), 1_000, rust)
    assert {:ok, nil} = DynamoDB.find_session(rotating, elixir_command.session_id, 160)
    assert {:error, :invalid_session} = Session.validate(session_service, session_cookie, "HU")

    assert {:ok, rust_sid} =
             barrier |> Path.join("rust-session") |> File.read!() |> SessionId.parse()

    now = System.system_time(:second)
    assert {:ok, nil} = DynamoDB.find_session(current_only, rust_sid, now)
    assert {:ok, rust_session} = DynamoDB.find_session(rotating, rust_sid, now)

    assert {:ok, true} =
             DynamoDB.is_session_owner_active(
               rotating,
               rust_session.user_id,
               rust_session.created_at_unix
             )

    assert :ok = DynamoDB.revoke_session(rotating, rust_sid, now)
    assert {:ok, nil} = DynamoDB.find_session(store, rust_sid, now)

    assert {:error, :conditional_write_failed} =
             DynamoDB.revoke_session(rotating, rust_sid, now + 1)

    rust_record = challenge("01", "02", "rust@example.test", lookup_key)
    race_command = plan(rust_record, "c", "d")
    File.write!(Path.join(barrier, "release"), "release")
    elixir_commit = DynamoDB.commit_magic_link_authentication(rotating, race_command)

    assert elixir_commit in [
             :ok,
             {:error, :rejected},
             {:error, :user_conflict},
             {:error, :unavailable}
           ]

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
    assert [_, rust_committed] = Regex.run(~r/compatibility_rust_committed=(\d+)/, output)
    assert if(elixir_commit == :ok, do: 1, else: 0) + String.to_integer(rust_committed) == 1

    assert {:ok, from_rust} =
             DynamoDB.find_magic_link_for_authentication(store, rust_record.selector_lookup_hmac)

    assert from_rust.email == rust_record.email
    assert Lookup.matches?(from_rust.verifier_hash, rust_record.verifier_hash)
    assert from_rust.expires_at_unix == rust_record.expires_at_unix
    assert from_rust.consumed_at_unix == 150
    assert {:ok, raced_user} = DynamoDB.find_user_for_authentication(store, rust_record.email)

    assert UserId.value(raced_user.user_id) in [
             "usr-" <> String.duplicate("c", 32),
             "usr-" <> String.duplicate("e", 32)
           ]

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

    assert_request_to_logout(rotating, lookup_key)
  end

  test "atomic account creation, disable checks and immutable challenge binding leave no partial writes" do
    endpoint = System.fetch_env!("DYNAMODB_LOCAL_ENDPOINT")
    table = "atomic-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

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
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, store} = DynamoDB.new(table, key, {LocalDynamo, endpoint})
    {:ok, lookup_key} = LookupKey.new(:binary.copy(<<0x42>>, 32))
    first = challenge("ab", "cd", "atomic@example.test", lookup_key)

    second = %{
      challenge("01", "02", "atomic@example.test", lookup_key)
      | terms_version: "terms-new",
        privacy_version: "privacy-new",
        consented_at_unix: 120
    }

    for record <- [first, second],
        do: assert(DynamoDB.put_magic_link_if_absent(store, record) == :ok)

    commands = [plan(first, "a", "b"), plan(second, "c", "d")]
    parent = self()

    tasks =
      Enum.map(commands, fn command ->
        Task.async(fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> {command, DynamoDB.commit_magic_link_authentication(store, command)}
          end
        end)
      end)

    for _ <- tasks, do: assert_receive({:ready, _})
    for task <- tasks, do: send(task.pid, :go)
    results = Enum.map(tasks, &Task.await/1)
    assert Enum.count(results, fn {_, result} -> result == :ok end) == 1
    {winner, :ok} = Enum.find(results, fn {_, result} -> result == :ok end)
    {loser, error} = Enum.find(results, fn {_, result} -> result != :ok end)
    assert error in [{:error, :user_conflict}, {:error, :unavailable}]
    assert DynamoDB.commit_magic_link_authentication(store, loser) == {:error, :user_conflict}

    assert {:ok, unconsumed} =
             DynamoDB.find_magic_link_for_authentication(
               store,
               loser.magic_link.selector_lookup_hmac
             )

    assert unconsumed.consumed_at_unix == nil
    assert {:ok, original_user} = DynamoDB.find_user_for_authentication(store, first.email)
    {:create, winner_id} = winner.user
    assert original_user.user_id == winner_id
    {:ok, loser_hmac} = StorageKey.hmac(key, "sih", SessionId.value(loser.session_id))

    assert {:ok, absent} =
             get(endpoint, table, %{
               "pk" => %{"S" => "SESSION#" <> loser_hmac},
               "sk" => %{"S" => "SESSION"}
             })

    refute Map.has_key?(absent, "Item")

    profile_key = %{
      "pk" => %{"S" => "USERID#" <> UserId.value(winner_id)},
      "sk" => %{"S" => "PROFILE"}
    }

    assert {:ok, _} =
             LocalDynamo.request(endpoint, "UpdateItem", %{
               "TableName" => table,
               "Key" => profile_key,
               "UpdateExpression" => "SET disabled = :value",
               "ExpressionAttributeValues" => %{":value" => %{"BOOL" => true}}
             })

    existing = %{loser | user: {:existing, winner_id}, attempt_id: attempt_id()}
    assert DynamoDB.commit_magic_link_authentication(store, existing) == {:error, :user_conflict}

    assert {:ok, _} =
             LocalDynamo.request(endpoint, "UpdateItem", %{
               "TableName" => table,
               "Key" => profile_key,
               "UpdateExpression" => "SET disabled = :value",
               "ExpressionAttributeValues" => %{":value" => %{"BOOL" => false}}
             })

    assert DynamoDB.commit_magic_link_authentication(store, %{
             existing
             | now_unix: 201,
               attempt_id: attempt_id()
           }) == {:error, :rejected}

    assert DynamoDB.commit_magic_link_authentication(store, %{
             existing
             | session_id: winner.session_id,
               attempt_id: attempt_id()
           }) == {:error, :session_conflict}

    {:ok, wrong_email} = Email.normalize("other@example.test")

    for {field, value} <- [
          expires_at_unix: 201,
          terms_version: "different",
          privacy_version: "different",
          consented_at_unix: 0,
          email: wrong_email
        ] do
      changed = %{
        existing
        | magic_link: Map.put(existing.magic_link, field, value),
          attempt_id: attempt_id()
      }

      assert DynamoDB.commit_magic_link_authentication(store, changed) == {:error, :rejected}
    end

    assert DynamoDB.commit_magic_link_authentication(store, %{existing | attempt_id: attempt_id()}) ==
             :ok

    assert {:ok, ^original_user} = DynamoDB.find_user_for_authentication(store, first.email)

    zero_consent = %{
      challenge("03", "04", "zero@example.test", lookup_key)
      | consented_at_unix: 0
    }

    assert DynamoDB.put_magic_link_if_absent(store, zero_consent) == :ok

    assert DynamoDB.commit_magic_link_authentication(store, plan(zero_consent, "e", "f")) ==
             {:error, :rejected}
  end

  test "local-only test client refuses non-loopback endpoints" do
    assert LocalDynamo.request("https://example.test", "UpdateItem", %{}) == {:error, :internal}
  end

  defp assert_request_to_logout(store, lookup_key) do
    now = 150
    versions = {"terms-v1", "privacy-v1"}
    db = {DynamoDB, store}
    clock = fn -> {:ok, now} end
    io = %{repository: db, limiter: db, clock: clock, outbox: {Mailbox, self()}}
    policy = CountryPolicy.eu27()

    assert {:ok, confirm_keys} =
             Keyring.new(:confirm, [{:active, "conf", :binary.copy(<<82>>, 32), 300, 600}])

    assert {:ok, session_keys} =
             Keyring.new(:session, [
               {:active, "session", :binary.copy(<<83>>, 32), 300, 2_592_300}
             ])

    assert {:ok, request} = Request.new(lookup_key, versions, io)

    assert {:ok, flow} =
             Flow.new(lookup_key, {confirm_keys, session_keys}, versions, io,
               country_policy: policy
             )

    assert {:ok, sessions} = Session.new(session_keys, db, clock, {86_400, 2_592_000}, policy)

    assert {:ok, :sent} = Request.request(request, "flow@example.test", true, true)
    assert_receive {:mail, mail}
    assert {:ok, landing} = Flow.land(flow, Token.value(mail.token))
    cookie = ConfirmCookie.cookie_value(landing.flow)
    assert {:ok, state} = Flow.read_state(flow, cookie)
    assert state.account == "f•••••@example.test"
    assert {:ok, nil} = DynamoDB.find_user_for_authentication(store, mail.email)
    assert {:ok, selector} = Lookup.selector(lookup_key, mail.token)

    assert {:ok, %{consumed_at_unix: nil}} =
             DynamoDB.find_magic_link_for_authentication(store, selector)

    outcomes =
      1..2
      |> Task.async_stream(fn _ -> Flow.confirm(flow, cookie, state.confirmation, "HU") end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert [{:ok, authenticated}] = Enum.filter(outcomes, &match?({:ok, _}, &1))
    assert {:error, :magic_link_unavailable} in outcomes
    assert {:error, :magic_link_unavailable} = Flow.read_state(flow, cookie)

    assert {:ok, %{consumed_at_unix: ^now}} =
             DynamoDB.find_magic_link_for_authentication(store, selector)

    assert {:ok, validated} = Session.validate(sessions, authenticated.session_cookie, "AT")
    assert Session.record(validated).email == mail.email

    assert {:error, :invalid_session} =
             Session.validate(sessions, authenticated.session_cookie, "GB")

    assert {:ok, target} = Session.validate_for_logout(sessions, authenticated.session_cookie)
    assert :ok = Session.revoke(sessions, target.session_id)

    assert {:error, :invalid_session} =
             Session.validate(sessions, authenticated.session_cookie, "HU")
  end

  defp assert_request_quotas(store, lookup_key) do
    assert {:ok, locales} = LocaleAllowlist.new("en", ["hu"])

    io = %{
      repository: {DynamoDB, store},
      limiter: {DynamoDB, store},
      outbox: {Mailbox, self()},
      clock: fn -> {:ok, 100} end
    }

    assert {:ok, request} =
             Request.new(lookup_key, {"terms-v1", "privacy-v1"}, io, locales: locales)

    for _ <- 1..3 do
      assert {:ok, :sent} = Request.request(request, " QUOTA@EXAMPLE.TEST ", true, true, "hu-HU")
      assert_receive {:mail, mail}
      assert mail.locale == "hu"
      assert {:ok, selector} = Lookup.selector(lookup_key, mail.token)
      assert {:ok, challenge} = DynamoDB.find_magic_link_for_authentication(store, selector)
      assert challenge.email == mail.email
      assert challenge.expires_at_unix == 700
    end

    assert {:ok, {:throttled, :email_short_window}} =
             Request.request(request, "quota@example.test", true, true)

    refute_received {:mail, _}
  end

  defp challenge(selector, verifier, address, key) do
    {:ok, token} =
      Token.parse(
        "mlv1." <> String.duplicate(selector, 16) <> "." <> String.duplicate(verifier, 32)
      )

    {:ok, selector} = Lookup.selector(key, token)
    {:ok, verifier} = Lookup.verifier(key, token)
    {:ok, email} = Email.normalize(address)

    %Challenge{
      selector_lookup_hmac: selector,
      verifier_hash: verifier,
      email: email,
      expires_at_unix: 200,
      terms_version: "terms-v1",
      privacy_version: "privacy-v1",
      consented_at_unix: 100
    }
  end

  defp plan(record, user_hex, session_hex) do
    {:ok, user} = UserId.parse("usr-" <> String.duplicate(user_hex, 32))
    {:ok, session} = SessionId.parse("sid-" <> String.duplicate(session_hex, 64))

    expected =
      struct!(
        AuthenticationExpectation,
        Map.take(Map.from_struct(record), [
          :selector_lookup_hmac,
          :email,
          :expires_at_unix,
          :terms_version,
          :privacy_version,
          :consented_at_unix
        ])
      )

    %CommitAuthentication{
      magic_link: expected,
      now_unix: 150,
      attempt_id: attempt_id(),
      user: {:create, user},
      session_id: session,
      session_expires_at_unix: 300
    }
  end

  defp attempt_id do
    {:ok, id} =
      AuthenticationAttemptId.parse(
        "aid-" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
      )

    id
  end

  defp wait_ready(_path, 0, rust) do
    case Task.yield(rust, 0) do
      {:ok, {output, status}} -> flunk("Rust exited before the barrier (#{status}):\n#{output}")
      _ -> flunk("Rust did not reach the shared-budget barrier")
    end
  end

  defp wait_ready(path, attempts, rust) do
    unless File.exists?(path) do
      Process.sleep(10)
      wait_ready(path, attempts - 1, rust)
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
