defmodule DatadeftAuth.AWS.DynamoDB.UserLookupTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.DynamoDB
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.UserId

  defmodule Client do
    def request(owner, operation, input) do
      send(owner, {:request, operation, input})

      receive do
        {:reply, result} -> result
      after
        1_000 -> {:error, :unavailable}
      end
    end
  end

  setup do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, store} = DynamoDB.new("synthetic-auth", key, {Client, self()})
    {:ok, email} = Email.normalize("user@example.test")
    %{store: store, key: key, email: email}
  end

  defp user_id, do: "usr-" <> String.duplicate("ab", 16)

  defp lookup,
    do: %{
      "entity_type" => %{"S" => "user_email_lookup"},
      "email_normalized" => %{"S" => "user@example.test"},
      "user_id" => %{"S" => user_id()}
    }

  defp profile,
    do: %{
      "entity_type" => %{"S" => "user_profile"},
      "user_id" => %{"S" => user_id()},
      "email_normalized" => %{"S" => "user@example.test"},
      "disabled" => %{"BOOL" => false},
      "terms_version" => %{"S" => "terms-v1"},
      "privacy_version" => %{"S" => "privacy-v1"},
      "consented_at_unix" => %{"N" => "100"}
    }

  defp reply(item), do: send(self(), {:reply, {:ok, %{"Item" => item}}})

  test "reads Rust's email lookup and profile with strong consistency", context do
    reply(lookup())
    reply(profile())
    assert {:ok, user} = DynamoDB.find_user_for_authentication(context.store, context.email)
    assert UserId.value(user.user_id) == user_id()
    assert user.email == context.email
    refute user.disabled
    assert user.terms_version == "terms-v1"
    assert user.privacy_version == "privacy-v1"
    assert user.consented_at_unix == 100
    assert inspect(user) == "#DatadeftAuth.MagicLink.Service.User<redacted>"
    assert {:ok, lookup_key} = Keys.user_email(context.key, context.email)
    assert_receive {:request, "GetItem", %{"Key" => ^lookup_key, "ConsistentRead" => true}}

    assert_receive {:request, "GetItem",
                    %{
                      "Key" => %{"pk" => %{"S" => pk}, "sk" => %{"S" => "PROFILE"}},
                      "ConsistentRead" => true
                    }}

    assert pk == "USERID#" <> user_id()
  end

  test "absent lookup is absent, but a dangling lookup fails closed", context do
    send(self(), {:reply, {:ok, %{}}})
    assert DynamoDB.find_user_for_authentication(context.store, context.email) == {:ok, nil}
    reply(lookup())
    send(self(), {:reply, {:ok, %{}}})

    assert DynamoDB.find_user_for_authentication(context.store, context.email) ==
             {:error, :internal}
  end

  test "missing and corrupt required profile data fail closed", context do
    for field <- ["entity_type", "user_id", "email_normalized", "disabled"] do
      reply(lookup())
      reply(Map.delete(profile(), field))

      assert DynamoDB.find_user_for_authentication(context.store, context.email) ==
               {:error, :internal}
    end

    for {field, value} <- [
          {"entity_type", %{"S" => "user_email_lookup"}},
          {"disabled", %{"S" => "false"}},
          {"email_normalized", %{"S" => "User@example.test"}},
          {"email_normalized", %{"S" => "other@example.test"}},
          {"user_id", %{"S" => "usr-" <> String.duplicate("cd", 16)}},
          {"consented_at_unix", %{"N" => "-1"}},
          {"consented_at_unix", %{"N" => "18446744073709551616"}},
          {"terms_version", %{"N" => "1"}}
        ] do
      reply(lookup())
      reply(Map.put(profile(), field, value))

      assert DynamoDB.find_user_for_authentication(context.store, context.email) ==
               {:error, :internal}
    end
  end

  test "optional consent fields may be absent; disabled is preserved for service policy",
       context do
    reply(lookup())

    reply(
      profile()
      |> Map.drop(["terms_version", "privacy_version", "consented_at_unix"])
      |> Map.put("disabled", %{"BOOL" => true})
    )

    assert {:ok, user} = DynamoDB.find_user_for_authentication(context.store, context.email)
    assert user.disabled
    assert user.terms_version == nil
    assert user.consented_at_unix == nil
  end

  test "corrupt lookups and dependency failures are not reported as missing accounts", context do
    for item <- [
          Map.put(lookup(), "entity_type", %{"S" => "user_profile"}),
          Map.put(lookup(), "email_normalized", %{"S" => "other@example.test"}),
          Map.put(lookup(), "user_id", %{"S" => "usr_legacy"})
        ] do
      reply(item)

      assert DynamoDB.find_user_for_authentication(context.store, context.email) ==
               {:error, :internal}
    end

    send(self(), {:reply, {:error, :unavailable}})

    assert DynamoDB.find_user_for_authentication(context.store, context.email) ==
             {:error, :unavailable}
  end
end
