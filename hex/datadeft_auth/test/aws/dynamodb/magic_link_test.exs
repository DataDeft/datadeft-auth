defmodule DatadeftAuth.AWS.DynamoDB.MagicLinkTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.AWS.{DynamoDB, StorageKey}
  alias DatadeftAuth.MagicLink.Core.{Email, Lookup, LookupKey, Token}
  alias DatadeftAuth.MagicLink.Service.Challenge

  defmodule Client do
    def request({owner, response}, operation, input) do
      send(owner, {:request, operation, input})
      response
    end
  end

  defp setup_record(response \\ {:ok, %{}}) do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    {:ok, store} = DynamoDB.new("synthetic-auth", key, {Client, {self(), response}})

    {:ok, token} =
      Token.parse("mlv1." <> String.duplicate("ab", 16) <> "." <> String.duplicate("cd", 32))

    {:ok, lookup_key} = LookupKey.new(:binary.copy(<<0x42>>, 32))
    {:ok, selector} = Lookup.selector(lookup_key, token)
    {:ok, verifier} = Lookup.verifier(lookup_key, token)
    {:ok, email} = Email.normalize("elixir@example.test")

    {store,
     %Challenge{
       selector_lookup_hmac: selector,
       verifier_hash: verifier,
       email: email,
       expires_at_unix: 200,
       terms_version: "terms-v1",
       privacy_version: "privacy-v1",
       consented_at_unix: 100
     }}
  end

  test "writes the exact Rust challenge shape with keyed material only" do
    {store, record} = setup_record()
    assert DynamoDB.put_magic_link_if_absent(store, record) == :ok
    assert_receive {:request, "PutItem", input}
    assert input["ConditionExpression"] == "attribute_not_exists(pk)"
    item = input["Item"]

    assert Map.keys(item) |> Enum.sort() ==
             Enum.sort([
               "pk",
               "sk",
               "entity_type",
               "email_normalized",
               "verifier_hash",
               "expires_at_unix",
               "terms_version",
               "privacy_version",
               "consented_at_unix",
               "ttl"
             ])

    assert item["pk"] == %{"S" => "ML#" <> Lookup.storage_value(record.selector_lookup_hmac)}
    assert item["sk"] == %{"S" => "CHALLENGE"}
    assert item["ttl"] == %{"N" => "86600"}
    assert item["verifier_hash"] == %{"S" => Lookup.storage_value(record.verifier_hash)}
    assert item["email_normalized"] == %{"S" => "elixir@example.test"}
    assert inspect(record) == "#DatadeftAuth.MagicLink.Service.Challenge<redacted>"
  end

  test "reads Rust's candidate without consuming it and validates every required field" do
    {store, record} = setup_record()
    assert :ok = DynamoDB.put_magic_link_if_absent(store, record)
    assert_receive {:request, "PutItem", %{"Item" => item}}
    {store, _} = setup_record({:ok, %{"Item" => item}})

    assert {:ok, decoded} =
             DynamoDB.find_magic_link_for_authentication(store, record.selector_lookup_hmac)

    assert decoded.email == record.email
    assert Lookup.matches?(decoded.verifier_hash, record.verifier_hash)
    assert decoded.consumed_at_unix == nil
    assert_receive {:request, "GetItem", %{"ConsistentRead" => true}}
    refute_receive {:request, "UpdateItem", _}

    for field <- [
          "entity_type",
          "email_normalized",
          "verifier_hash",
          "expires_at_unix",
          "terms_version",
          "privacy_version",
          "consented_at_unix"
        ] do
      {store, _} = setup_record({:ok, %{"Item" => Map.delete(item, field)}})

      assert DynamoDB.find_magic_link_for_authentication(store, record.selector_lookup_hmac) ==
               {:error, :internal}
    end
  end

  test "keeps conditional failures distinct from outages and rejects malformed records" do
    for {response, expected} <- [
          {{:error, :conditional_write_failed}, {:error, :conditional_write_failed}},
          {{:error, :unavailable}, {:error, :unavailable}}
        ] do
      {store, record} = setup_record(response)
      assert DynamoDB.put_magic_link_if_absent(store, record) == expected
    end

    {store, record} = setup_record()

    assert DynamoDB.put_magic_link_if_absent(store, %{record | expires_at_unix: -1}) ==
             {:error, :invalid_input}

    assert DynamoDB.put_magic_link_if_absent(store, %{
             record
             | verifier_hash: record.selector_lookup_hmac
           }) == {:error, :invalid_input}
  end
end
