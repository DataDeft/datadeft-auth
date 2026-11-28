defmodule DatadeftAuth.AWS.DynamoDB.KeysTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.MagicLink.Core.Email

  setup do
    {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    %{key: key}
  end

  test "email identity uses the storage domain, not the service lookup domain", %{key: key} do
    assert {:ok, email} = Email.normalize(" USER@EXAMPLE.COM ")

    assert Keys.user_email(key, email) ==
             {:ok,
              %{
                "pk" => %{
                  "S" =>
                    "USER#emh_48f078f217f580d763c2edf13fec18bf2ffc3490100ecc51450090f196a23bf5"
                },
                "sk" => %{"S" => "PROFILE"}
              }}
  end

  test "lifetime counter identity matches Rust and never depends on a storage key" do
    assert Keys.lifetime_rate("pow:budget:abc") ==
             {:ok,
              %{
                "pk" => %{
                  "S" => "RL#lt_952cdd8fe2cbc9ac3c77dfe0e178850e9d4bc329ab5d930e918c71f29c469c8a"
                },
                "sk" => %{"S" => "COUNTER"}
              }}
  end

  test "fixed-window boundaries match Rust, including the zero-window bucket", %{key: key} do
    assert {:ok, first} = Keys.rate(key, "req:email:synthetic", 60, 0)
    assert Keys.rate(key, "req:email:synthetic", 60, 59) == {:ok, first}
    assert {:ok, second} = Keys.rate(key, "req:email:synthetic", 60, 60)
    refute second == first
    assert Keys.rate(key, "req:email:synthetic", 0, 123) == {:ok, first}
    assert Keys.rate(key, "req:email:synthetic", 0, 18_446_744_073_709_551_615) == {:ok, first}
  end

  test "rate keys are bounded ASCII components, like Rust", %{key: key} do
    for value <- ["", "a b", "a@example.test", "a\0b", String.duplicate("a", 257), nil] do
      assert Keys.lifetime_rate(value) == {:error, :invalid_key}
      assert Keys.rate(key, value, 60, 0) == {:error, :invalid_key}
    end

    assert {:ok, _} = Keys.lifetime_rate(String.duplicate("a", 256))
    assert Keys.rate(key, "valid", -1, 0) == {:error, :invalid_key}
    assert Keys.rate(key, "valid", 60, 18_446_744_073_709_551_616) == {:error, :invalid_key}
  end
end
