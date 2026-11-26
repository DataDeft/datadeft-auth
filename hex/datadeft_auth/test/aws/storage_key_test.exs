defmodule DatadeftAuth.AWS.StorageKeyTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.StorageKey

  test "matches the Rust storage HMAC vectors" do
    assert {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))

    assert StorageKey.hmac(key, "sih", "sid_000102030405060708090a0b") ==
             {:ok, "sih_87e7f48488fa0a349a177fc19ab47a99cce9e36171c10270856df31f7ed52807"}

    assert StorageKey.hmac(key, "emh", "user@example.com") ==
             {:ok, "emh_48f078f217f580d763c2edf13fec18bf2ffc3490100ecc51450090f196a23bf5"}

    assert StorageKey.hmac(key, "rlh", "req:email:user@example.com:0") ==
             {:ok, "rlh_1bd9b30bdc96ac134e8e1ee7f593eddcd0144cb506c22d176cf22e4245464574"}
  end

  test "rejects invalid key lengths and does not echo input" do
    for bytes <- [<<>>, :binary.copy(<<0x11>>, 31), :binary.copy(<<0x11>>, 33), nil] do
      assert StorageKey.new(bytes) == {:error, :bad_key_length}
    end
  end

  test "inspection redacts key material" do
    assert {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert inspect(key) == "#DatadeftAuth.AWS.StorageKey<redacted>"
  end

  test "framing rejects NUL prefixes but permits NUL in the value like Rust" do
    assert {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert StorageKey.hmac(key, "emh\0other", "value") == {:error, :invalid_framing}
    assert {:ok, first} = StorageKey.hmac(key, "emh", "a\0b")
    assert {:ok, second} = StorageKey.hmac(key, "emh", "ab")
    refute first == second
  end

  test "domains and prefixes separate identical inputs" do
    assert {:ok, key} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert {:ok, email} = StorageKey.hmac(key, "emh", "value")
    assert {:ok, session} = StorageKey.hmac(key, "sih", "value")

    refute String.split(email, "_", parts: 2) |> List.last() ==
             String.split(session, "_", parts: 2) |> List.last()
  end

  test "key identity uses constant-time comparison" do
    assert {:ok, first} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert {:ok, same} = StorageKey.new(:binary.copy(<<0x11>>, 32))
    assert {:ok, other} = StorageKey.new(:binary.copy(<<0x22>>, 32))
    assert StorageKey.same?(first, same)
    refute StorageKey.same?(first, other)
  end
end
