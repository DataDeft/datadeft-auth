defmodule DatadeftAuth.MagicLink.Core.LookupTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Core.{Email, Lookup, LookupKey, Token}

  setup do
    {:ok, key} = LookupKey.new(:binary.copy(<<0x42>>, 32))

    {:ok, token} =
      Token.parse(
        "mlv1.000102030405060708090a0b0c0d0e0f.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
      )

    %{key: key, token: token}
  end

  test "matches the Rust service lookup and verifier vectors", %{key: key, token: token} do
    {:ok, email} = Email.normalize("USER@EXAMPLE.COM")
    assert {:ok, account} = Lookup.email(key, email)
    assert {:ok, selector} = Lookup.selector(key, token)
    assert {:ok, verifier} = Lookup.verifier(key, token)

    assert Lookup.storage_value(account) ==
             "emh_7330b67f746ac427ff0777354000ca197fd1120ee6cf99371c484b92b8d517c8"

    assert Lookup.storage_value(selector) ==
             "mlh_42fb608ee6ce2ac56bac6bb240a98c857a315afbb186159a59133b679d597a21"

    assert Lookup.storage_value(verifier) ==
             "mlv_ae00fd0d4e973106d9bd55e5f219d530f554138c53327c07c81a7df8a1cbadae"

    for lookup <- [account, selector, verifier] do
      assert {:ok, parsed} = Lookup.parse(lookup.kind, Lookup.storage_value(lookup))
      assert Lookup.matches?(lookup, parsed)
      assert byte_size(Lookup.binding(lookup)) == 32
      assert inspect(lookup) == "#DatadeftAuth.MagicLink.Core.Lookup<redacted>"
    end

    assert inspect(key) == "#DatadeftAuth.MagicLink.Core.LookupKey<redacted>"
  end

  test "verifier comparisons are constant-time and role-bound", %{key: key, token: token} do
    assert {:ok, verifier} = Lookup.verifier(key, token)
    assert {:ok, selector} = Lookup.selector(key, token)
    refute Lookup.matches?(selector, verifier)
    assert {:ok, other} = Lookup.parse(:verifier, "mlv_" <> String.duplicate("0", 64))
    refute Lookup.matches?(verifier, other)
  end

  test "lookup parser refuses uppercase, wrong roles, wrong lengths and trailing data" do
    value = "mlv_" <> String.duplicate("a", 64)

    for invalid <- [
          String.upcase(value),
          value <> "\n",
          value <> "0",
          " " <> value,
          "mlv_" <> String.duplicate("a", 63),
          nil
        ] do
      assert Lookup.parse(:verifier, invalid) == {:error, :invalid_token}
    end

    assert Lookup.parse(:selector, value) == {:error, :invalid_token}
    assert LookupKey.new(<<0>>) == {:error, :bad_key_length}
  end
end
