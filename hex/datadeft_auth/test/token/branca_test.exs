defmodule DatadeftAuth.Token.BrancaTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.Token.{Base62, Branca}

  @key :binary.copy(<<0x42>>, 32)

  test "bounded binary payloads round-trip with authenticated time and fresh OS nonces" do
    for payload <- [<<>>, <<0, 255, 128>>, :binary.copy(<<1>>, 1024)] do
      assert {:ok, first} = Branca.encode(payload, @key, 123)
      assert {:ok, second} = Branca.encode(payload, @key, 123)
      assert {:ok, {123, nonce, ^payload}} = Branca.decode(first, @key)
      assert byte_size(nonce) == 24
      assert {:ok, {123, other_nonce, ^payload}} = Branca.decode(second, @key)
      refute :crypto.hash_equals(nonce, other_nonce)
    end
  end

  test "rejects tampered headers, ciphertext, wrong keys and noncanonical spellings" do
    {:ok, token} = Branca.encode("synthetic payload", @key, 0)
    {:ok, blob} = Base62.decode(token)

    for position <- [0, 1, 5, 29, byte_size(blob) - 1] do
      <<before::binary-size(position), byte, after_bytes::binary>> = blob
      changed = before <> <<Bitwise.bxor(byte, 1)>> <> after_bytes
      assert Branca.decode(Base62.encode(changed), @key) == {:error, :invalid_token}
    end

    assert Branca.decode(token, :binary.copy(<<0x43>>, 32)) == {:error, :invalid_token}
    assert Branca.decode("0" <> token, @key) == {:error, :invalid_token}
  end

  test "invalid inputs fail with fixed atoms, including calls bypassing the Elixir facade" do
    for module <- [Branca, DatadeftAuth.Native] do
      encode = if module == Branca, do: :encode, else: :branca_encode
      decode = if module == Branca, do: :decode, else: :branca_decode

      for {data, key, timestamp} <- [
            {:binary.copy(<<0>>, 1025), @key, 0},
            {<<>>, <<>>, 0},
            {nil, @key, 0},
            {<<>>, @key, -1},
            {<<>>, @key, 4_294_967_296},
            {<<>>, nil, 0}
          ] do
        assert apply(module, encode, [data, key, timestamp]) == {:error, :invalid_input}
      end

      for {token, key} <- [
            {String.duplicate("a", 1438), @key},
            {nil, @key},
            {<<255>>, @key},
            {"", @key},
            {"a", nil},
            {"a", <<>>}
          ] do
        assert apply(module, decode, [token, key]) == {:error, :invalid_token}
      end
    end
  end

  @tag :repository
  test "decodes and rejects every applicable official Rust Branca vector" do
    path =
      Path.expand(
        "../../../../crates/datadeft-auth-token-core/tests/fixtures/branca_test.json",
        __DIR__
      )

    vectors = path |> File.read!() |> Jason.decode!()

    for group <- vectors["testGroups"], vector <- group["tests"] do
      key = Base.decode16!(vector["key"], case: :mixed)

      if vector["isValid"] do
        payload = Base.decode16!(vector["msg"], case: :mixed)
        timestamp = vector["timestamp"]
        assert {:ok, {^timestamp, nonce, ^payload}} = Branca.decode(vector["token"], key)
        assert byte_size(nonce) == 24
      else
        assert Branca.decode(vector["token"], key) == {:error, :invalid_token}
      end
    end
  end
end
