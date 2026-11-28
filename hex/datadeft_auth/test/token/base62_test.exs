defmodule DatadeftAuth.Token.Base62Test do
  use ExUnit.Case, async: true
  alias DatadeftAuth.Token.Base62

  test "matches Rust's pinned standard-alphabet vectors in both directions" do
    for {bytes, encoded} <- [
          {"", ""},
          {"f", "1e"},
          {"fo", "6ox"},
          {"foo", "SAPP"},
          {"foob", "1sIyuo"},
          {"fooba", "7kENWa1"},
          {"foobar", "VytN8Wjy"},
          {"=", "z"},
          {">", "10"},
          {"?", "11"},
          {"Hello, World!", "1wJfrzvdbtXUOlUjUf"},
          {"你好，世界！", "1ugmIChyMAcCbDRpROpAtpXdp"},
          {"こんにちは", "1fyB0pNlcVqP3tfXZ1FmB"}
        ] do
      assert Base62.encode(bytes) == encoded
      assert Base62.decode(encoded) == {:ok, bytes}
    end
  end

  test "preserves Rust's integer-codec limitations, not arbitrary-byte semantics" do
    assert Base62.encode(<<0, 0>>) == ""
    assert Base62.encode(<<0, 1, 2>>) == Base62.encode(<<1, 2>>)
    assert Base62.decode("0001") == {:ok, <<1>>}
    assert Base62.decode("000") == {:ok, <<>>}
  end

  test "rejects every non-alphabet byte, including whitespace and invalid UTF-8" do
    for input <- [" A", "A\nB", "A\rB", "ABC@123", "é", <<255>>, nil] do
      assert Base62.decode(input) == {:error, :invalid_base62}
    end
  end

  test "bounded arbitrary nonzero-leading blobs round trip canonically" do
    for size <- [1, 2, 16, 45, 128, 1_069] do
      bytes = <<0xBA>> <> :binary.copy(<<0xAB>>, size - 1)
      encoded = Base62.encode(bytes)
      assert Base62.decode(encoded) == {:ok, bytes}
      refute String.starts_with?(encoded, "0")
    end
  end
end
