defmodule DatadeftAuth.MagicLink.Core.TokenTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Core.Token

  @selector "000102030405060708090a0b0c0d0e0f"
  @verifier "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
  @wire "mlv1." <> @selector <> "." <> @verifier

  test "exact Rust wire grammar and redacted rendering" do
    assert {:ok, token} = Token.parse(@wire)
    assert Token.value(token) == @wire
    assert Token.selector(token) == @selector
    assert Token.verifier(token) == @verifier
    assert inspect(token) == "#DatadeftAuth.MagicLink.Core.Token<redacted>"
  end

  test "refuses noncanonical spellings, extra segments and invalid bytes" do
    for input <- [
          "",
          String.upcase(@wire),
          @wire <> ".",
          @wire <> "\n",
          " " <> @wire,
          String.replace(@wire, "mlv1", "mlv0"),
          "mlv1." <> @selector <> "." <> String.duplicate("g", 64),
          "mlv1." <> @selector <> "." <> String.duplicate("0", 63),
          <<255>>,
          nil
        ] do
      assert Token.parse(input) == {:error, :invalid_token}
    end
  end

  test "generation makes two independent entropy requests of the correct sizes" do
    entropy = fn size ->
      send(self(), {:draw, size})

      case size do
        16 -> {:ok, Base.decode16!(@selector, case: :lower)}
        32 -> {:ok, Base.decode16!(@verifier, case: :lower)}
      end
    end

    assert {:ok, token} = Token.generate(entropy)
    assert Token.value(token) == @wire
    assert_receive {:draw, 16}
    assert_receive {:draw, 32}
    refute_receive {:draw, _}
  end

  test "entropy failure or wrong-sized draws fail closed" do
    assert Token.generate(fn _ -> {:error, :unavailable} end) == {:error, :entropy_unavailable}
    assert Token.generate(fn _ -> {:ok, <<0>>} end) == {:error, :entropy_unavailable}

    assert Token.generate(fn
             16 -> {:ok, :binary.copy(<<0>>, 16)}
             32 -> {:error, :unavailable}
           end) == {:error, :entropy_unavailable}
  end
end
