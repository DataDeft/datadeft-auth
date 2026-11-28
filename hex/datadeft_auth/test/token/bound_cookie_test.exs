defmodule DatadeftAuth.Token.BoundCookieTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.Token.{BoundCookie, Branca, Keyring}

  @now 1_700_000_000
  @root :binary.copy(<<0x45>>, 32)
  @kid "session-active"
  @sid "sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  # Synthetic pin from Rust's session_cookie_golden_value_and_single_edits_are_rejected.
  @golden "v1.session-active.1cvR6OEpuO38jsjYKybSqZiPuQpoAJRIqyuPinjG9yOzapVUJAzYsNBITbuG43wc89HecbOAt66OVagxgUfGOfr1w1HJx0Qop85kIDIm42COckWGIwR0UsU0YytUd0jpUjTzdfiRzy590C3OlMY7Kro5aooao8CGGAxUZ4t0YLIjlfZ94aqTXLLOdyG7UKluqzBzuNgIn"

  test "opens Rust's golden cookie, with exact authenticated body bytes" do
    assert {:ok, result} = BoundCookie.open(@golden, ring(), @now, {60, 60})
    assert result.body == <<1, 68, @sid::binary, 2, "HU">>
    assert result.kid == @kid
    assert result.timestamp == @now
    assert result.iat == @now
    assert byte_size(result.nonce) == 24
    refute inspect(result) =~ @sid
    assert {:ok, _} = BoundCookie.open(@golden, ring(), @now + 60, {60, 60})
    assert {:error, :invalid_token} = BoundCookie.open(@golden, ring(), @now + 61, {60, 60})
  end

  test "mint produces exact framing and derives the Rust HKDF key" do
    root = :binary.copy(<<0x11>>, 32)
    ring = ring(root)

    assert {:ok, "v1.session-active." <> token} =
             BoundCookie.mint("body", ring, @now, @now - 12, @now)

    key =
      Base.decode16!("eda74d6ba28134ffe9c380e3a14729aa1fa4474dfbf63014a8b82e0325e4b10b",
        case: :lower
      )

    iat = @now - 12

    assert {:ok, {@now, _, <<1, ^iat::32, 10, "session-v1", 14, "session-active", "body">>}} =
             Branca.decode(token, key)
  end

  test "skew never extends expiration and sliding refresh retains absolute time" do
    assert {:ok, token} = BoundCookie.mint("body", ring(), @now, @now - 200, @now)
    assert {:ok, _} = BoundCookie.open(token, ring(), @now + 1, {1, 201})
    assert {:error, :invalid_token} = BoundCookie.open(token, ring(), @now + 1, {60, 200})
    assert {:ok, _} = BoundCookie.open(token, ring(), @now - 60, {1, 201})
    assert {:error, :invalid_token} = BoundCookie.open(token, ring(), @now - 61, {60, 201})
    assert {:error, :invalid_token} = BoundCookie.open(token, ring(), @now - 1, {60, 201}, 0)
    assert {:error, :invalid_timestamp} = BoundCookie.open(token, ring(), @now, {60, 2_592_001})
    assert {:error, :invalid_timestamp} = BoundCookie.open(token, ring(), @now, {60, 60}, 301)
    assert {:error, :invalid_timestamp} = BoundCookie.mint("body", ring(), @now, @now + 1, @now)

    assert {:error, :invalid_timestamp} =
             BoundCookie.mint("body", ring(), @now - 61, @now - 61, @now)
  end

  test "key rotation verifies old values only inside their window and mints only active" do
    slots = [{:verify_only, @kid, @root, @now + 10}, active("next", @root)]
    assert {:ok, rotated} = Keyring.new(:session, slots)
    assert {:ok, _} = BoundCookie.open(@golden, rotated, @now + 10, {300, 300})
    assert {:error, :invalid_token} = BoundCookie.open(@golden, rotated, @now + 11, {300, 300})
    assert {:ok, "v1.next." <> _} = BoundCookie.mint("body", rotated, @now, @now, @now)

    assert {:error, :key_expired} =
             BoundCookie.mint("body", rotated, @now + 101, @now, @now + 101)

    assert {:ok, retired} = Keyring.new(:session, [active("next", @root)])
    assert {:error, :invalid_token} = BoundCookie.open(@golden, retired, @now, {60, 60})
    refute inspect(rotated) =~ @kid
  end

  test "malformed wrappers, cross-purpose values and authenticated wrong inner metadata fail closed" do
    assert {:ok, wrong_purpose} = Keyring.new(:confirm, [active(@kid, @root)])
    assert {:error, :invalid_token} = BoundCookie.open(@golden, wrong_purpose, @now, {60, 60})
    [_, _, golden_token] = :binary.split(@golden, ".", [:global])

    for value <- [
          nil,
          "v2.x.y",
          "v1..x",
          "v1.session-active.",
          "v1.session-active.a.b",
          "v1.bad kid.a",
          "v1.session-active.0" <> golden_token
        ] do
      assert {:error, :invalid_token} = BoundCookie.open(value, ring(), @now, {60, 60})
    end

    root = :binary.copy(<<0x11>>, 32)

    key =
      Base.decode16!("eda74d6ba28134ffe9c380e3a14729aa1fa4474dfbf63014a8b82e0325e4b10b",
        case: :lower
      )

    for payload <- [
          <<1, @now::32, 1, "x", 14, @kid::binary>>,
          <<1, @now::32, 10, "session-v1", 1, "x">>,
          <<2, @now::32>>,
          <<1, @now + 1::32, 10, "session-v1", 14, @kid::binary>>
        ] do
      {:ok, token} = Branca.encode(payload, key, @now)

      assert {:error, :invalid_token} =
               BoundCookie.open("v1." <> @kid <> "." <> token, ring(root), @now, {60, 60})
    end
  end

  test "keyring requires unique sane windows and a purpose-specific kid budget" do
    for slots <- [
          [],
          [{:verify_only, @kid, @root, @now}],
          [active(@kid, @root), active(@kid, @root)],
          [active(@kid, @root), active("next", @root)],
          [active("bad.kid", @root)],
          [active(@kid, <<1>>)],
          [{:active, @kid, @root, @now, @now + 2_591_999}]
        ] do
      assert {:error, :keyring_misconfigured} = Keyring.new(:session, slots)
    end

    assert {:ok, _} = Keyring.new(:pow_proof, [active(String.duplicate("k", 12), @root)])

    assert {:error, :keyring_misconfigured} =
             Keyring.new(:pow_proof, [active(String.duplicate("k", 13), @root)])

    assert {:ok, _} = Keyring.new(:session, [active(String.duplicate("k", 38), @root)])

    assert {:error, :keyring_misconfigured} =
             Keyring.new(:session, [active(String.duplicate("k", 39), @root)])

    assert {:error, :payload_too_large} =
             BoundCookie.mint(:binary.copy(<<0>>, 98), ring(), @now, @now, @now)
  end

  defp ring(root \\ @root) do
    {:ok, ring} = Keyring.new(:session, [active(@kid, root)])
    ring
  end

  defp active(kid, root), do: {:active, kid, root, @now + 100, @now + 100 + 2_592_000}
end
