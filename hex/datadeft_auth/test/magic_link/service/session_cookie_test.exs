defmodule DatadeftAuth.MagicLink.Service.SessionCookieTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Service.{SessionCookie, SessionId}
  alias DatadeftAuth.Token.{BoundCookie, Keyring}

  @now 1_700_000_000
  @sid "sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  @root :binary.copy(<<0x45>>, 32)

  test "session cookie carries canonical ID, optional pinned country and original issue time" do
    {:ok, id} = SessionId.parse(@sid)
    issued = @now - 10

    for country <- [nil, "HU", "EU"] do
      assert {:ok, value} = SessionCookie.mint(ring(:session), id, country, @now, issued)
      assert {:ok, result} = SessionCookie.open(ring(:session), value, @now, {60, 300})
      assert result.session_id == id
      assert result.country == country
      assert result.issued_at_unix == issued
      assert result.last_activity_unix == @now
      assert {:ok, frame} = BoundCookie.open(value, ring(:session), @now, {60, 300})
      bytes = country || ""
      assert frame.body == <<1, 68, @sid::binary, byte_size(bytes), bytes::binary>>
      refute inspect(result) =~ @sid
      assert {:error, :invalid_token} = SessionCookie.open(ring(:confirm), value, @now, {60, 300})
    end
  end

  test "malformed authenticated bodies never become session identities" do
    for body <- [
          <<2, 68, @sid::binary, 0>>,
          <<1, 68, @sid::binary, 0, 0>>,
          <<1, 68, @sid::binary, 2, "Hu">>,
          <<1, 68, @sid::binary, 1, "A">>,
          <<1, 68, String.upcase(@sid)::binary, 0>>,
          <<1, 68, @sid::binary>>
        ] do
      assert {:ok, value} = BoundCookie.mint(body, ring(:session), @now, @now, @now)
      assert {:error, :invalid_token} = SessionCookie.open(ring(:session), value, @now, {60, 300})
    end

    {:ok, id} = SessionId.parse(@sid)
    assert {:error, :invalid_input} = SessionCookie.mint(ring(:session), id, "hu", @now, @now)
    assert {:error, :invalid_input} = SessionCookie.mint(ring(:confirm), id, nil, @now, @now)
  end

  defp ring(purpose) do
    {:ok, ring} =
      Keyring.new(purpose, [{:active, "session-active", @root, @now, @now + 2_592_000}])

    ring
  end
end
