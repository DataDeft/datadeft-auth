defmodule DatadeftAuth.MagicLink.Core.ConfirmCookieTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Core.{ConfirmCookie, Lookup}
  alias DatadeftAuth.Token.{BoundCookie, Branca, Keyring}

  @now 900
  @expiry 1000
  @nonce :binary.copy(<<0xAA>>, 32)
  @root :binary.copy(<<0x11>>, 32)
  @selector :binary.copy(<<0x11>>, 32)
  @verifier :binary.copy(<<0x22>>, 32)
  @account :binary.copy(<<0x33>>, 32)
  @body <<1, @selector::binary, @verifier::binary, @account::binary, @nonce::binary, @expiry::32>>

  test "pins Rust's body and HKDF, and opens only with the independent canonical nonce" do
    ring = ring()
    {selector, verifier, account} = bindings()

    draw = fn n ->
      send(self(), {:draw, n})
      {:ok, @nonce}
    end

    assert {:ok, minted} =
             ConfirmCookie.mint(ring, {selector, verifier, account}, @expiry, @now, draw)

    assert_receive {:draw, 32}
    refute_received {:draw, _}
    value = ConfirmCookie.cookie_value(minted)
    confirmation = ConfirmCookie.confirmation(minted)
    assert confirmation == Base.encode16(@nonce, case: :lower)
    refute inspect(minted) =~ confirmation
    assert {:ok, frame} = BoundCookie.open(value, ring, @now, {300, 300})
    assert frame.body == @body
    assert "v1.confirm-active." <> token = value

    key =
      Base.decode16!("64423584c5e2c5dc0648d1bec4443bc4e1d019cbaea681b5e84ced9b3cb0c313",
        case: :lower
      )

    assert {:ok,
            {@now, _, <<1, @now::32, 13, "ml-confirm-v1", 14, "confirm-active", @body::binary>>}} =
             Branca.decode(token, key)

    assert {:ok, state} = ConfirmCookie.verify(ring, value, confirmation, @expiry, 300)
    assert Lookup.matches?(state.selector, selector)
    assert Lookup.matches?(state.verifier, verifier)
    assert Lookup.matches?(state.account, account)
    assert state.expires_at_unix == @expiry
    assert {:ok, read} = ConfirmCookie.read(ring, value, @now, 300)
    assert ConfirmCookie.confirmation(read) == confirmation
    refute inspect(read) =~ confirmation

    for invalid <- [
          String.upcase(confirmation),
          "00" <> binary_part(confirmation, 2, 62),
          confirmation <> "\n",
          nil
        ] do
      assert {:error, :invalid_token} = ConfirmCookie.verify(ring, value, invalid, @now, 300)
    end

    assert {:error, :invalid_token} =
             ConfirmCookie.verify(ring, value, confirmation, @expiry + 1, 300)

    assert {:error, :invalid_token} = ConfirmCookie.verify(ring, value, confirmation, @now, 99)
    assert {:error, :invalid_token} = ConfirmCookie.read(ring, value, @now, 0)
  end

  test "rejects malformed authenticated bodies, wrong binding roles and invalid expiry" do
    ring = ring()

    for body <- [
          @body <> <<0>>,
          binary_part(@body, 0, 132),
          <<2>> <> binary_part(@body, 1, 132),
          binary_part(@body, 0, 129) <> <<@now - 1::32>>
        ] do
      {:ok, value} = BoundCookie.mint(body, ring, @now, @now, @now)
      assert {:error, :invalid_token} = ConfirmCookie.read(ring, value, @now, 300)
    end

    {selector, verifier, account} = bindings()
    draw = fn _ -> {:ok, @nonce} end

    assert {:error, :invalid_input} =
             ConfirmCookie.mint(ring, {verifier, selector, account}, @expiry, @now, draw)

    assert {:error, :invalid_timestamp} =
             ConfirmCookie.mint(ring, bindings(), @now + 301, @now, draw)

    assert {:error, :invalid_timestamp} =
             ConfirmCookie.mint(ring, bindings(), @now - 1, @now, draw)

    assert {:error, :entropy_unavailable} =
             ConfirmCookie.mint(ring, bindings(), @expiry, @now, fn _ -> {:ok, <<1>>} end)
  end

  defp ring do
    {:ok, ring} = Keyring.new(:confirm, [{:active, "confirm-active", @root, @now, @now + 300}])
    ring
  end

  defp bindings do
    {:ok, selector} = Lookup.parse(:selector, "mlh_" <> Base.encode16(@selector, case: :lower))
    {:ok, verifier} = Lookup.parse(:verifier, "mlv_" <> Base.encode16(@verifier, case: :lower))
    {:ok, account} = Lookup.parse(:email, "emh_" <> Base.encode16(@account, case: :lower))
    {selector, verifier, account}
  end
end
