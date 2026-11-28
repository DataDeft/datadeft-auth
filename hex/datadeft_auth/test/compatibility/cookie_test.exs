defmodule DatadeftAuth.Compatibility.CookieTest do
  use ExUnit.Case, async: false
  alias DatadeftAuth.MagicLink.Core.{ConfirmCookie, Lookup}
  alias DatadeftAuth.MagicLink.Service.{SessionCookie, SessionId}
  alias DatadeftAuth.Token.Keyring

  @moduletag :repository
  @moduletag timeout: 120_000
  @now 1_700_000_000
  @expiry @now + 100
  @sid "sid-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

  test "Rust and Elixir each open the other's session and confirmation cookies" do
    dir =
      Path.join(System.tmp_dir!(), "dd-cookie-" <> Base.encode16(:crypto.strong_rand_bytes(16)))

    File.mkdir!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    {:ok, sid} = SessionId.parse(@sid)
    session_ring = ring(:session, "session-active", 0x45, 2_592_000)
    confirm_ring = ring(:confirm, "confirm-active", 0x11, 300)
    {:ok, selector} = Lookup.parse(:selector, "mlh_" <> String.duplicate("11", 32))
    {:ok, verifier} = Lookup.parse(:verifier, "mlv_" <> String.duplicate("22", 32))
    {:ok, account} = Lookup.parse(:email, "emh_" <> String.duplicate("33", 32))
    {:ok, session} = SessionCookie.mint(session_ring, sid, "HU", @now, @now - 5)

    {:ok, confirm} =
      ConfirmCookie.mint(confirm_ring, {selector, verifier, account}, @expiry, @now, fn n ->
        {:ok, :binary.copy(<<0xCC>>, n)}
      end)

    fields = [session, ConfirmCookie.cookie_value(confirm), ConfirmCookie.confirmation(confirm)]
    File.write!(Path.join(dir, "elixir.tsv"), [Enum.intersperse(fields, "\t"), "\n"])

    {output, status} =
      System.cmd(
        "cargo",
        [
          "test",
          "--locked",
          "-p",
          "datadeft-magic-link-service",
          "--test",
          "elixir_cookie_parity",
          "--",
          "--ignored",
          "--exact",
          "elixir_cookie_parity"
        ],
        cd: Path.expand("../../../..", __DIR__),
        env: [{"DD_AUTH_COOKIE_FIXTURES", dir}],
        stderr_to_stdout: true
      )

    assert status == 0, output

    [session, confirm, nonce] =
      dir
      |> Path.join("rust.tsv")
      |> File.read!()
      |> String.trim_trailing("\n")
      |> String.split("\t")

    issued = @now - 5

    assert {:ok,
            %SessionCookie{
              session_id: ^sid,
              country: "HU",
              issued_at_unix: ^issued,
              last_activity_unix: @now
            }} = SessionCookie.open(session_ring, session, @now, {60, 60})

    assert {:ok, %ConfirmCookie{expires_at_unix: @expiry} = state} =
             ConfirmCookie.verify(confirm_ring, confirm, nonce, @now, 300)

    assert Lookup.matches?(state.selector, selector)
    assert Lookup.matches?(state.verifier, verifier)
    assert Lookup.matches?(state.account, account)
  end

  defp ring(purpose, kid, byte, lifetime) do
    {:ok, ring} =
      Keyring.new(purpose, [{:active, kid, :binary.copy(<<byte>>, 32), @now, @now + lifetime}])

    ring
  end
end
