defmodule DatadeftAuthFlowTest do
  use ExUnit.Case, async: false
  import DatadeftAuth.TestSupport
  alias DatadeftAuth.{DevMagicLink, Error, FlowState, Landing, Session, Validation}

  @email "flow-user@example.test"
  @consent [terms_accepted: true, privacy_accepted: true]

  defp start_configured do
    pid = start_supervised!({DatadeftAuth, [config: fake_config()]})
    ready(pid)
    pid
  end

  defp token_from(url) do
    [_, token] = String.split(url, "?token=", parts: 2)
    token
  end

  test "the full magic-link flow signs in, validates and logs out" do
    pid = start_configured()

    assert {:ok, "magic_link_request_sent"} = DatadeftAuth.request_link(pid, @email, @consent)

    assert {:ok, %DevMagicLink{found: true, magic_link_url: url, expires_at_unix: expires}} =
             DatadeftAuth.fake_last_magic_link(pid, @email)

    assert expires > System.os_time(:second)

    assert {:ok, %Landing{usable: true} = landing} =
             DatadeftAuth.landing(pid, token_from(url))

    assert landing.account =~ "@example.test"
    refute landing.account == @email

    # The landing GET is repeatable and never consumes; the flow-state read
    # mirrors it for redirect-landing pages.
    assert {:ok, %FlowState{usable: true, confirmation: confirmation}} =
             DatadeftAuth.flow_state(pid, landing.confirm_cookie)

    assert confirmation == landing.confirmation

    assert {:ok, %Session{session_cookie: cookie, user_created: true}} =
             DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)

    assert {:ok, %Validation{valid: true, user_id: user_id}} =
             DatadeftAuth.validate_session(pid, cookie)

    assert String.starts_with?(user_id, "usr-")

    assert {:ok, %{revoked: true}} = DatadeftAuth.logout(pid, cookie)
    assert {:ok, %Validation{valid: false}} = DatadeftAuth.validate_session(pid, cookie)
    assert {:ok, %{revoked: false}} = DatadeftAuth.logout(pid, cookie)
  end

  test "consumption is one-time and unusable states stay uniform" do
    pid = start_configured()

    assert {:ok, _} = DatadeftAuth.request_link(pid, @email, @consent)
    {:ok, %DevMagicLink{magic_link_url: url}} = DatadeftAuth.fake_last_magic_link(pid, @email)
    {:ok, %Landing{} = landing} = DatadeftAuth.landing(pid, token_from(url))

    assert {:ok, %Session{}} =
             DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)

    # A second confirmation of the consumed link is rejected generically, and
    # the spent token lands as unusable, exactly like a forged one.
    assert {:error, %Error{code: :rejected}} =
             DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)

    assert {:ok, %Landing{usable: false, confirm_cookie: nil}} =
             DatadeftAuth.landing(pid, token_from(url))

    assert {:ok, %Landing{usable: false}} = DatadeftAuth.landing(pid, "mlv1.forged.token")
    assert {:ok, %FlowState{usable: false}} = DatadeftAuth.flow_state(pid, "junk")
  end

  test "input shape failures and missing consent are typed errors" do
    pid = start_configured()

    assert {:error, %Error{code: :bad_request}} =
             DatadeftAuth.request_link(pid, "not an email", @consent)

    assert {:error, %Error{code: :bad_request}} = DatadeftAuth.request_link(pid, @email)

    assert {:error, %Error{code: :bad_request}} =
             DatadeftAuth.confirm(pid, "cookie", "confirmation", country: "hungary")
  end

  test "per-email request throttling keeps the generic reason labels internal" do
    pid = start_configured()

    reasons =
      for _ <- 1..4 do
        {:ok, reason} = DatadeftAuth.request_link(pid, @email, @consent)
        reason
      end

    assert "magic_link_request_sent" in reasons
    assert "magic_link_request_throttled_email_short_window" in reasons
  end

  test "auth calls without a config fail closed as configuration" do
    pid = start_supervised!({DatadeftAuth, []})
    ready(pid)

    assert {:error, %Error{code: :configuration}} =
             DatadeftAuth.request_link(pid, @email, @consent)

    assert {:ok, :transport_ready} = DatadeftAuth.status(pid)
  end

  test "a refused configuration keeps the owner alive and unready" do
    # AWS mode without its aws section is a configuration error.
    config = %{fake_config() | mode: :aws}
    pid = start_supervised!({DatadeftAuth, [config: config, restart_delay: 5000]})

    Process.sleep(300)
    assert Process.alive?(pid)
    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
  end

  test "oversized payloads are refused locally without consuming an ID" do
    pid = start_configured()
    huge = String.duplicate("a", DatadeftAuth.Protocol.max_frame())

    assert {:error, %Error{code: :bad_request}} = DatadeftAuth.landing(pid, huge)
    assert {:ok, :transport_ready} = DatadeftAuth.status(pid)
  end

  test "secret material is redacted in inspected results" do
    pid = start_configured()

    assert {:ok, _} = DatadeftAuth.request_link(pid, @email, @consent)

    {:ok, %DevMagicLink{magic_link_url: url} = dev} =
      DatadeftAuth.fake_last_magic_link(pid, @email)

    refute inspect(dev) =~ token_from(url)

    {:ok, %Landing{} = landing} = DatadeftAuth.landing(pid, token_from(url))
    refute inspect(landing) =~ landing.confirm_cookie
    refute inspect(landing) =~ landing.confirmation

    {:ok, %Session{} = session} =
      DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)

    refute inspect(session) =~ session.session_cookie
  end

  test "the config template is validated at the boundary" do
    for config <- [
          %{mode: :production},
          %{fake_config() | email: "not a map"} |> Map.put(:huge, String.duplicate("a", 20_000)),
          :not_a_map
        ] do
      assert {:error, %Error{code: :configuration}} =
               DatadeftAuth.start_link(config: config)
    end

    # Content errors surface from the executable, not the Elixir side: an
    # email template without the URL marker is refused at init.
    config = %{
      fake_config()
      | email: %{link_base_url: "https://x.test/?t=", subject: "s", text: "no marker"}
    }

    pid = start_supervised!({DatadeftAuth, [config: config, restart_delay: 5000]})
    Process.sleep(300)
    assert Process.alive?(pid)
    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
  end
end
