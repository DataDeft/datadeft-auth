defmodule DatadeftAuthApiContractTest do
  use ExUnit.Case, async: false
  import DatadeftAuth.TestSupport
  alias DatadeftAuth.{Error, FlowState, Landing, Session, Validation}

  test "malformed API inputs fail locally without sending requests or restarting" do
    pid = start_supervised!({DatadeftAuth, [config: fake_config()]})
    ready(pid)
    before = :sys.get_state(pid)

    for {operation, args} <- [
          {:request_link, [nil]},
          {:request_link, ["user@example.test", :not_options]},
          {:request_link, ["user@example.test", [:not_a_keyword]]},
          {:request_link, ["user@example.test", [{:terms_accepted, true} | :invalid]]},
          {:request_link, ["user@example.test", [terms_accepted: true, terms_accepted: false]]},
          {:request_link, ["user@example.test", [unknown: true]]},
          {:request_link, ["user@example.test", [terms_accepted: "true"]]},
          {:request_link, ["user@example.test", [locale: false]]},
          {:landing, [nil]},
          {:landing, [<<255>>]},
          {:flow_state, [nil]},
          {:confirm, [nil, "confirmation"]},
          {:confirm, ["cookie", nil]},
          {:confirm, ["cookie", "confirmation", [:not_a_keyword]]},
          {:confirm, ["cookie", "confirmation", [country: false]]},
          {:validate_session, [nil]},
          {:validate_session, ["cookie", [country: "HU", country: "GB"]]},
          {:logout, [nil]},
          {:logout, ["cookie", [country: <<255>>]]},
          {:pow_verify, [nil]},
          {:pow_verify, [%{chg: <<255>>, sol: "x", non: "x", tim: "x", tag: "x"}]},
          {:pow_admit, [nil]},
          {:fake_last_magic_link, [nil]}
        ] do
      assert {:error, %Error{code: :bad_request}} = apply(DatadeftAuth, operation, [pid | args])
    end

    after_calls = :sys.get_state(pid)
    assert after_calls.port == before.port
    assert after_calls.next_id == before.next_id
    assert after_calls.ready
    assert {:ok, :transport_ready} = DatadeftAuth.status(pid)
  end

  test "result inspection redacts account identity and user identifiers" do
    account = "private-user@example.test"
    user_id = "usr-" <> String.duplicate("a", 32)

    for result <- [
          %Landing{usable: true, account: account},
          %FlowState{usable: true, account: account},
          %Session{session_cookie: "fixture-cookie", user_id: user_id, user_created: false},
          %Validation{valid: true, user_id: user_id}
        ] do
      refute inspect(result) =~ account
      refute inspect(result) =~ user_id
      refute inspect(result) =~ "fixture-cookie"
    end
  end

  test "trusted country binding is preserved by confirmation and validation" do
    config = fake_config()
    config = %{config | service: Map.put(config.service, :enforce_country, true)}
    pid = start_supervised!({DatadeftAuth, [config: config]})
    ready(pid)
    email = "country-user@example.test"

    {:ok, _} =
      DatadeftAuth.request_link(pid, email, terms_accepted: true, privacy_accepted: true)

    {:ok, %{magic_link_url: url}} = DatadeftAuth.fake_last_magic_link(pid, email)
    [_, token] = String.split(url, "?token=", parts: 2)
    {:ok, landing} = DatadeftAuth.landing(pid, token)

    {:ok, session} =
      DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation, country: "HU")

    assert session.country == "HU"

    assert {:ok, %Validation{valid: true}} =
             DatadeftAuth.validate_session(pid, session.session_cookie, country: "HU")

    assert {:ok, %Validation{valid: false}} =
             DatadeftAuth.validate_session(pid, session.session_cookie, country: "GB")

    assert {:ok, %Validation{valid: false}} =
             DatadeftAuth.validate_session(pid, session.session_cookie)
  end

  test "concurrent confirmation of one link yields exactly one session" do
    pid = start_supervised!({DatadeftAuth, [config: fake_config()]})
    ready(pid)
    email = "concurrent-user@example.test"

    assert {:ok, _} =
             DatadeftAuth.request_link(pid, email, terms_accepted: true, privacy_accepted: true)

    {:ok, %{magic_link_url: url}} = DatadeftAuth.fake_last_magic_link(pid, email)
    [_, token] = String.split(url, "?token=", parts: 2)
    {:ok, landing} = DatadeftAuth.landing(pid, token)

    results =
      1..2
      |> Task.async_stream(fn _ ->
        DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)
      end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, %Session{}}, &1)) == 1
    assert Enum.count(results, &match?({:error, %Error{code: :rejected}}, &1)) == 1
  end
end
