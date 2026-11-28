defmodule DatadeftAuth.MagicLink.Service.FlowTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Core.{ConfirmCookie, Email, Lookup, LookupKey, Token}

  alias DatadeftAuth.MagicLink.Service.{
    Challenge,
    CountryPolicy,
    Flow,
    SessionCookie,
    User,
    UserId
  }

  alias DatadeftAuth.Token.Keyring

  @now 100

  defmodule Store do
    def check_rate_limit(pid, key, cap, window, now) do
      send(self(), {:limit, key, cap, window, now})
      Agent.get(pid, &Map.get(&1, :limit, {:ok, :allowed}))
    end

    def find_magic_link_for_authentication(pid, selector) do
      send(self(), {:find, selector})
      {:ok, Agent.get(pid, &Map.get(&1.rows, Lookup.storage_value(selector)))}
    end

    def find_user_for_authentication(pid, _email) do
      send(self(), :find_user)
      {:ok, Agent.get(pid, &Map.get(&1, :user))}
    end

    def commit_magic_link_authentication(pid, command) do
      send(self(), {:commit, command})

      Agent.get_and_update(pid, fn state ->
        case state.commits do
          [{result, changes} | rest] -> {result, Map.merge(%{state | commits: rest}, changes)}
          [] -> {:error, state}
        end
      end)
    end
  end

  test "landing and flow state do not commit, verify account binding and throttle on a miss" do
    {service, store, row, token, _ring} = setup_flow()
    raw_token = Token.value(token)
    selector_key = Lookup.storage_value(row.selector_lookup_hmac)
    rate_key = "magic-link:landing:selector:" <> selector_key
    assert {:ok, landing} = Flow.land(service, raw_token)
    assert landing.account == "a•••••@example.test"
    assert landing.cookie_max_age_secs == 30
    assert_received {:limit, ^rate_key, 30, 600, @now}
    assert_received {:find, _}
    value = ConfirmCookie.cookie_value(landing.flow)
    nonce = ConfirmCookie.confirmation(landing.flow)
    refute inspect(landing) =~ landing.account
    assert {:ok, state} = Flow.read_state(service, value)
    assert state.account == landing.account
    assert state.confirmation == nonce
    refute inspect(state) =~ nonce
    refute_received {:commit, _}
    refute_received :find_user

    {:ok, other_address} = Email.normalize("bob@example.test")
    Agent.update(store, &put_in(&1, [:rows, selector_key, Access.key!(:email)], other_address))
    assert Flow.read_state(service, value) == {:error, :magic_link_unavailable}
    assert Flow.confirm(service, value, nonce, nil) == {:error, :magic_link_unavailable}
    refute_received :find_user
    refute_received {:commit, _}
    Agent.update(store, &%{&1 | rows: %{}})
    assert Flow.land(service, raw_token) == {:error, :magic_link_unavailable}
    assert_received {:limit, ^rate_key, 30, 600, @now}
  end

  test "old-key landing only on current-key miss; valid nonce required before consume and commit" do
    {service, store, old_row, token, keys} = setup_flow(previous: true, enforce_country: true)
    assert {:ok, landing} = Flow.land(service, Token.value(token))
    assert_receive {:find, current_selector}
    assert_receive {:find, old_selector}
    assert Lookup.matches?(old_selector, old_row.selector_lookup_hmac)
    refute Lookup.matches?(current_selector, old_selector)
    assert_received {:limit, _, 30, 600, @now}
    cookie = ConfirmCookie.cookie_value(landing.flow)
    nonce = ConfirmCookie.confirmation(landing.flow)

    assert Flow.confirm(service, cookie, String.duplicate("0", 64), "HU") ==
             {:error, :magic_link_unavailable}

    assert Flow.confirm(service, cookie, nonce, "EU") == {:error, :magic_link_unavailable}
    assert Flow.confirm(service, cookie, nonce, "hu") == {:error, :bad_request}
    refute_received {:limit, _, 5, 600, @now}
    refute_received {:commit, _}

    Agent.update(store, &%{&1 | commits: [{:ok, %{}}]})
    assert {:ok, outcome} = Flow.confirm(service, cookie, nonce, "HU")
    assert outcome.user_created
    assert outcome.country == "EU"
    old_bucket = "magic-link:consume:selector:" <> Lookup.storage_value(old_selector)
    assert_received {:limit, ^old_bucket, 5, 600, @now}
    assert_received {:commit, command}
    assert command.user == {:create, outcome.user_id}
    assert command.session_id == outcome.session_id
    assert command.session_expires_at_unix == @now + 2_592_000

    assert {:ok, opened} =
             SessionCookie.open(keys, outcome.session_cookie, @now, {86_400, 2_592_000})

    assert opened.session_id == outcome.session_id
    assert opened.country == "EU"
    refute inspect(outcome) =~ outcome.session_cookie

    bad = %{old_row | selector_lookup_hmac: current_selector, consumed_at_unix: @now}
    Agent.update(store, &put_in(&1, [:rows, Lookup.storage_value(current_selector)], bad))
    flush_finds()
    assert Flow.land(service, Token.value(token)) == {:error, :magic_link_unavailable}
    assert_receive {:find, ^current_selector}
    refute_received {:find, _}
  end

  test "ambiguous writes replay identical command; confirmed user/session conflicts replan only affected fields" do
    {service, store, row, token, _keys} = setup_flow()
    {:ok, uid} = UserId.parse("usr-" <> String.duplicate("1", 32))

    user = %User{
      user_id: uid,
      email: row.email,
      disabled: false,
      terms_version: row.terms_version,
      privacy_version: row.privacy_version,
      consented_at_unix: 10
    }

    assert {:ok, landing} = Flow.land(service, Token.value(token))
    cookie = ConfirmCookie.cookie_value(landing.flow)
    nonce = ConfirmCookie.confirmation(landing.flow)

    commits = [
      {{:error, :unavailable}, %{}},
      {{:error, :user_conflict}, %{user: user}},
      {{:error, :session_conflict}, %{}},
      {:ok, %{}}
    ]

    Agent.update(store, &%{&1 | commits: commits})
    assert {:ok, result} = Flow.confirm(service, cookie, nonce, nil)
    assert result.user_id == uid
    refute result.user_created
    assert_received {:commit, first}
    assert_received {:commit, ^first}
    assert_received {:commit, converged}
    assert_received {:commit, final}
    assert converged.user == {:existing, uid}
    assert converged.session_id == first.session_id
    assert first.attempt_id != converged.attempt_id
    assert final.attempt_id != converged.attempt_id
    assert final.session_id != converged.session_id
    assert final.magic_link == first.magic_link
    assert final.session_id == result.session_id
    refute_received {:commit, _}
    assert Flow.temporary_state_action(:unavailable) == :preserve
    assert Flow.temporary_state_action(:magic_link_unavailable) == :clear
  end

  test "expired, consumed, stale or unrecorded consent and limiter errors fail without writes" do
    {service, store, row, token, _ring} = setup_flow()
    key = Lookup.storage_value(row.selector_lookup_hmac)
    assert {:ok, landing} = Flow.land(service, Token.value(token))
    cookie = ConfirmCookie.cookie_value(landing.flow)
    nonce = ConfirmCookie.confirmation(landing.flow)

    for changes <- [
          %{expires_at_unix: @now},
          %{consumed_at_unix: @now},
          %{terms_version: "old"},
          %{privacy_version: "old"},
          %{consented_at_unix: 0}
        ] do
      Agent.update(store, &put_in(&1, [:rows, key], struct!(row, changes)))
      assert Flow.land(service, Token.value(token)) == {:error, :magic_link_unavailable}
      assert Flow.read_state(service, cookie) == {:error, :magic_link_unavailable}
      assert Flow.confirm(service, cookie, nonce, nil) == {:error, :magic_link_unavailable}
    end

    Agent.update(store, &Map.put(&1, :limit, {:error, :unavailable}))
    assert Flow.land(service, Token.value(token)) == {:error, :unavailable}
    refute_received {:commit, _}
  end

  defp setup_flow(opts \\ []) do
    {:ok, current} = LookupKey.new(:binary.copy(<<0x25>>, 32))
    {:ok, old} = LookupKey.new(:binary.copy(<<0x33>>, 32))
    previous = if opts[:previous], do: old, else: nil
    {:ok, token} = Token.generate(fn n -> {:ok, :binary.copy(<<n>>, n)} end)
    {:ok, selector} = Lookup.selector(previous || current, token)
    {:ok, verifier} = Lookup.verifier(previous || current, token)
    {:ok, email} = Email.normalize("alice@example.test")

    row = %Challenge{
      email: email,
      selector_lookup_hmac: selector,
      verifier_hash: verifier,
      consented_at_unix: 10,
      expires_at_unix: @now + 30,
      terms_version: "t",
      privacy_version: "p"
    }

    {:ok, store} =
      Agent.start_link(fn -> %{rows: %{Lookup.storage_value(selector) => row}, commits: []} end)

    {:ok, confirm} =
      Keyring.new(:confirm, [{:active, "conf", :binary.copy(<<0x53>>, 32), 200, 500}])

    {:ok, session} =
      Keyring.new(:session, [{:active, "sess", :binary.copy(<<0x77>>, 32), 200, 2_592_200}])

    io = %{repository: {Store, store}, limiter: {Store, store}, clock: fn -> {:ok, @now} end}

    assert {:ok, service} =
             Flow.new(current, {confirm, session}, {"t", "p"}, io,
               previous_lookup_key: previous,
               country_policy: CountryPolicy.eu27(),
               enforce_country: opts[:enforce_country] || false
             )

    {service, store, row, token, session}
  end

  defp flush_finds do
    receive do
      {:find, _} -> flush_finds()
    after
      0 -> :ok
    end
  end
end
