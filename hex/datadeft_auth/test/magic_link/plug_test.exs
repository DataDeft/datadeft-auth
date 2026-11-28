defmodule DatadeftAuth.MagicLink.PlugTest do
  use ExUnit.Case, async: true
  import Plug.Conn
  import Plug.Test, only: [conn: 2, conn: 3]
  alias DatadeftAuth.MagicLink.Core.{Email, LookupKey, Token}
  alias DatadeftAuth.MagicLink.Plug, as: Web
  alias DatadeftAuth.MagicLink.Service.{Flow, Request, Session, SessionRecord, UserId}
  alias DatadeftAuth.Token.Keyring

  @origin "https://login.example.test"
  @request_body ~s({"email":"alice@example.test","terms_accepted":true,"privacy_accepted":true})
  @unavailable ~s({"error":"unavailable","message":"The service is temporarily unavailable. Try again later."})
  @bad_request ~s({"error":"bad_request","message":"Invalid request."})

  defmodule Store do
    alias DatadeftAuth.MagicLink.Core.Lookup
    alias DatadeftAuth.MagicLink.Service.SessionRecord

    def check_rate_limit(pid, _, _, _, _), do: Agent.get(pid, & &1.limit)

    def enqueue_magic_link(pid, mail) do
      owner = Agent.get(pid, & &1.owner)
      send(owner, {:mail, mail})
      :ok
    end

    def put_magic_link_if_absent(pid, row) do
      Agent.update(pid, &%{&1 | row: row})
    end

    def find_magic_link_for_authentication(pid, selector) do
      Agent.get(pid, fn state ->
        if state.row && Lookup.matches?(state.row.selector_lookup_hmac, selector),
          do: {:ok, state.row},
          else: {:ok, nil}
      end)
    end

    def find_user_for_authentication(_, _), do: {:ok, nil}

    def commit_magic_link_authentication(pid, command) do
      Agent.get_and_update(pid, fn state ->
        case state.row.consumed_at_unix do
          nil ->
            {_, user} = command.user

            session = %SessionRecord{
              session_id: command.session_id,
              user_id: user,
              email: state.row.email,
              created_at_unix: command.now_unix,
              revoked_at_unix: nil
            }

            {:ok,
             %{state | row: %{state.row | consumed_at_unix: command.now_unix}, session: session}}

          _ ->
            {{:error, :rejected}, state}
        end
      end)
    end

    def find_session(pid, id, _) do
      Agent.get(pid, fn state ->
        case state.session do
          %SessionRecord{session_id: ^id, revoked_at_unix: nil} = record -> {:ok, record}
          _ -> {:ok, nil}
        end
      end)
    end

    def is_session_owner_active(_, _, _), do: {:ok, true}

    def revoke_session(pid, id, now) do
      Agent.get_and_update(pid, fn state ->
        case state.session do
          %SessionRecord{session_id: ^id} = record when state.revoke == :ok ->
            {:ok, %{state | session: %{record | revoked_at_unix: now}}}

          _ ->
            {{:error, :unavailable}, state}
        end
      end)
    end
  end

  setup do
    owner = self()

    {:ok, store} =
      Agent.start_link(fn ->
        %{owner: owner, limit: {:ok, :allowed}, row: nil, session: nil, revoke: :ok}
      end)

    db = {Store, store}
    clock = fn -> {:ok, 1_000} end
    io = %{repository: db, outbox: db, limiter: db, clock: clock}
    {:ok, lookup} = LookupKey.new(:binary.copy(<<33>>, 32))

    {:ok, confirm} =
      Keyring.new(:confirm, [{:active, "flow", :binary.copy(<<44>>, 32), 2_000, 2_300}])

    {:ok, session} =
      Keyring.new(:session, [{:active, "session", :binary.copy(<<55>>, 32), 2_000, 2_594_000}])

    {:ok, request} = Request.new(lookup, {"terms", "privacy"}, io)
    {:ok, flow} = Flow.new(lookup, {confirm, session}, {"terms", "privacy"}, io)
    {:ok, sessions} = Session.new(session, db, clock)

    {:ok, web} =
      Web.new(@origin, request, flow, sessions, country_header: "cloudfront-viewer-country")

    %{web: web, store: store, services: [request, flow, sessions]}
  end

  test "bounds and strictly decodes request JSON; shared fixed public bodies", %{
    web: web,
    store: store
  } do
    for {type, body} <- [
          {"text/plain", @request_body},
          {"application/json", "{}"},
          {"application/json", String.duplicate(" ", 4100) <> @request_body},
          {"application/json",
           ~s({"email":"other@example.test",) <>
             binary_part(@request_body, 1, byte_size(@request_body) - 1)},
          {"application/json", String.replace_suffix(@request_body, "}", ~s(,"extra":true}))}
        ] do
      response =
        conn(:post, "/auth/magic-link/request", body)
        |> put_req_header("content-type", type)
        |> Web.request(web)

      assert response.status == 400
      assert response.resp_body == @bad_request
    end

    for headers <- [
          [{"content-type", "application/json"}],
          [{"content-length", "9000"}],
          [{"content-length", "0"}, {"content-length", "1"}]
        ] do
      invalid = json(:post, "/auth/magic-link/request", @request_body)

      assert Web.request(%{invalid | req_headers: invalid.req_headers ++ headers}, web).status ==
               400
    end

    refute_received {:mail, _}
    assert Agent.get(store, & &1.row) == nil

    first = send_request(web)
    assert_receive {:mail, _}
    Agent.update(store, &%{&1 | limit: {:ok, :denied}})
    denied = send_request(web)
    assert {first.status, first.resp_body} == {denied.status, denied.resp_body}
    assert first.resp_body == ~s({"status":"ok"})
    refute_received {:mail, _}

    Agent.update(store, &%{&1 | limit: {:error, :unavailable}})
    failed = send_request(web)
    assert failed.status == 503
    assert failed.resp_body == @unavailable
    assert get_resp_header(failed, "cache-control") == ["no-store"]
    assert is_binary(failed.private.datadeft_auth_reason)
    refute failed.resp_body =~ failed.private.datadeft_auth_reason
  end

  test "open is scanner-safe and non-reflective; flow state checks fetch site and duplicate cookies",
       %{web: web, store: store} do
    {open, token, cookie} = open_flow(web)
    assert open.status == 303
    assert get_resp_header(open, "location") == ["/auth/magic-link/confirm"]
    assert [set] = get_resp_header(open, "set-cookie")
    assert set == cookie <> "; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=300"
    assert get_resp_header(open, "referrer-policy") == ["strict-origin"]
    assert get_resp_header(open, "x-frame-options") == ["DENY"]
    assert [csp] = get_resp_header(open, "content-security-policy")
    assert csp =~ "frame-ancestors 'none'"

    refute Enum.any?(open.resp_headers, fn {key, value} ->
             key != "set-cookie" && String.contains?(value, token)
           end)

    for query <- [
          "missing=1",
          "token=" <> token <> "&token=" <> token,
          "token=%61",
          "token=" <> String.duplicate("a", 768)
        ] do
      invalid = Web.open(conn(:get, "/auth/magic-link/open?" <> query), web)
      assert invalid.status == open.status
      assert get_resp_header(invalid, "location") == get_resp_header(open, "location")
      assert get_resp_header(invalid, "set-cookie") == []
    end

    for site <- [nil, "cross-site", "same-site"] do
      refused = get_state(web, cookie, site)
      assert refused.resp_body == ~s({"usable":false})
      assert get_resp_header(refused, "set-cookie") == []
    end

    duplicate = get_state(web, cookie <> "; " <> cookie)
    assert duplicate.resp_body == ~s({"usable":false})
    assert [clear] = get_resp_header(duplicate, "set-cookie")
    assert clear =~ "Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires="

    for fields <- [
          [cookie, cookie],
          ["dd_auth_confirm=\"quoted\""],
          ["dd_auth_confirm=" <> String.duplicate("a", 4097)],
          [cookie, String.duplicate("x", 8192)],
          [cookie | List.duplicate("ignored=1", 128)]
        ] do
      request = conn(:get, "/auth/magic-link/flow-state")
      headers = [{"sec-fetch-site", "same-origin"} | Enum.map(fields, &{"cookie", &1})]
      refused = Web.flow_state(%{request | req_headers: headers}, web)
      assert refused.resp_body == ~s({"usable":false})
    end

    for value <- [cookie, "unrelated=raw comma, hello; invalid; " <> cookie] do
      usable = get_state(web, value)

      assert {:ok,
              %{"usable" => true, "account" => "a•••••@example.test", "confirmation" => nonce}} =
               Jason.decode(usable.resp_body)

      assert byte_size(nonce) == 64
      assert get_resp_header(usable, "cross-origin-resource-policy") == ["same-origin"]
      assert get_resp_header(usable, "access-control-allow-origin") == []
    end

    assert Agent.get(store, & &1.row.consumed_at_unix) == nil
    assert Agent.get(store, & &1.session) == nil
  end

  test "server-rendered landing receives account plus nonce, while rejected GETs change no cookies",
       %{
         web: web,
         store: store
       } do
    {_, token, _} = open_flow(web)

    render = fn account, nonce ->
      assert account == "a•••••@example.test"
      assert byte_size(nonce) == 64
      "<!doctype html><h1>Sign in</h1>"
    end

    landing = Web.landing(conn(:get, "/auth/magic-link/landing?token=" <> token), web, render)
    assert landing.status == 200
    assert get_resp_header(landing, "cache-control") == ["no-store"]
    assert [_] = get_resp_header(landing, "set-cookie")
    assert Agent.get(store, & &1.row.consumed_at_unix) == nil

    rejected = Web.landing(conn(:get, "/auth/magic-link/landing?token=bad"), web, render)
    assert rejected.status == 200
    assert get_resp_header(rejected, "set-cookie") == []
  end

  test "confirm uses one origin and one nonce; protected pages and logout use live storage", %{
    web: web,
    store: store
  } do
    {_, _, cookie} = open_flow(web)
    %{"confirmation" => nonce} = Jason.decode!(get_state(web, cookie).resp_body)

    base =
      conn(:post, "/auth/magic-link/consume", "confirmation=" <> nonce)
      |> put_req_header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
      |> put_req_header("cookie", cookie)

    for extras <- [
          [],
          [{"origin", "null"}],
          [{"origin", "https://foreign.example.test"}],
          [{"origin", @origin}, {"origin", @origin}],
          [{"origin", @origin}, {"sec-fetch-site", "same-site"}]
        ] do
      rejected = Web.confirm(%{base | req_headers: base.req_headers ++ extras}, web)
      assert rejected.status == 400
      assert Agent.get(store, & &1.row.consumed_at_unix) == nil
    end

    assert Web.confirm(%{base | method: "GET"}, web).status == 400

    for body <- [
          ~s({"confirmation":"#{nonce}","country":"HU"}),
          ~s({"confirmation":"#{nonce}","confirmation":"#{nonce}"})
        ] do
      invalid =
        json(:post, "/auth/magic-link/consume", body)
        |> put_req_header("cookie", cookie)
        |> put_req_header("origin", @origin)
        |> Web.confirm(web)

      assert invalid.status == 400
      assert ["dd_auth_confirm=" <> _] = get_resp_header(invalid, "set-cookie")
    end

    assert Agent.get(store, & &1.row.consumed_at_unix) == nil

    base =
      base
      |> put_req_header("origin", @origin)
      |> put_req_header("sec-fetch-site", "same-origin")
      |> put_req_header("cloudfront-viewer-country", "HU")

    Agent.update(store, &%{&1 | limit: {:error, :unavailable}})
    retry_later = Web.confirm(base, web)
    assert retry_later.status == 503 and retry_later.resp_body == @unavailable
    assert get_resp_header(retry_later, "set-cookie") == []
    Agent.update(store, &%{&1 | limit: {:ok, :allowed}})
    signed_in = Web.confirm(base, web)
    assert signed_in.status == 303
    assert get_resp_header(signed_in, "location") == ["/auth/magic-link/complete"]
    assert Agent.get(store, & &1.row.consumed_at_unix) == 1_000

    assert signed_in
           |> get_resp_header("set-cookie")
           |> Enum.find(&String.starts_with?(&1, "dd_auth_confirm=")) =~ "Max-Age=0"

    session_header =
      signed_in
      |> get_resp_header("set-cookie")
      |> Enum.find(&String.starts_with?(&1, "dd_session="))

    [session_cookie, attrs] = String.split(session_header, ";", parts: 2)
    assert attrs == " Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
    assert Web.confirm(base, web).status == 400

    me = conn(:get, "/me") |> put_req_header("cookie", session_cookie)
    assert {:error, no_country} = Web.authenticate(me, web)
    assert no_country.status == 401
    assert get_resp_header(no_country, "www-authenticate") == ["DD-Session"]
    assert ["dd_session=" <> _] = get_resp_header(no_country, "set-cookie")

    assert {:ok, protected, %SessionRecord{user_id: %UserId{}, email: %Email{}}} =
             Web.authenticate(put_req_header(me, "cloudfront-viewer-country", "HU"), web)

    assert get_resp_header(protected, "cache-control") == ["no-store"]

    logout = conn(:post, "/auth/logout") |> put_req_header("cookie", session_cookie)
    assert Web.logout(logout, web).status == 400
    logout = put_req_header(logout, "origin", @origin)
    Agent.update(store, &%{&1 | revoke: :fail})
    failed = Web.logout(logout, web)
    assert failed.status == 503 and failed.resp_body == @unavailable
    assert get_resp_header(failed, "set-cookie") == []
    assert Agent.get(store, & &1.session.revoked_at_unix) == nil
    Agent.update(store, &%{&1 | revoke: :ok})
    ended = Web.logout(logout, web)
    assert ended.status == 303
    assert Agent.get(store, & &1.session.revoked_at_unix) == 1_000

    assert ["dd_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=" <> _] =
             get_resp_header(ended, "set-cookie")

    assert {:error, replay} =
             Web.authenticate(put_req_header(me, "cloudfront-viewer-country", "HU"), web)

    assert replay.status == 401
  end

  test "insecure cookies require explicit loopback configuration", %{
    services: [request, flow, sessions]
  } do
    for origin <- [
          "null",
          "https://login.example.test/",
          "https://LOGIN.example.test",
          "https://login.example.test:443",
          "http://example.test"
        ] do
      assert {:error, :invalid_config} = Web.new(origin, request, flow, sessions)
    end

    for path <- [
          "https://external.test/",
          "//external.test/",
          "/../escape",
          "/a?token=ignored",
          "/a%2Fb"
        ] do
      assert {:error, :invalid_config} =
               Web.new(@origin, request, flow, sessions, after_sign_in: path)
    end

    assert {:error, :invalid_config} = Web.new("http://127.0.0.1:4000", request, flow, sessions)

    assert {:error, :invalid_config} =
             Web.new("http://example.test", request, flow, sessions, insecure_local: true)

    assert {:ok, local} =
             Web.new("http://127.0.0.1:4000", request, flow, sessions, insecure_local: true)

    {open, _, _} = open_flow(local)
    assert [header] = get_resp_header(open, "set-cookie")
    refute header =~ "; Secure"
  end

  defp json(method, path, body),
    do: conn(method, path, body) |> put_req_header("content-type", "application/json")

  defp send_request(web),
    do: json(:post, "/auth/magic-link/request", @request_body) |> Web.request(web)

  defp open_flow(web) do
    assert send_request(web).status == 200
    assert_receive {:mail, mail}
    token = Token.value(mail.token)
    open = conn(:get, "/auth/magic-link/open?token=" <> token) |> Web.open(web)
    assert [header] = get_resp_header(open, "set-cookie")
    [cookie | _] = String.split(header, ";", parts: 2)
    {open, token, cookie}
  end

  defp get_state(web, cookie, site \\ "same-origin") do
    request = conn(:get, "/auth/magic-link/flow-state") |> put_req_header("cookie", cookie)
    request = if site, do: put_req_header(request, "sec-fetch-site", site), else: request
    Web.flow_state(request, web)
  end
end
