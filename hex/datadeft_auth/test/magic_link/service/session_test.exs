defmodule DatadeftAuth.MagicLink.Service.SessionTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Core.Email

  alias DatadeftAuth.MagicLink.Service.{
    CountryPolicy,
    Session,
    SessionCookie,
    SessionId,
    SessionRecord,
    UserId
  }

  alias DatadeftAuth.Token.Keyring

  @now 1000
  @ages {20, 100}
  @sid "sid-" <> String.duplicate("a", 64)
  @uid "usr-" <> String.duplicate("b", 32)

  defmodule Repository do
    @behaviour DatadeftAuth.MagicLink.Service.SessionRepository

    def find_session({owner, row, _}, id, now) do
      send(owner, {:find, id, now})
      row
    end

    def is_session_owner_active({owner, _, active}, id, created) do
      send(owner, {:active, id, created})
      active
    end

    def revoke_session({owner, _, _}, id, now) do
      send(owner, {:revoke, id, now})
      :ok
    end
  end

  test "validation reads one clock, is read-only, and requires a live active owner" do
    row = record()
    service = service({:ok, row}, {:ok, true})
    value = cookie(row.session_id, "HU", @now - 10, @now - 20)
    assert {:ok, validated} = Session.validate(service, value, "HU")
    assert Session.record(validated) == row
    assert_receive :clock
    assert_receive {:find, _, @now}
    assert_receive {:active, _, @now}
    refute_received :clock
    refute_received {:revoke, _, _}
    refute inspect(validated) =~ @sid

    assert Session.validate(service, value, nil) == {:error, :invalid_session}
    assert Session.validate(service, value, "AT") == {:error, :invalid_session}
    assert Session.validate(service, value, "EU") == {:error, :invalid_session}
    refute_received {:find, _, _}

    assert Session.validate(service({:ok, row}, {:ok, false}), value, "HU") ==
             {:error, :invalid_session}

    assert Session.validate(service({:ok, row}, {:error, :unavailable}), value, "HU") ==
             {:error, :unavailable}
  end

  test "checks absolute server creation, id and revocation even if the repository returns a row" do
    row = record()
    value = cookie(row.session_id, nil, @now, @now)
    {:ok, wrong_id} = SessionId.parse("sid-" <> String.duplicate("b", 64))

    for field <- [
          session_id: wrong_id,
          revoked_at_unix: @now,
          created_at_unix: @now + 61,
          created_at_unix: @now - 101,
          created_at_unix: nil
        ] do
      {name, data} = field

      assert Session.validate(service({:ok, Map.put(row, name, data)}, {:ok, true}), value, nil) ==
               {:error, :invalid_session}
    end

    assert Session.validate(service({:ok, nil}, {:ok, true}), value, nil) ==
             {:error, :invalid_session}

    assert Session.validate(service({:error, :unavailable}, {:ok, true}), value, nil) ==
             {:error, :unavailable}

    assert Session.validate(service({:error, :internal}, {:ok, true}), value, nil) ==
             {:error, :internal}
  end

  test "logout bypasses idle and country only and cannot feed refresh" do
    row = record()
    service = service({:ok, row}, {:ok, true}, CountryPolicy.eu27())
    old = cookie(row.session_id, "EU", @now - 21, @now - 60)
    assert Session.validate(service, old, "HU") == {:error, :invalid_session}
    assert {:ok, ^row} = Session.validate_for_logout(service, old)
    assert Session.refresh(service, row) == {:error, :invalid_session}
    assert :ok = Session.revoke(service, row.session_id)
    assert_receive {:revoke, _, @now}
    absolute_expired = cookie(row.session_id, "EU", @now - 21, @now - 101)
    assert Session.validate_for_logout(service, absolute_expired) == {:error, :invalid_session}
    active = cookie(row.session_id, "EU", @now, @now)
    assert {:ok, _} = Session.validate(service, active, "AT")
    assert {:error, :invalid_session} = Session.validate(service, active, "EU")
  end

  test "refresh is same-request only, preserves issue time, uses active key and never calls storage" do
    row = record()
    value = cookie(row.session_id, "HU", @now - 10, @now - 30)
    initial = service({:ok, row}, {:ok, true})
    assert {:ok, validated} = Session.validate(initial, value, "HU")
    assert_receive {:find, _, _}
    assert_receive {:active, _, _}

    {:ok, rotated} = Keyring.new(:session, [{:active, "next", key(), 2000, 2_594_000}])
    current = service({:ok, row}, {:ok, true}, :exact, @now + 1, rotated)
    assert {:ok, "v1.next." <> _ = refreshed} = Session.refresh(current, validated)
    assert {:ok, opened} = SessionCookie.open(rotated, refreshed, @now + 1, @ages)
    assert opened.session_id == row.session_id
    assert opened.issued_at_unix == @now - 30
    assert opened.last_activity_unix == @now + 1
    assert opened.country == "HU"
    refute_received {:find, _, _}
    refute_received {:active, _, _}
    refute_received {:revoke, _, _}

    assert Session.refresh(service({:ok, row}, {:ok, true}, :exact, @now + 61), validated) ==
             {:error, :invalid_session}

    assert Session.refresh(service({:ok, row}, {:ok, true}, :exact, @now - 1), validated) ==
             {:error, :invalid_session}

    for {activity, issue} <- [{@now - 9, @now - 30}, {@now - 10, @now - 100}] do
      assert {:ok, validated} =
               Session.validate(initial, cookie(row.session_id, nil, activity, issue), nil)

      assert {:ok, nil} = Session.refresh(initial, validated)
    end
  end

  defp record do
    {:ok, id} = SessionId.parse(@sid)
    {:ok, uid} = UserId.parse(@uid)
    {:ok, email} = Email.normalize("session@example.test")

    %SessionRecord{
      session_id: id,
      user_id: uid,
      email: email,
      created_at_unix: @now,
      revoked_at_unix: nil
    }
  end

  defp service(row, owner, policy \\ :exact, now \\ @now, keys \\ ring()) do
    caller = self()

    clock = fn ->
      send(caller, :clock)
      {:ok, now}
    end

    {:ok, service} = Session.new(keys, {Repository, {caller, row, owner}}, clock, @ages, policy)
    service
  end

  defp cookie(id, country, activity, issue) do
    {:ok, value} = SessionCookie.mint(ring(), id, country, activity, issue)
    value
  end

  defp ring do
    {:ok, ring} = Keyring.new(:session, [{:active, "current", key(), 2000, 2_594_000}])
    ring
  end

  defp key, do: :binary.copy(<<0x33>>, 32)
end
