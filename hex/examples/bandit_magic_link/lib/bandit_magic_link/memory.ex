defmodule BanditMagicLink.Memory do
  @moduledoc false
  alias DatadeftAuth.MagicLink.Core.Lookup
  alias DatadeftAuth.MagicLink.Service.{SessionRecord, User}

  # Demo-only, single-node repository. All mutations are serialized; there is
  # no persistence, TTL sweeping, key rotation, or production admin support.
  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}}
  end

  def start_link do
    Agent.start_link(fn -> %{challenges: %{}, users: %{}, sessions: %{}, rate: %{}} end,
      name: __MODULE__
    )
  end

  def check_rate_limit(agent, key, limit, seconds, now) do
    bucket = {key, div(now, seconds)}

    Agent.get_and_update(agent, fn state ->
      count = Map.get(state.rate, bucket, 0)

      if count < limit,
        do: {{:ok, :allowed}, put_in(state.rate[bucket], count + 1)},
        else: {{:ok, :denied}, state}
    end)
  end

  def put_magic_link_if_absent(agent, row) do
    key = Lookup.storage_value(row.selector_lookup_hmac)

    Agent.get_and_update(agent, fn state ->
      if Map.has_key?(state.challenges, key),
        do: {{:error, :conditional_write_failed}, state},
        else: {:ok, put_in(state.challenges[key], row)}
    end)
  end

  def find_magic_link_for_authentication(agent, selector) do
    key = Lookup.storage_value(selector)
    Agent.get(agent, &{:ok, Map.get(&1.challenges, key)})
  end

  def find_user_for_authentication(agent, address),
    do: Agent.get(agent, &{:ok, Map.get(&1.users, address)})

  def commit_magic_link_authentication(agent, command) do
    Agent.get_and_update(agent, fn state ->
      expected = command.magic_link
      key = Lookup.storage_value(expected.selector_lookup_hmac)

      with :ok <- challenge_matches(Map.get(state.challenges, key), expected, command.now_unix),
           {:ok, user} <- user_for_commit(Map.get(state.users, expected.email), command),
           false <- Map.has_key?(state.sessions, command.session_id) do
        session = %SessionRecord{
          session_id: command.session_id,
          user_id: user.user_id,
          email: user.email,
          created_at_unix: command.now_unix,
          revoked_at_unix: nil
        }

        state =
          state
          |> put_in([:challenges, key, Access.key(:consumed_at_unix)], command.now_unix)
          |> put_in([:users, user.email], user)
          |> put_in([:sessions, session.session_id], {command.session_expires_at_unix, session})

        {:ok, state}
      else
        true -> {{:error, :session_conflict}, state}
        {:error, reason} -> {{:error, reason}, state}
      end
    end)
  end

  defp challenge_matches(row, expected, now) do
    if row && is_nil(row.consumed_at_unix) && row.expires_at_unix > now &&
         row.expires_at_unix == expected.expires_at_unix && row.email == expected.email &&
         row.consented_at_unix == expected.consented_at_unix &&
         row.terms_version == expected.terms_version &&
         row.privacy_version == expected.privacy_version,
       do: :ok,
       else: {:error, :rejected}
  end

  defp user_for_commit(nil, %{user: {:create, id}, magic_link: expected}) do
    {:ok,
     %User{
       user_id: id,
       email: expected.email,
       disabled: false,
       terms_version: expected.terms_version,
       privacy_version: expected.privacy_version,
       consented_at_unix: expected.consented_at_unix
     }}
  end

  defp user_for_commit(%User{user_id: id, disabled: false} = user, %{user: {:existing, id}}),
    do: {:ok, user}

  defp user_for_commit(_, _), do: {:error, :user_conflict}

  def find_session(agent, id, now) do
    Agent.get(agent, fn state ->
      case Map.get(state.sessions, id) do
        {expiry, %SessionRecord{revoked_at_unix: nil} = session} when expiry >= now ->
          {:ok, session}

        _ ->
          {:ok, nil}
      end
    end)
  end

  def is_session_owner_active(agent, id, _created) do
    Agent.get(agent, fn state ->
      active =
        Enum.any?(state.users, fn {_, user} -> user.user_id == id and not user.disabled end)

      {:ok, active}
    end)
  end

  def revoke_session(agent, id, now) do
    Agent.get_and_update(agent, fn state ->
      case Map.get(state.sessions, id) do
        {expiry, %SessionRecord{revoked_at_unix: nil} = session} ->
          {:ok, put_in(state.sessions[id], {expiry, %{session | revoked_at_unix: now}})}

        _ ->
          {{:error, :conditional_write_failed}, state}
      end
    end)
  end
end
