defmodule DatadeftAuth.AWS.DynamoDB.Users do
  @moduledoc false

  alias DatadeftAuth.AWS.DynamoDB.Items
  alias DatadeftAuth.AWS.DynamoDB.Keys
  alias DatadeftAuth.AWS.DynamoDB.Rotation
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.User
  alias DatadeftAuth.MagicLink.Service.UserId

  def find(store, email) do
    with {:ok, lookup, migrate?} <-
           Rotation.get_with_fallback(store, &Keys.user_email(&1, email)) do
      case lookup do
        nil -> {:ok, nil}
        item -> read_and_migrate(store, email, item, migrate?)
      end
    else
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  defp read_and_migrate(store, email, lookup, migrate?) do
    with {:ok, user} <- read_profile(store, email, lookup),
         {:ok, _} <- maybe_migrate(store, email, user.user_id, migrate?) do
      {:ok, user}
    end
  end

  defp maybe_migrate(store, email, id, true), do: Rotation.put_lookup(store, email, id)
  defp maybe_migrate(_, _, _, false), do: {:ok, false}

  defp read_profile(store, email, lookup) do
    with {:ok, "user_email_lookup"} <- Items.required_string(lookup, "entity_type"),
         {:ok, stored_email} <- Items.required_string(lookup, "email_normalized"),
         {:ok, ^email} <- Email.from_normalized(stored_email),
         {:ok, id} <- Items.required_string(lookup, "user_id"),
         {:ok, id} <- UserId.parse(id),
         {:ok, profile} when is_map(profile) <- Rotation.get(store, Keys.profile(id)),
         {:ok, user} <- decode_profile(profile, id, email) do
      {:ok, user}
    else
      {:error, :unavailable} -> {:error, :unavailable}
      _ -> {:error, :internal}
    end
  end

  defp decode_profile(profile, expected_id, expected_email) do
    with {:ok, "user_profile"} <- Items.required_string(profile, "entity_type"),
         {:ok, raw_id} <- Items.required_string(profile, "user_id"),
         {:ok, ^expected_id} <- UserId.parse(raw_id),
         {:ok, raw_email} <- Items.required_string(profile, "email_normalized"),
         {:ok, ^expected_email} <- Email.from_normalized(raw_email),
         {:ok, disabled} <- Items.required_bool(profile, "disabled"),
         {:ok, terms} <- Items.optional_string(profile, "terms_version"),
         {:ok, privacy} <- Items.optional_string(profile, "privacy_version"),
         {:ok, consented} <- Items.optional_u64(profile, "consented_at_unix") do
      {:ok,
       %User{
         user_id: expected_id,
         email: expected_email,
         disabled: disabled,
         terms_version: terms,
         privacy_version: privacy,
         consented_at_unix: consented
       }}
    else
      _ -> {:error, :internal}
    end
  end
end
