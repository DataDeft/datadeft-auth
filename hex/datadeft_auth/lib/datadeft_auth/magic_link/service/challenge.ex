defmodule DatadeftAuth.MagicLink.Service.Challenge do
  @moduledoc "Keyed magic-link repository record/candidate. Contains no raw bearer token."
  @enforce_keys [
    :selector_lookup_hmac,
    :verifier_hash,
    :email,
    :expires_at_unix,
    :terms_version,
    :privacy_version,
    :consented_at_unix
  ]
  defstruct [
    :selector_lookup_hmac,
    :verifier_hash,
    :email,
    :expires_at_unix,
    :terms_version,
    :privacy_version,
    :consented_at_unix,
    consumed_at_unix: nil
  ]
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Challenge do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Challenge<redacted>"
end
