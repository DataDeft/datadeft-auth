defmodule DatadeftAuth.MagicLink.Service.Challenge do
  @moduledoc "Keyed magic-link repository record/candidate. Contains no raw bearer token."
  @type t :: %__MODULE__{
          selector_lookup_hmac: DatadeftAuth.MagicLink.Core.Lookup.t(),
          verifier_hash: DatadeftAuth.MagicLink.Core.Lookup.t(),
          email: DatadeftAuth.MagicLink.Core.Email.t(),
          expires_at_unix: non_neg_integer(),
          terms_version: String.t(),
          privacy_version: String.t(),
          consented_at_unix: non_neg_integer(),
          consumed_at_unix: non_neg_integer() | nil
        }
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
