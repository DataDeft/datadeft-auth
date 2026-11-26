defmodule DatadeftAuth.MagicLink.Service.AuthenticationExpectation do
  @moduledoc """
  Immutable challenge fields an authentication commit binds. No verifier material.
  Only construct after service-side constant-time verification and policy checks.
  """
  @type t :: %__MODULE__{
          selector_lookup_hmac: DatadeftAuth.MagicLink.Core.Lookup.t(),
          email: DatadeftAuth.MagicLink.Core.Email.t(),
          expires_at_unix: non_neg_integer(),
          terms_version: String.t(),
          privacy_version: String.t(),
          consented_at_unix: non_neg_integer()
        }
  @enforce_keys [
    :selector_lookup_hmac,
    :email,
    :expires_at_unix,
    :terms_version,
    :privacy_version,
    :consented_at_unix
  ]
  defstruct [
    :selector_lookup_hmac,
    :email,
    :expires_at_unix,
    :terms_version,
    :privacy_version,
    :consented_at_unix
  ]
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.AuthenticationExpectation do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.AuthenticationExpectation<redacted>"
end
