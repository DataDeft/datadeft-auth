defmodule DatadeftAuth.MagicLink.Service.User do
  @moduledoc """
  Authentication repository account record. A disabled account is returned as
  disabled, not disguised as an absent account. The service owns admission policy.
  """
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.UserId

  @enforce_keys [:user_id, :email, :disabled]
  defstruct [:user_id, :email, :disabled, :terms_version, :privacy_version, :consented_at_unix]

  @type t :: %__MODULE__{
          user_id: UserId.t(),
          email: Email.t(),
          disabled: boolean(),
          terms_version: String.t() | nil,
          privacy_version: String.t() | nil,
          consented_at_unix: non_neg_integer() | nil
        }
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.User do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.User<redacted>"
end
