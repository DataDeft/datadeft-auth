defmodule DatadeftAuth.MagicLink.Service.Mail do
  @moduledoc """
  Delivery input for the injected outbox. Render the token only for delivery
  over the application's configured link. Do not log or store the raw bearer.
  """
  alias DatadeftAuth.MagicLink.Core.{Email, Token}
  @enforce_keys [:email, :token, :expires_at_unix, :locale]
  defstruct [:email, :token, :expires_at_unix, :locale]

  @type t :: %__MODULE__{
          email: Email.t(),
          token: Token.t(),
          expires_at_unix: non_neg_integer(),
          locale: String.t() | nil
        }
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.Mail do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.Mail<redacted>"
end
