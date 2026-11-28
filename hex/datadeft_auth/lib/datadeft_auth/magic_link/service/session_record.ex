defmodule DatadeftAuth.MagicLink.Service.SessionRecord do
  @moduledoc "Authoritative server-side session record, redacted on inspection."
  alias DatadeftAuth.MagicLink.Core.Email
  alias DatadeftAuth.MagicLink.Service.{SessionId, UserId}

  @enforce_keys [:session_id, :user_id, :email, :created_at_unix, :revoked_at_unix]
  defstruct [:session_id, :user_id, :email, :created_at_unix, :revoked_at_unix]

  @type t :: %__MODULE__{
          session_id: SessionId.t(),
          user_id: UserId.t(),
          email: Email.t(),
          created_at_unix: non_neg_integer(),
          revoked_at_unix: non_neg_integer() | nil
        }
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.SessionRecord do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.SessionRecord<redacted>"
end
