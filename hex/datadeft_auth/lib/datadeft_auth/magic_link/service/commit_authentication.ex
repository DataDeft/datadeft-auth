defmodule DatadeftAuth.MagicLink.Service.CommitAuthentication do
  @moduledoc """
  One exact atomic authentication plan, not an authentication or token-validation API.

  The trusted service must validate verifier, account, policy and consent, draw
  independent IDs, calculate expiry and finish cookie minting before submission.
  `user` is `{:existing, UserId.t()}` or `{:create, UserId.t()}`.

  An unavailable result may mean committed. Retry only this identical command
  with the same attempt ID; never regenerate IDs, reread or replan an ambiguous
  attempt. A changed command requires a fresh attempt ID after a confirmed
  cancellation. Attempt IDs are request-scoped, never persisted.
  """
  @type t :: %__MODULE__{
          magic_link: DatadeftAuth.MagicLink.Service.AuthenticationExpectation.t(),
          now_unix: non_neg_integer(),
          attempt_id: DatadeftAuth.MagicLink.Service.AuthenticationAttemptId.t(),
          user: {:create | :existing, DatadeftAuth.MagicLink.Service.UserId.t()},
          session_id: DatadeftAuth.MagicLink.Service.SessionId.t(),
          session_expires_at_unix: non_neg_integer()
        }
  @enforce_keys [
    :magic_link,
    :now_unix,
    :attempt_id,
    :user,
    :session_id,
    :session_expires_at_unix
  ]
  defstruct [:magic_link, :now_unix, :attempt_id, :user, :session_id, :session_expires_at_unix]
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.CommitAuthentication do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.CommitAuthentication<redacted>"
end
