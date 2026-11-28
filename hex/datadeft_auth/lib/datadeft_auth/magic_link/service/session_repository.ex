defmodule DatadeftAuth.MagicLink.Service.SessionRepository do
  @moduledoc "Injected live session repository. Missing/revoked/expired rows return `{:ok, nil}`."
  alias DatadeftAuth.MagicLink.Service.{SessionId, SessionRecord, UserId}

  @type error :: :unavailable | :rate_limited | :internal | :conditional_write_failed

  @callback find_session(term(), SessionId.t(), non_neg_integer()) ::
              {:ok, SessionRecord.t() | nil} | {:error, error()}
  @callback is_session_owner_active(term(), UserId.t(), non_neg_integer()) ::
              {:ok, boolean()} | {:error, error()}
  @callback revoke_session(term(), SessionId.t(), non_neg_integer()) :: :ok | {:error, error()}
end
