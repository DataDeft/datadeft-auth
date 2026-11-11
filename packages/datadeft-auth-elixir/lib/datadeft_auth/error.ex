defmodule DatadeftAuth.Error do
  @moduledoc "A redacted operational error. Codes are internal diagnostics, not HTTP responses."
  @enforce_keys [:code]
  defstruct [:code]

  @typedoc """
  Closed diagnostic codes; never map these directly to public HTTP responses.
  :rejected and :bad_request clear temporary client state; :unavailable
  preserves it for an identical retry after backoff.
  """
  @type code ::
          :configuration
          | :unavailable
          | :overloaded
          | :protocol
          | :timeout
          | :bad_request
          | :rejected
          | :internal

  @typedoc "Operational errors contain only a diagnostic code, never transport payloads."
  @type t :: %__MODULE__{code: code()}
end
