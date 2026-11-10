defmodule DatadeftAuth.Error do
  @moduledoc "A redacted operational error. Codes are internal diagnostics, not HTTP responses."
  @enforce_keys [:code]
  defstruct [:code]
  @type t :: %__MODULE__{code: atom()}
end
