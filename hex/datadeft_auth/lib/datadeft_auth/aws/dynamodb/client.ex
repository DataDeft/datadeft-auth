defmodule DatadeftAuth.AWS.DynamoDB.Client do
  @moduledoc """
  Explicit DynamoDB IO boundary. Implementations own credentials, signing, HTTP,
  timeouts and provider-error scrubbing. Never log request bodies or raw errors.

  Inputs and outputs use DynamoDB's JSON AttributeValue representation. A
  conditional failure must be distinguished from outages, never treated as a
  successful write. Transaction cancellation returns only ordered reason codes,
  never provider messages or request/item data. The transaction adapter attributes
  conflicts by action position. `:unavailable` on a transaction is ambiguous:
  any retry must preserve the exact request and ClientRequestToken. No automatic
  replay or replanning is authorized by this contract.
  """

  @callback request(state :: term(), operation :: String.t(), input :: map()) ::
              {:ok, map()}
              | {:error, :conditional_write_failed | :unavailable | :internal}
              | {:error, {:transaction_canceled, [String.t() | nil]}}
end
