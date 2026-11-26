defmodule DatadeftAuth.AWS.DynamoDB.Client do
  @moduledoc """
  Explicit DynamoDB IO boundary. Implementations own credentials, signing, HTTP,
  timeouts and provider-error scrubbing. Never log request bodies or raw errors.

  Inputs and outputs use DynamoDB's JSON AttributeValue representation. A
  conditional failure must be distinguished from outages, never treated as a
  successful write. No automatic replay is authorized by this contract.
  """

  @callback request(state :: term(), operation :: String.t(), input :: map()) ::
              {:ok, map()} | {:error, :conditional_write_failed | :unavailable | :internal}
end
