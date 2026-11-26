defmodule DatadeftAuth.Test.LocalDynamo do
  @moduledoc false
  @behaviour DatadeftAuth.AWS.DynamoDB.Client

  # Test-only, loopback-only, unsigned local transport. Never use with AWS.
  @impl true
  def request(endpoint, operation, input) do
    case URI.parse(endpoint) do
      %URI{scheme: "http", host: "127.0.0.1", port: port, path: path}
      when is_integer(port) and path in [nil, "", "/"] ->
        post(endpoint, operation, input)

      _ ->
        {:error, :internal}
    end
  end

  defp post(endpoint, operation, input) do
    headers = [
      {~c"x-amz-target", String.to_charlist("DynamoDB_20120810." <> operation)},
      {~c"authorization",
       ~c"AWS4-HMAC-SHA256 Credential=local/19700101/local/dynamodb/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"}
    ]

    request =
      {String.to_charlist(endpoint), headers, ~c"application/x-amz-json-1.0",
       Jason.encode!(input)}

    case :httpc.request(:post, request, [timeout: 5_000, connect_timeout: 2_000],
           body_format: :binary
         ) do
      {:ok, {{_, 200, _}, _, body}} ->
        case Jason.decode(body) do
          {:ok, output} when is_map(output) -> {:ok, output}
          _ -> {:error, :internal}
        end

      {:ok, {{_, 400, _}, _, body}} ->
        case Jason.decode(body) do
          {:ok, %{"__type" => type} = output} ->
            cond do
              String.ends_with?(type, "#ConditionalCheckFailedException") ->
                {:error, :conditional_write_failed}

              String.ends_with?(type, "#TransactionCanceledException") ->
                {:error,
                 {:transaction_canceled,
                  Enum.map(Map.get(output, "CancellationReasons", []), &Map.get(&1, "Code"))}}

              true ->
                {:error, :internal}
            end

          _ ->
            {:error, :internal}
        end

      _ ->
        {:error, :unavailable}
    end
  end
end
