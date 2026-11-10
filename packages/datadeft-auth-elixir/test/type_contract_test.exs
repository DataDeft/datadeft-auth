defmodule DatadeftAuth.TypeContractTest do
  use ExUnit.Case, async: true

  # Presence checks for the public transport contracts plus the redaction
  # callback. They complement compilation and runtime tests but do not check
  # implementations against specs; that requires a type analyzer. Private
  # helpers are deliberately not pinned so refactors stay one-file edits.
  @contracts [
    {DatadeftAuth, [start_link: 1, child_spec: 1, status: 1],
     [
       option: 0,
       options: 0,
       status_result: 0,
       request_timeout: 0,
       max_pending: 0,
       restart_delay: 0
     ]},
    {DatadeftAuth.Error, [], [code: 0, t: 0]},
    {DatadeftAuth.Protocol,
     [max_frame: 0, max_request_id: 0, build_version: 0, request: 2, feed: 2, reply: 1],
     [request_id: 0, operation: 0, result: 0, failure: 0, frame: 0, buffer: 0, feed_result: 0]},
    {DatadeftAuth.Connection, [start_link: 1, format_status: 1], []}
  ]

  test "critical API, protocol and lifecycle contracts retain specs and types" do
    for {module, functions, types} <- @contracts do
      {:ok, specs} = Code.Typespec.fetch_specs(module)
      specified = Map.new(specs)

      for function <- functions do
        assert Map.has_key?(specified, function),
               "missing spec for #{inspect(module)} #{inspect(function)}"
      end

      {:ok, definitions} = Code.Typespec.fetch_types(module)
      defined = Enum.map(definitions, fn {_kind, {name, _type, args}} -> {name, length(args)} end)

      for type <- types do
        assert type in defined, "missing type for #{inspect(module)} #{inspect(type)}"
      end
    end
  end
end
