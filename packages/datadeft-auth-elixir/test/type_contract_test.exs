defmodule DatadeftAuth.TypeContractTest do
  use ExUnit.Case, async: true

  # Contract-presence checks complement compilation and runtime tests. They do
  # not check implementations against specs; that requires a type analyzer.
  @contracts [
    {DatadeftAuth, [start_link: 0, start_link: 1, child_spec: 1, status: 1],
     [option: 0, options: 0, status_result: 0]},
    {DatadeftAuth.Error, [], [code: 0, t: 0]},
    {DatadeftAuth.Protocol, [max_frame: 0, build_version: 0, request: 2, feed: 2, reply: 1],
     [request_id: 0, operation: 0, result: 0, failure: 0, frame: 0, buffer: 0, feed_result: 0]},
    {DatadeftAuth.Connection,
     [
       start_link: 1,
       init: 1,
       handle_call: 3,
       handle_info: 2,
       terminate: 2,
       format_status: 1,
       replies: 2,
       reply: 2,
       send_request: 3,
       disconnect: 2,
       schedule_restart: 1,
       finish: 2,
       open: 1,
       close: 1,
       error: 1
     ], [pending_request: 0, next_id: 0, state: 0, state: 1, call_result: 0]}
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
