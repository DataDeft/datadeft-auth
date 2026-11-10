defmodule DatadeftAuthTest do
  use ExUnit.Case, async: false
  import DatadeftAuth.TestSupport
  alias DatadeftAuth.Error

  test "real child handshakes and responds to concurrent health checks" do
    pid = start_supervised!({DatadeftAuth, []})
    ready(pid)
    results = 1..20 |> Task.async_stream(fn _ -> DatadeftAuth.status(pid) end) |> Enum.to_list()
    assert Enum.all?(results, &(&1 == {:ok, {:ok, :transport_ready}}))
    assert DatadeftAuth.status(:nonexistent_datadeft_auth) == {:error, %Error{code: :unavailable}}
  end

  test "invalid configuration is redacted" do
    for opts <- [
          [unknown: 1],
          [executable: "relative"],
          [request_timeout: 0],
          [max_pending: 1025],
          [name: nil, name: nil],
          :invalid
        ] do
      assert {:error, %Error{code: :configuration}} = DatadeftAuth.start_link(opts)
    end
  end

  test "native crash leaves owner alive and restarts with a new OS process" do
    pid = start_supervised!({DatadeftAuth, [restart_delay: 30]})
    ready(pid)
    old = os_pid(pid)
    {_, 0} = System.cmd("kill", ["-KILL", Integer.to_string(old)])
    eventually(fn -> not alive?(old) end)
    ready(pid)
    assert Process.alive?(pid)
    refute os_pid(pid) == old
    assert :sys.get_status(pid) |> inspect() |> String.contains?(":redacted")
  end

  test "normal owner shutdown closes stdin and leaves no Rust child" do
    pid = start_supervised!({DatadeftAuth, []})
    ready(pid)
    child = os_pid(pid)
    stop_supervised!(DatadeftAuth)
    eventually(fn -> not alive?(child) end)
  end

  test "abrupt owner death leaves no Rust child" do
    {:ok, pid} = DatadeftAuth.start_link([])
    Process.unlink(pid)
    ready(pid)
    child = os_pid(pid)
    Process.exit(pid, :kill)
    eventually(fn -> not alive?(child) end)
  end

  test "abrupt BEAM termination closes the Rust child pipes" do
    args = [
      "--erl",
      "+S 1:1",
      "-pa",
      :code.lib_dir(:datadeft_auth) |> to_string() |> Path.join("ebin"),
      "-pa",
      :code.lib_dir(:jason) |> to_string() |> Path.join("ebin"),
      "-e",
      """
      Application.load(:datadeft_auth)
      {:ok, pid} = DatadeftAuth.start_link([])
      Enum.reduce_while(1..100, nil, fn _, _ ->
        case DatadeftAuth.status(pid) do
          {:ok, :transport_ready} -> {:halt, nil}
          _ -> Process.sleep(20); {:cont, nil}
        end
      end)
      %{port: port} = :sys.get_state(pid)
      {:os_pid, child} = Port.info(port, :os_pid)
      IO.puts(child)
      System.halt(0)
      """
    ]

    {output, 0} = System.cmd("elixir", args)
    child = output |> String.trim() |> String.to_integer()
    eventually(fn -> not alive?(child) end)
  end

  test "missing executable stays unavailable rather than restarting the supervisor" do
    pid =
      start_supervised!(
        {DatadeftAuth, [executable: "/nonexistent/datadeft-auth-port", restart_delay: 30]}
      )

    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
    Process.sleep(80)
    assert Process.alive?(pid)
  end

  test "malformed or oversized handshake fails closed" do
    for mode <- [:malformed, :oversized] do
      pid =
        start_supervised!(
          {DatadeftAuth, [executable: fake(mode), restart_delay: 1000, request_timeout: 2000]},
          id: mode
        )

      Process.sleep(400)
      assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
      assert Process.alive?(pid)
      stop_supervised!(mode)
    end
  end

  test "worker failure completes an outstanding request once without replay" do
    pid =
      start_supervised!(
        {DatadeftAuth, [executable: fake(:crash), request_timeout: 2000, restart_delay: 1000]}
      )

    # Wait for handshake without sending a health ping (which crashes this fixture).
    eventually(fn -> :sys.get_state(pid).ready end)
    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
    assert Process.alive?(pid)
  end

  test "bounded admission, timeout and caller-death cleanup" do
    pid =
      start_supervised!(
        {DatadeftAuth, [executable: fake(:slow), request_timeout: 700, max_pending: 1]}
      )

    eventually(fn -> :sys.get_state(pid).ready end)
    task = Task.async(fn -> DatadeftAuth.status(pid) end)
    eventually(fn -> map_size(:sys.get_state(pid).pending) == 1 end)
    assert {:error, %Error{code: :overloaded}} = DatadeftAuth.status(pid)
    assert {:error, %Error{code: :timeout}} = Task.await(task)
    assert map_size(:sys.get_state(pid).pending) == 0

    caller = spawn(fn -> DatadeftAuth.status(pid) end)
    eventually(fn -> map_size(:sys.get_state(pid).pending) == 1 end)
    Process.exit(caller, :kill)
    eventually(fn -> map_size(:sys.get_state(pid).pending) == 0 end)
  end

  test "handshake deadline closes an unresponsive executable" do
    pid =
      start_supervised!(
        {DatadeftAuth, [executable: fake(:silent), request_timeout: 1000, restart_delay: 1000]}
      )

    Process.sleep(1200)
    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
    assert :sys.get_state(pid).port == nil
  end
end
