ExUnit.start()

defmodule DatadeftAuth.TestSupport do
  import ExUnit.Assertions

  def executable,
    do: :code.priv_dir(:datadeft_auth) |> to_string() |> Path.join("datadeft-auth-port")

  def eventually(fun, attempts \\ 150)

  def eventually(fun, attempts) when attempts > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      eventually(fun, attempts - 1)
    end
  end

  def eventually(_, 0), do: flunk("condition did not become true")

  def ready(pid), do: eventually(fn -> DatadeftAuth.status(pid) == {:ok, :transport_ready} end)

  def os_pid(connection) do
    %{port: port} = :sys.get_state(connection)
    {:os_pid, pid} = Port.info(port, :os_pid)
    pid
  end

  def alive?(pid) do
    {_, status} = System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
    status == 0
  end

  def fake(mode) do
    dir = Path.join(System.tmp_dir!(), "datadeft-fixture-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, "worker")

    handshake =
      Jason.encode!(%{
        version: 1,
        id: 1,
        result: %{
          operation: "handshake",
          build_version: DatadeftAuth.Protocol.build_version(),
          max_frame_bytes: 4096
        }
      })
      |> Base.encode64()

    contents =
      File.read!(Path.join(__DIR__, "fixtures/worker.erl"))
      |> String.replace("__MODE__", Atom.to_string(mode))
      |> String.replace("__HANDSHAKE__", handshake)

    File.write!(path, contents)
    File.chmod!(path, 0o755)
    ExUnit.Callbacks.on_exit(fn -> File.rm_rf!(dir) end)
    path
  end
end
