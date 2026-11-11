ExUnit.start()

defmodule DatadeftAuth.TestSupport do
  import ExUnit.Assertions

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

  @doc "An auth config for the executable's fake mode with fresh random keys."
  def fake_config do
    key = fn -> :crypto.strong_rand_bytes(32) |> Base.encode64() end
    now = System.os_time(:second)

    document =
      Jason.encode!(%{
        kid: "test-active",
        mint_until_unix: now + 90 * 24 * 60 * 60,
        verify_until_unix: now + 121 * 24 * 60 * 60,
        magic_link_lookup_hmac_b64: key.(),
        storage_hmac_b64: key.(),
        session_cookie_root_b64: key.(),
        magic_link_confirm_cookie_root_b64: key.(),
        pow_challenge_secret_b64: key.(),
        pow_proof_cookie_root_b64: key.()
      })

    %{
      mode: :fake,
      service: %{terms_version: "test-terms-v1", privacy_version: "test-privacy-v1"},
      email: %{
        link_base_url: "https://auth.example.test/magic?token=",
        subject: "Sign in",
        text: "Open {magic_link_url} to sign in."
      },
      secrets: %{active_document: document}
    }
  end

  def fake(mode) do
    suffix = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    dir = Path.join(System.tmp_dir!(), "datadeft-fixture-#{suffix}")
    File.mkdir!(dir)
    path = Path.join(dir, "worker")

    handshake =
      Jason.encode!(%{
        version: 1,
        id: 1,
        result: %{
          operation: "handshake",
          build_version: DatadeftAuth.Protocol.build_version(),
          max_frame_bytes: DatadeftAuth.Protocol.max_frame()
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
