# Build a Hex source archive, unpack it outside the workspace, and test that
# exact source plus a clean path consumer and release. Never edit working sources.
Code.require_file("package_stage.exs", __DIR__)

defmodule PackageCheck do
  import PackageStage, only: [cmd!: 3, cmd!: 4]

  def run do
    root = File.cwd!()

    temporary =
      Path.join(System.tmp_dir!(), "datadeft-package-#{System.unique_integer([:positive])}")

    stage = Path.join(temporary, "stage")
    unpacked = Path.join(temporary, "unpacked")

    try do
      PackageStage.stage!(root, stage)
      cmd!("mix", ["hex.build"], stage)
      archive = Path.join(stage, "datadeft_auth-#{Mix.Project.config()[:version]}.tar")
      {:ok, entries} = :erl_tar.extract(String.to_charlist(archive), [:memory])
      contents = entries |> List.keyfind(~c"contents.tar.gz", 0) |> elem(1)
      File.mkdir_p!(unpacked)
      {:ok, files} = :erl_tar.extract({:binary, contents}, [:compressed, :memory])

      for {name, _} <- files do
        name = to_string(name)

        unless Enum.any?(["lib/", "test/", "native/"], &String.starts_with?(name, &1)) or
                 name in ["mix.exs", "mix.lock", ".formatter.exs", "README.md", "LICENSE"] do
          raise "unexpected Hex archive entry"
        end

        if Path.type(name) == :absolute or ".." in Path.split(name),
          do: raise("unsafe archive path")
      end

      :ok =
        :erl_tar.extract({:binary, contents}, [:compressed, {:cwd, String.to_charlist(unpacked)}])

      cmd!("mix", ["deps.get", "--check-locked"], unpacked)
      cmd!("mix", ["test", "--warnings-as-errors"], unpacked)

      consumer = Path.join(temporary, "consumer")
      File.mkdir_p!(Path.join(consumer, "lib"))

      File.write!(Path.join(consumer, "mix.exs"), """
      defmodule Consumer.MixProject do
        use Mix.Project
        def project, do: [app: :consumer, version: "0.0.0",
          deps: [{:datadeft_auth, path: #{inspect(unpacked)}}]]
        def application, do: []
      end
      """)

      cmd!("mix", ["deps.get"], consumer)
      cmd!("mix", ["release"], consumer, [{"MIX_ENV", "prod"}])
      release = Path.join(consumer, "_build/prod/rel/consumer/bin/consumer")

      cmd!(
        release,
        [
          "eval",
          """
          {:ok, pid} = DatadeftAuth.start_link([])
          ready = Enum.reduce_while(1..100, false, fn _, _ ->
            case DatadeftAuth.status(pid) do
              {:ok, :transport_ready} -> {:halt, true}
              _ -> Process.sleep(20); {:cont, false}
            end
          end)
          if not ready, do: raise("release transport unavailable")
          GenServer.stop(pid)
          """
        ],
        consumer
      )

      IO.puts("Isolated Hex source archive, clean consumer and Mix release passed.")
    after
      File.rm_rf!(temporary)
    end
  end
end

PackageCheck.run()
