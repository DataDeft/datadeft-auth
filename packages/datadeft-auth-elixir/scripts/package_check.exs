# Build a Hex source archive, unpack it outside the workspace, and test that
# exact source plus a clean path consumer and release. Never edit working sources.
defmodule PackageCheck do
  def run do
    root = File.cwd!()

    temporary =
      Path.join(System.tmp_dir!(), "datadeft-package-#{System.unique_integer([:positive])}")

    stage = Path.join(temporary, "stage")
    unpacked = Path.join(temporary, "unpacked")
    File.mkdir_p!(stage)

    try do
      for item <- ["lib", "test", "mix.exs", "mix.lock", ".formatter.exs", "README.md", "LICENSE"] do
        File.cp_r!(Path.join(root, item), Path.join(stage, item))
      end

      native = "native/datadeft_auth_port"
      File.mkdir_p!(Path.join(stage, native))
      File.cp_r!(Path.join([root, native, "src"]), Path.join([stage, native, "src"]))
      manifest = File.read!(Path.join([root, native, "Cargo.toml"]))

      fields = [
        {"version", Mix.Project.config()[:version]},
        {"edition", "2024"},
        {"rust-version", "1.94.1"},
        {"license", "MIT"},
        {"repository", "https://github.com/DataDeft/datadeft-auth"}
      ]

      manifest =
        Enum.reduce(fields, manifest, fn {key, value}, source ->
          String.replace(source, "\n#{key}.workspace = true", ~s(\n#{key} = "#{value}"))
        end)

      manifest = String.replace(manifest, "[lints]\nworkspace = true", "")
      File.write!(Path.join([stage, native, "Cargo.toml"]), manifest <> "\n[workspace]\n")

      cmd!("cargo", ["generate-lockfile", "--manifest-path", "#{native}/Cargo.toml"], stage)
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

  defp cmd!(command, args, dir, env \\ []) do
    {output, code} = System.cmd(command, args, cd: dir, env: env, stderr_to_stdout: true)

    if code != 0 do
      IO.write(output)
      raise "isolated package verification failed"
    end
  end
end

PackageCheck.run()
