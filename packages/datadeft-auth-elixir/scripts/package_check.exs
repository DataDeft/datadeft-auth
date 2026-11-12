# Build a Hex source archive, unpack it outside the workspace, and test that
# exact source plus a clean path consumer and release. Never edit working sources.
Code.require_file("package_stage.exs", __DIR__)

defmodule PackageCheck do
  import PackageStage, only: [cmd!: 3, cmd!: 4]

  def run do
    root = File.cwd!()

    suffix = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    temporary = Path.join(System.tmp_dir!(), "datadeft-package-#{suffix}")
    File.mkdir!(temporary)

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
          # Fresh test-only keys; no host credentials or AWS resources.
          key = fn -> :crypto.strong_rand_bytes(32) |> Base.encode64() end
          now = System.os_time(:second)
          document = Jason.encode!(%{
            kid: "release-test",
            mint_until_unix: now + 90 * 86400,
            verify_until_unix: now + 121 * 86400,
            magic_link_lookup_hmac_b64: key.(), storage_hmac_b64: key.(),
            session_cookie_root_b64: key.(), magic_link_confirm_cookie_root_b64: key.(),
            pow_challenge_secret_b64: key.(), pow_proof_cookie_root_b64: key.()
          })
          config = %{
            mode: :fake,
            service: %{terms_version: "test-v1", privacy_version: "test-v1"},
            email: %{link_base_url: "https://auth.example.test/auth/magic-link/landing?token=",
              subject: "Sign in", text: "Open {magic_link_url}"},
            secrets: %{active_document: document}
          }
          {:ok, pid} = DatadeftAuth.start_link(config: config)
          ready = Enum.reduce_while(1..100, false, fn _, _ ->
            case DatadeftAuth.status(pid) do
              {:ok, :transport_ready} -> {:halt, true}
              _ -> Process.sleep(20); {:cont, false}
            end
          end)
          if not ready, do: raise("release transport unavailable")
          email = "release-user@example.test"
          {:ok, _} = DatadeftAuth.request_link(pid, email,
            terms_accepted: true, privacy_accepted: true)
          {:ok, %{magic_link_url: url}} = DatadeftAuth.fake_last_magic_link(pid, email)
          token = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() |> Map.fetch!("token")
          {:ok, landing} = DatadeftAuth.landing(pid, token)
          {:ok, %{usable: true}} = DatadeftAuth.flow_state(pid, landing.confirm_cookie)
          {:ok, session} = DatadeftAuth.confirm(pid, landing.confirm_cookie, landing.confirmation)
          {:ok, %{valid: true}} = DatadeftAuth.validate_session(pid, session.session_cookie)
          {:ok, %{revoked: true}} = DatadeftAuth.logout(pid, session.session_cookie)
          {:ok, %{valid: false}} = DatadeftAuth.validate_session(pid, session.session_cookie)
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
