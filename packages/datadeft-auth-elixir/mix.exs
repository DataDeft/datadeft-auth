defmodule Mix.Tasks.Compile.DatadeftPort do
  use Mix.Task.Compiler
  @moduledoc false

  @impl true
  def run(_args) do
    root = File.cwd!()
    manifest = Path.join(root, "native/datadeft_auth_port/Cargo.toml")
    # The binary is Mix-env independent: share one cargo target dir under
    # _build so dev/test/prod compiles reuse the same release build.
    target =
      Mix.Project.build_path() |> Path.dirname() |> Path.join("datadeft_native") |> Path.expand()

    args = ["build", "--release", "--locked", "--manifest-path", manifest, "--target-dir", target]

    case System.cmd("cargo", args, stderr_to_stdout: true) do
      {_output, 0} ->
        priv = Path.join(Mix.Project.app_path(), "priv")
        File.mkdir_p!(priv)

        File.cp!(
          Path.join(target, "release/datadeft-auth-port"),
          Path.join(priv, "datadeft-auth-port")
        )

        File.chmod!(Path.join(priv, "datadeft-auth-port"), 0o755)
        {:ok, []}

      {output, _status} ->
        Mix.shell().info(output)
        Mix.shell().error("datadeft_auth Rust executable build failed")
        {:error, []}
    end
  rescue
    error ->
      # Usually a missing toolchain; include the exception so any other
      # failure stays diagnosable.
      Mix.shell().error(
        "datadeft_auth native build failed (requires Cargo and a supported " <>
          "Rust toolchain): #{Exception.message(error)}"
      )

      {:error, []}
  end
end

defmodule DatadeftAuth.MixProject do
  use Mix.Project
  # x-release-please-start-version
  @version "0.5.0"
  # x-release-please-end

  def project do
    [
      app: :datadeft_auth,
      version: @version,
      elixir: "~> 1.16",
      compilers: [:datadeft_port] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: [{:jason, "~> 1.4.4"}],
      description:
        "Framework-independent authentication through an isolated Rust process (in development)",
      package: [
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/DataDeft/datadeft-auth"},
        files: [
          "lib",
          "test",
          ".formatter.exs",
          "mix.exs",
          "mix.lock",
          "README.md",
          "LICENSE",
          "native/datadeft_auth_port/Cargo.toml",
          "native/datadeft_auth_port/Cargo.lock",
          "native/datadeft_auth_port/src"
        ]
      ]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
