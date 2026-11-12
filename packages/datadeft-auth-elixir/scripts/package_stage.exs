# Shared staging for the publishable standalone package: copies the Hex
# package sources and materializes a self-contained Rust workspace (the port
# executable plus vendored workspace crates) so the published source builds
# without this checkout. Required by package_check.exs and stage_publish.exs;
# never edits working sources and uploads nothing.
defmodule PackageStage do
  # The port's workspace dependencies, vendored with their own path deps
  # preserved (they are siblings under vendor/ exactly as under crates/).
  @vendored [
    "datadeft-auth-token-core",
    "datadeft-magic-link-core",
    "datadeft-magic-link-service",
    "datadeft-magic-link-aws",
    "datadeft-pow-core"
  ]

  def stage!(root, stage) do
    File.mkdir_p!(stage)

    # The native entries are staged separately below with a self-contained
    # workspace manifest.
    for item <- Mix.Project.config()[:package][:files],
        not String.starts_with?(item, "native/") do
      File.cp_r!(Path.join(root, item), Path.join(stage, item))
    end

    workspace_root = Path.expand(Path.join(root, "../.."))
    native = Path.join(stage, "native")
    port = Path.join(native, "datadeft_auth_port")
    File.mkdir_p!(port)

    File.cp_r!(
      Path.join(root, "native/datadeft_auth_port/src"),
      Path.join(port, "src")
    )

    # Inside the stage the crates live under native/vendor, siblings exactly
    # like under crates/, so intra-crate path dependencies stay valid.
    port_manifest =
      root
      |> Path.join("native/datadeft_auth_port/Cargo.toml")
      |> File.read!()
      |> String.replace("../../../../crates/", "../vendor/")

    if String.contains?(port_manifest, "../../") do
      raise "unvendored path dependency in the port manifest"
    end

    File.write!(Path.join(port, "Cargo.toml"), port_manifest)

    for crate <- @vendored do
      source = Path.join([workspace_root, "crates", crate])
      target = Path.join([native, "vendor", crate])
      File.mkdir_p!(target)
      File.cp_r!(Path.join(source, "src"), Path.join(target, "src"))
      File.cp_r!(Path.join(source, "Cargo.toml"), Path.join(target, "Cargo.toml"))

      # Explicit [[bench]] targets must exist even in a non-benchmark build.
      if File.dir?(Path.join(source, "benches")) do
        File.cp_r!(Path.join(source, "benches"), Path.join(target, "benches"))
      end
    end

    # The staged workspace inherits package metadata, dependency floors and
    # lints verbatim from the tree that was tested.
    root_manifest = File.read!(Path.join(workspace_root, "Cargo.toml"))

    inherited =
      case String.split(root_manifest, "[workspace.package]", parts: 2) do
        [_, inherited] -> inherited
        _ -> raise "workspace package metadata not found in the root Cargo.toml"
      end

    File.write!(Path.join(native, "Cargo.toml"), """
    [workspace]
    resolver = "3"
    members = ["datadeft_auth_port", "vendor/*"]

    [workspace.package]#{inherited}
    """)

    # Retain the dependency versions verified in the checkout. Update only
    # workspace packages to reconcile the staged member set; generate-lockfile
    # would instead resolve every dependency again against the latest index.
    File.cp!(Path.join(workspace_root, "Cargo.lock"), Path.join(native, "Cargo.lock"))

    cmd!(
      "cargo",
      ["update", "--workspace", "--offline", "--manifest-path", "native/Cargo.toml"],
      stage
    )

    :ok
  end

  def cmd!(command, args, dir, env \\ []) do
    {output, code} = System.cmd(command, args, cd: dir, env: env, stderr_to_stdout: true)

    if code != 0 do
      IO.write(output)
      raise "command failed: #{command} #{Enum.join(args, " ")}"
    end
  end
end
