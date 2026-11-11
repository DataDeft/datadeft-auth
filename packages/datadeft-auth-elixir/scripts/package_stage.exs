# Shared staging for the publishable standalone package: copies the Hex
# package sources and materializes the workspace Cargo metadata and lockfile
# into a standalone crate. Required by package_check.exs and stage_publish.exs;
# never edits working sources and uploads nothing.
defmodule PackageStage do
  def stage!(root, stage) do
    File.mkdir_p!(stage)

    # The native entries are staged separately below with a rewritten manifest.
    for item <- Mix.Project.config()[:package][:files],
        not String.starts_with?(item, "native/") do
      File.cp_r!(Path.join(root, item), Path.join(stage, item))
    end

    native = "native/datadeft_auth_port"
    File.mkdir_p!(Path.join(stage, native))
    File.cp_r!(Path.join([root, native, "src"]), Path.join([stage, native, "src"]))
    manifest = File.read!(Path.join([root, native, "Cargo.toml"]))

    # Inherited package metadata comes from the workspace manifest, so the
    # staged standalone crate cannot drift from the tree that was tested.
    workspace_manifest = File.read!(Path.join(root, "../../Cargo.toml"))

    fields =
      [{"version", Mix.Project.config()[:version]}] ++
        for key <- ["edition", "rust-version", "license", "repository"] do
          case Regex.run(~r/^#{key} = "([^"]+)"/m, workspace_manifest) do
            [_, value] -> {key, value}
            nil -> raise "#{key} not found in the workspace Cargo.toml"
          end
        end

    manifest =
      Enum.reduce(fields, manifest, fn {key, value}, source ->
        String.replace(source, "\n#{key}.workspace = true", ~s(\n#{key} = "#{value}"))
      end)

    manifest = String.replace(manifest, "[lints]\nworkspace = true", "")
    if String.contains?(manifest, "workspace = true"), do: raise("unreplaced workspace field")
    File.write!(Path.join([stage, native, "Cargo.toml"]), manifest <> "\n[workspace]\n")

    cmd!("cargo", ["generate-lockfile", "--manifest-path", "#{native}/Cargo.toml"], stage)
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
