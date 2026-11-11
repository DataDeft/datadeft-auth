# Stage the publishable standalone package under _build and build its Hex
# archive as a rehearsal. Publishing stays a manual, separately authorized
# step run from the printed directory; this script uploads nothing.
Code.require_file("package_stage.exs", __DIR__)

root = File.cwd!()
stage = Mix.Project.build_path() |> Path.dirname() |> Path.join("publish_stage")
File.rm_rf!(stage)
PackageStage.stage!(root, stage)
PackageStage.cmd!("mix", ["hex.build"], stage)
IO.puts("Publishable package staged; review and run `mix hex.publish` from:")
IO.puts(stage)
