defmodule DatadeftAuth.MixProject do
  use Mix.Project

  # x-release-please-start-version
  @version "0.7.0"
  # x-release-please-end

  def project do
    [
      app: :datadeft_auth,
      version: @version,
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: if(Mix.env() == :test, do: ["lib", "test/support"], else: ["lib"]),
      deps: [{:jason, "~> 1.4", only: :test}],
      description: "Native Elixir authentication compatible with datadeft-auth Rust.",
      package: [licenses: ["MIT"], files: ["lib", "mix.exs", "README.md", "LICENSE"]]
    ]
  end

  def application do
    [extra_applications: if(Mix.env() == :test, do: [:crypto, :inets, :ssl], else: [:crypto])]
  end
end
