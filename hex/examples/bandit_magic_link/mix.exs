defmodule BanditMagicLink.MixProject do
  use Mix.Project

  def project do
    [
      app: :bandit_magic_link,
      version: "0.0.0",
      elixir: "~> 1.16",
      deps: [
        {:datadeft_auth, path: "../../datadeft_auth"},
        {:bandit, "~> 1.15 and >= 1.15.0"},
        {:plug, "~> 1.20 and >= 1.20.4"}
      ]
    ]
  end

  def application do
    [mod: {BanditMagicLink, []}, extra_applications: [:crypto]]
  end
end
