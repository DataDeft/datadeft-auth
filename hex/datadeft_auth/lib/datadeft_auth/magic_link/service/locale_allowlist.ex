defmodule DatadeftAuth.MagicLink.Service.LocaleAllowlist do
  @moduledoc "Resolve a request hint only to an app-configured email locale."

  @enforce_keys [:default, :tags]
  defstruct [:default, :tags]
  @opaque t :: %__MODULE__{default: String.t(), tags: [String.t()]}

  @spec new(String.t(), [String.t()]) :: {:ok, t()} | {:error, :invalid_locale_allowlist}
  def new(default, others) when is_list(others) do
    tags = [default | others]

    if Enum.all?(tags, &valid_tag?/1) and Enum.uniq(tags) == tags do
      {:ok, %__MODULE__{default: default, tags: tags}}
    else
      {:error, :invalid_locale_allowlist}
    end
  end

  def new(_, _), do: {:error, :invalid_locale_allowlist}

  @doc "Ignore invalid or oversized hints; prefer exact tag, then the first language match."
  @spec resolve(t(), term()) :: String.t()
  def resolve(%__MODULE__{default: default, tags: tags}, hint)
      when is_binary(hint) and byte_size(hint) <= 35 do
    if Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, hint) do
      tag = String.downcase(hint, :ascii)
      [lang | _] = :binary.split(tag, ["-", "_"])

      Enum.find(tags, &(String.downcase(&1, :ascii) == tag)) ||
        Enum.find(tags, &(hd(:binary.split(&1, "-")) == lang)) || default
    else
      default
    end
  end

  def resolve(%__MODULE__{default: default}, _), do: default

  defp valid_tag?(tag) when is_binary(tag) and byte_size(tag) in 2..6,
    do: Regex.match?(~r/\A[a-z]{2,3}(-[A-Z]{2})?\z/, tag)

  defp valid_tag?(_), do: false
end
