defmodule DatadeftAuth.MagicLink.Service.CountryPolicy do
  @moduledoc """
  Exact or grouped pinning of trusted-edge country codes. Never use country
  values from request bodies or from a client-controlled header.
  """

  @enforce_keys [:pins]
  defstruct [:pins]
  @opaque t :: :exact | %__MODULE__{pins: %{binary() => binary()}}
  @eu27 ~w(AT BE BG CY CZ DE DK EE ES FI FR GR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK)

  @spec eu27() :: t()
  def eu27, do: %__MODULE__{pins: Map.new(@eu27, &{&1, "EU"})}

  @doc "Build a policy from `{tag, members}` pairs; overlapping groups and duplicate tags are invalid."
  @spec groups([{binary(), [binary()]}]) :: {:ok, t()} | {:error, :invalid_country_policy}
  def groups(groups), do: add_groups(groups, %{}, MapSet.new())

  @doc "Pin a trusted country; pseudo-codes in the group-tag namespace count as missing."
  @spec pin(t(), binary() | nil) :: binary() | nil
  def pin(policy, <<a, b>> = country) when a in ?A..?Z and b in ?A..?Z do
    if not group_tag?(country) do
      case policy do
        :exact -> country
        %__MODULE__{pins: pins} -> Map.get(pins, country, country)
        _ -> nil
      end
    end
  end

  def pin(_, _), do: nil

  defp add_groups([], pins, _), do: {:ok, %__MODULE__{pins: pins}}

  defp add_groups([{tag, [_ | _] = countries} | rest], pins, tags) do
    with true <- group_tag?(tag) and not MapSet.member?(tags, tag),
         {:ok, next} <- add_countries(countries, tag, pins) do
      add_groups(rest, next, MapSet.put(tags, tag))
    else
      _ -> {:error, :invalid_country_policy}
    end
  end

  defp add_groups(_, _, _), do: {:error, :invalid_country_policy}

  defp add_countries([], _, pins), do: {:ok, pins}

  defp add_countries([<<a, b>> = country | rest], tag, pins) when a in ?A..?Z and b in ?A..?Z do
    if Map.has_key?(pins, country),
      do: {:error, :invalid_country_policy},
      else: add_countries(rest, tag, Map.put(pins, country, tag))
  end

  defp add_countries(_, _, _), do: {:error, :invalid_country_policy}

  defp group_tag?(tag) when tag in ["EU", "AA", "ZZ"], do: true
  defp group_tag?(<<?Q, second>>) when second in ?M..?Z, do: true
  defp group_tag?(<<?X, second>>) when second in ?A..?Z and second not in [?X, ?K], do: true
  defp group_tag?(_), do: false
end
