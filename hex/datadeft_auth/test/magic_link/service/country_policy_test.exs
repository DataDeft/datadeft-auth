defmodule DatadeftAuth.MagicLink.Service.CountryPolicyTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Service.CountryPolicy

  test "pins exact and EU27 trusted-edge codes, never directly accepts group namespace" do
    eu = CountryPolicy.eu27()
    assert CountryPolicy.pin(eu, "HU") == "EU"
    assert CountryPolicy.pin(eu, "PT") == "EU"
    assert CountryPolicy.pin(eu, "GB") == "GB"
    assert CountryPolicy.pin(:exact, "HU") == "HU"

    for code <- ["EU", "AA", "QM", "QZ", "XA", "XZ", "ZZ", "hu", nil] do
      assert CountryPolicy.pin(eu, code) == nil
      assert CountryPolicy.pin(:exact, code) == nil
    end

    assert CountryPolicy.pin(eu, "XX") == "XX"
    assert CountryPolicy.pin(eu, "XK") == "XK"
  end

  test "rejects ambiguous groups and tags that collide with request countries" do
    assert {:ok, policy} = CountryPolicy.groups([{"XA", ["US", "CA"]}])
    assert CountryPolicy.pin(policy, "CA") == "XA"

    for invalid <- [
          [{"US", ["CA"]}],
          [{"XX", ["US"]}],
          [{"XK", ["US"]}],
          [{"EU", []}],
          [{"EU", ["HU", "HU"]}],
          [{"EU", ["Hu"]}],
          [{"EU", ["HU"]}, {"XA", ["HU"]}],
          [{"EU", ["HU"]}, {"EU", ["AT"]}]
        ] do
      assert {:error, :invalid_country_policy} = CountryPolicy.groups(invalid)
    end
  end
end
