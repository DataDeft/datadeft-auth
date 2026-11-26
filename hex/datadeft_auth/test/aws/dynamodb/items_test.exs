defmodule DatadeftAuth.AWS.DynamoDB.ItemsTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.DynamoDB.Items

  test "numeric decoding matches Rust u64 parsing without accepting floats or overflow" do
    for {encoded, expected} <- [
          {"0", 0},
          {"+1", 1},
          {"0001", 1},
          {"18446744073709551615", 18_446_744_073_709_551_615}
        ] do
      assert Items.optional_u64(%{"value" => %{"N" => encoded}}, "value") == {:ok, expected}
    end

    for value <- ["-0", "-1", "1.0", "1e2", " 1", "1 ", "", "+", "18446744073709551616"] do
      assert Items.optional_u64(%{"value" => %{"N" => value}}, "value") == {:error, :internal}
    end
  end

  test "absent optional values differ from corrupt tagged attributes" do
    assert Items.optional_u64(%{}, "value") == {:ok, nil}
    assert Items.optional_string(%{}, "value") == {:ok, nil}
    assert Items.required_string(%{}, "value") == {:error, :internal}
    assert Items.required_bool(%{}, "value") == {:error, :internal}

    for attribute <- [
          %{"NULL" => true},
          %{"S" => "value", "N" => "1"},
          %{"S" => <<255>>},
          %{"N" => 1},
          nil
        ] do
      assert Items.optional_string(%{"value" => attribute}, "value") == {:error, :internal}
      assert Items.optional_u64(%{"value" => attribute}, "value") == {:error, :internal}
      assert Items.required_bool(%{"value" => attribute}, "value") == {:error, :internal}
    end
  end
end
