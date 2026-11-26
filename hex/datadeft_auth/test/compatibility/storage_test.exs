defmodule DatadeftAuth.Compatibility.StorageTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.AWS.StorageKey
  alias DatadeftAuth.MagicLink.Core.Email

  @moduletag :repository

  test "both languages pin identical storage HMAC bytes" do
    rows = rows("storage_hmac.tsv")
    assert length(rows) >= 6

    for [key, prefix, value, expected] <- rows do
      assert {:ok, key} = StorageKey.new(decode(key))
      assert StorageKey.hmac(key, decode(prefix), decode(value)) == {:ok, expected}
    end
  end

  test "email identities and rejection behavior match the Rust vectors" do
    rows = rows("email.tsv")
    assert length(rows) >= 50

    for [input, expected, stored] <- rows do
      input = decode(input)

      case expected do
        "-" ->
          assert Email.normalize(input) == {:error, :invalid_email}

        encoded ->
          assert {:ok, email} = Email.normalize(input)
          assert Email.value(email) == decode(encoded)
      end

      case stored do
        "true" ->
          assert {:ok, email} = Email.from_normalized(input)
          assert Email.value(email) == input

        "false" ->
          assert Email.from_normalized(input) == {:error, :invalid_email}
      end
    end
  end

  defp rows(name) do
    System.fetch_env!("DD_AUTH_COMPATIBILITY_DIR")
    |> Path.join(name)
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.map(&String.split(&1, "\t"))
  end

  defp decode(hex), do: Base.decode16!(hex, case: :lower)
end
