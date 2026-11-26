defmodule DatadeftAuth.MagicLink.Core.EmailTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.MagicLink.Core.Email

  test "trim and ASCII-lowercase the entire address without alias folding" do
    for {input, normalized} <- [
          {" User+Tag@Example.COM\t", "user+tag@example.com"},
          {"\nuser@example.test\r\n", "user@example.test"},
          {"First.Last+News@GMAIL.COM", "first.last+news@gmail.com"},
          {"\u0085USER@EXAMPLE.TEST\u3000", "user@example.test"}
        ] do
      assert {:ok, email} = Email.normalize(input)
      assert Email.value(email) == normalized
      assert Email.from_normalized(normalized) == {:ok, email}
    end
  end

  test "from_normalized validates rather than repairing stored values" do
    for value <- ["User@example.test", "user@EXAMPLE.TEST", " user@example.test"] do
      assert Email.from_normalized(value) == {:error, :invalid_email}
    end
  end

  test "invalid structures have a constant error containing no input" do
    for input <- [
          "",
          " ",
          "user name@example.test",
          "Name <user@example.test>",
          "a@example.test,b@example.test",
          "a@example.test;b@example.test",
          "two@@example.test",
          "@example.test",
          "user@",
          "user@example",
          "user@example.",
          "user@.example.test",
          "user@example..test",
          ".user@example.test",
          "user.@example.test",
          "user..name@example.test",
          "user@-example.test",
          "user@example-.test",
          "ü@example.test",
          "user@exämple.test",
          "user\0@example.test",
          "user\r\n@example.test",
          "\uFEFFuser@example.test",
          <<255>>,
          nil
        ] do
      assert Email.normalize(input) == {:error, :invalid_email}
      assert Email.from_normalized(input) == {:error, :invalid_email}
    end
  end

  test "enforces byte length caps for local parts, labels and whole addresses" do
    assert {:ok, _} = Email.normalize(String.duplicate("a", 64) <> "@example.test")

    assert {:error, :invalid_email} =
             Email.normalize(String.duplicate("a", 65) <> "@example.test")

    assert {:ok, _} = Email.normalize("a@" <> String.duplicate("b", 63) <> ".test")

    assert {:error, :invalid_email} =
             Email.normalize("a@" <> String.duplicate("b", 64) <> ".test")

    domain = Enum.map_join([61, 61, 60], ".", &String.duplicate("b", &1))
    assert {:ok, _} = Email.normalize(String.duplicate("a", 64) <> "@" <> domain <> ".test")

    assert {:error, :invalid_email} =
             Email.normalize(String.duplicate("a", 64) <> "@" <> domain <> ".tests")
  end

  test "inspection redacts the address" do
    assert {:ok, email} = Email.normalize("user@example.test")
    assert inspect(email) == "#DatadeftAuth.MagicLink.Core.Email<redacted>"
  end
end
