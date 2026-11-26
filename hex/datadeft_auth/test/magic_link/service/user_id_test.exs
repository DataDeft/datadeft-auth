defmodule DatadeftAuth.MagicLink.Service.UserIdTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.MagicLink.Service.UserId

  test "one canonical identifier spelling, explicitly accessible and redacted" do
    value = "usr-" <> String.duplicate("ab", 16)
    assert {:ok, id} = UserId.parse(value)
    assert UserId.value(id) == value
    assert inspect(id) == "#DatadeftAuth.MagicLink.Service.UserId<redacted>"

    for invalid <- [
          String.upcase(value),
          String.replace(value, "usr-", "usr_"),
          value <> "0",
          " " <> value,
          "usr-" <> String.duplicate("a", 31),
          nil
        ] do
      assert UserId.parse(invalid) == {:error, :invalid_user_id}
    end
  end
end
