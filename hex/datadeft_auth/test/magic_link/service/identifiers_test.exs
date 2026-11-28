defmodule DatadeftAuth.MagicLink.Service.IdentifiersTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.MagicLink.Service.{AuthenticationAttemptId, SessionId}

  test "canonical session and attempt IDs round-trip and inspect redacts them" do
    for {module, prefix, size} <- [{SessionId, "sid-", 64}, {AuthenticationAttemptId, "aid-", 32}] do
      value = prefix <> String.duplicate("a", size)
      assert {:ok, id} = module.parse(value)
      assert module.value(id) == value
      assert String.ends_with?(inspect(id), "<redacted>")
      refute String.contains?(inspect(id), value)
    end
  end

  test "IDs cannot be interchanged or accept noncanonical or malformed values" do
    for {module, prefix, size, error} <- [
          {SessionId, "sid-", 64, :invalid_session_id},
          {AuthenticationAttemptId, "aid-", 32, :invalid_attempt_id}
        ] do
      value = prefix <> String.duplicate("a", size)

      for invalid <- [
            String.upcase(value),
            value <> "\n",
            " " <> value,
            prefix <> String.duplicate("a", size - 1),
            prefix <> String.duplicate("g", size),
            "usr-" <> String.duplicate("a", 32),
            <<255>>,
            nil
          ] do
        assert module.parse(invalid) == {:error, error}
      end
    end
  end
end
