defmodule DatadeftAuth.ProtocolTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.Protocol

  test "framing handles fragmented prefixes, bodies and coalesced messages" do
    frame = Protocol.request(1, :handshake)
    <<first::binary-size(2), rest::binary>> = frame
    assert {:ok, [], ^first} = Protocol.feed(<<>>, first)
    assert {:ok, [body, second], <<>>} = Protocol.feed(first, rest <> frame)
    assert body == second
    assert %{"operation" => "handshake"} = Jason.decode!(body)
  end

  test "rejects zero and oversized prefixes without waiting for a body" do
    assert {:error, :protocol} = Protocol.feed(<<>>, <<0::32>>)
    assert {:error, :protocol} = Protocol.feed(<<>>, <<Protocol.max_frame() + 1::32>>)
    assert {:error, :protocol} = Protocol.feed(<<>>, <<0xFFFFFFFF::32>>)
  end

  test "reply IDs accept the inclusive uint32 bounds but not the internal sentinel" do
    for id <- [1, 0xFFFFFFFF] do
      frame = Jason.encode!(%{version: 1, id: id, result: %{operation: "ping"}})
      assert {:ok, ^id, :ping} = Protocol.reply(frame)
    end

    for id <- [-1, 0, 0x100000000] do
      frame = Jason.encode!(%{version: 1, id: id, result: %{operation: "ping"}})
      assert {:error, :protocol} = Protocol.reply(frame)
    end
  end

  test "per-request error replies parse only the closed code set" do
    frame = ~s({"version":1,"id":2,"result":{"operation":"error","code":"overloaded"}})
    assert {:ok, 2, {:error, :overloaded}} = Protocol.reply(frame)

    for frame <- [
          ~s({"version":1,"id":2,"result":{"operation":"error","code":"unknown"}}),
          ~s({"version":1,"id":2,"result":{"operation":"error"}}),
          ~s({"version":1,"id":2,"result":{"operation":"error","code":"overloaded","x":0}}),
          ~s({"version":1,"id":2,"result":{"operation":"error","code":1}})
        ] do
      assert {:error, :protocol} = Protocol.reply(frame)
    end
  end

  test "session validation forwards refresh values and refuses inconsistent failures" do
    for refreshed <- [nil, "fixture-refreshed-cookie"] do
      frame =
        Jason.encode!(%{
          version: 1,
          id: 2,
          result: %{
            operation: "validate_session",
            valid: true,
            user_id: "fixture-user",
            refreshed_cookie: refreshed
          }
        })

      assert {:ok, 2,
              {:validate_session,
               %DatadeftAuth.Validation{
                 valid: true,
                 user_id: "fixture-user",
                 refreshed_cookie: ^refreshed
               }}} = Protocol.reply(frame)
    end

    for result <- [
          %{valid: false, user_id: "fixture-user", refreshed_cookie: nil},
          %{valid: false, user_id: nil, refreshed_cookie: "fixture-cookie"},
          %{valid: true, user_id: nil, refreshed_cookie: nil},
          %{valid: true, user_id: "fixture-user", refreshed_cookie: 1}
        ] do
      frame =
        Jason.encode!(%{
          version: 1,
          id: 2,
          result: Map.put(result, :operation, "validate_session")
        })

      assert {:error, :protocol} = Protocol.reply(frame)
    end
  end

  test "strict response schema rejects duplicates, unknown fields and forged shapes" do
    valid = ~s({"version":1,"id":2,"result":{"operation":"ping"}})
    assert {:ok, 2, :ping} = Protocol.reply(valid)

    for frame <- [
          ~s({"version":1,"version":1,"id":2,"result":{"operation":"ping"}}),
          ~s({"version":1,"id":2,"result":{"operation":"ping","operation":"ping"}}),
          ~s({"version":1,"id":2,"result":{"operation":"ping"},"extra":0}),
          ~s({"version":1,"id":2,"result":{"operation":"ping","extra":0}}),
          ~s({"version":2,"id":2,"result":{"operation":"ping"}}),
          ~s({"version":1,"id":0,"result":{"operation":"ping"}}),
          ~s({"version":1,"id":4294967296,"result":{"operation":"ping"}}),
          ~s({"version":1,"id":2,"result":{"operation":"unexpected"}}),
          ~s({"version":1,"id":2,"result":{"operation":"handshake","build_version":"wrong","max_frame_bytes":4096}}),
          "{} {}",
          <<255>>,
          "[]",
          String.duplicate(" ", Protocol.max_frame() + 1),
          :not_a_binary
        ] do
      assert {:error, :protocol} = Protocol.reply(frame)
    end
  end
end
