defmodule DatadeftAuth.ProtocolTest do
  use ExUnit.Case, async: true
  alias DatadeftAuth.Protocol

  test "framing handles fragmented prefixes, bodies and coalesced messages" do
    frame = Protocol.request(1, "handshake")
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
