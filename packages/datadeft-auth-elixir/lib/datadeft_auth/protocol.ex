defmodule DatadeftAuth.Protocol do
  @moduledoc false
  @max_frame 4096

  def max_frame, do: @max_frame

  def build_version do
    Application.spec(:datadeft_auth, :vsn) |> to_string()
  end

  def request(id, operation) do
    data = Jason.encode!(%{version: 1, id: id, operation: operation, payload: %{}})
    <<byte_size(data)::unsigned-big-32, data::binary>>
  end

  # Raw stream framing checks the prefix before retaining an advertised body.
  # packet: 4 in the VM driver would allocate the body before our size check.
  def feed(buffer, chunk), do: frames(buffer <> chunk, [])

  defp frames(<<length::unsigned-big-32, _::binary>>, _acc)
       when length == 0 or length > @max_frame,
       do: {:error, :protocol}

  defp frames(<<length::unsigned-big-32, rest::binary>>, acc)
       when byte_size(rest) >= length do
    <<frame::binary-size(length), tail::binary>> = rest
    frames(tail, [frame | acc])
  end

  defp frames(buffer, acc), do: {:ok, Enum.reverse(acc), buffer}

  def reply(frame) when is_binary(frame) and byte_size(frame) in 1..@max_frame do
    with {:ok, decoded} <- Jason.decode(frame, objects: :ordered_objects),
         {:ok, envelope} <- object(decoded, ["version", "id", "result"]),
         %{"version" => 1, "id" => id, "result" => result} <- envelope,
         true <- is_integer(id) and id > 0 and id <= 0xFFFFFFFF,
         {:ok, result} <- result(result) do
      {:ok, id, result}
    else
      _ -> {:error, :protocol}
    end
  end

  def reply(_), do: {:error, :protocol}

  defp result(%Jason.OrderedObject{values: fields} = value) do
    case List.keyfind(fields, "operation", 0) do
      {"operation", "handshake"} ->
        with {:ok, result} <- object(value, ["operation", "build_version", "max_frame_bytes"]),
             %{"build_version" => version, "max_frame_bytes" => @max_frame} <- result,
             true <- version == build_version() do
          {:ok, :handshake}
        else
          _ -> {:error, :protocol}
        end

      {"operation", "ping"} ->
        case object(value, ["operation"]) do
          {:ok, _} -> {:ok, :ping}
          _ -> {:error, :protocol}
        end

      _ ->
        {:error, :protocol}
    end
  end

  defp result(_), do: {:error, :protocol}

  defp object(%Jason.OrderedObject{values: fields}, keys) do
    # Sorting preserves duplicate keys so they cannot be silently overwritten.
    if Enum.sort(Enum.map(fields, &elem(&1, 0))) == Enum.sort(keys) do
      {:ok, Map.new(fields)}
    else
      {:error, :protocol}
    end
  end

  defp object(_, _), do: {:error, :protocol}
end
