defmodule DatadeftAuth.Protocol do
  @moduledoc false
  @max_frame 4096
  @max_request_id 0xFFFFFFFF

  # Typespecs cannot reference module attributes; the literals mirror them.
  @typedoc "Nonzero uint32 wire ID, never reused within one Port connection."
  @type request_id :: 1..0xFFFFFFFF

  @typedoc "Closed operation set; encoded as strings on the wire."
  @type operation :: :handshake | :ping

  @typedoc "Reply result; the wire echoes the closed request operation set."
  @type result :: operation()
  @type failure :: {:error, :protocol}

  @typedoc "JSON body without its four-byte length prefix; validated at the boundary."
  @type frame :: binary()

  @typedoc "An incomplete prefix or body retained between raw Port chunks."
  @type buffer :: binary()

  @type feed_result :: {:ok, [frame()], buffer()} | failure()

  @spec max_frame() :: 4096
  def max_frame, do: @max_frame

  @spec max_request_id() :: 0xFFFFFFFF
  def max_request_id, do: @max_request_id

  @spec build_version() :: String.t()
  def build_version do
    # Releases and scripts may call before the application is loaded; without
    # this the version would read as "" and every handshake would fail closed.
    case Application.load(:datadeft_auth) do
      :ok -> :ok
      {:error, {:already_loaded, :datadeft_auth}} -> :ok
    end

    Application.spec(:datadeft_auth, :vsn) |> to_string()
  end

  @spec request(request_id(), operation()) :: binary()
  def request(id, operation) do
    data = Jason.encode!(%{version: 1, id: id, operation: operation, payload: %{}})
    <<byte_size(data)::unsigned-big-32, data::binary>>
  end

  # Raw stream framing checks the prefix before retaining an advertised body.
  # packet: 4 in the VM driver would allocate the body before our size check.
  @spec feed(buffer(), binary()) :: feed_result()
  def feed(buffer, chunk), do: frames(buffer <> chunk, [])

  @spec frames(binary(), [frame()]) :: feed_result()
  defp frames(<<length::unsigned-big-32, _::binary>>, _acc)
       when length == 0 or length > @max_frame,
       do: {:error, :protocol}

  defp frames(<<length::unsigned-big-32, rest::binary>>, acc)
       when byte_size(rest) >= length do
    <<frame::binary-size(length), tail::binary>> = rest
    frames(tail, [frame | acc])
  end

  defp frames(buffer, acc), do: {:ok, Enum.reverse(acc), buffer}

  @spec reply(term()) :: {:ok, request_id(), result()} | failure()
  def reply(frame) when is_binary(frame) and byte_size(frame) in 1..@max_frame do
    with {:ok, decoded} <- Jason.decode(frame, objects: :ordered_objects),
         {:ok, envelope} <- object(decoded, ["version", "id", "result"]),
         %{"version" => 1, "id" => id, "result" => result} <- envelope,
         true <- is_integer(id) and id > 0 and id <= @max_request_id,
         {:ok, result} <- result(result) do
      {:ok, id, result}
    else
      _ -> {:error, :protocol}
    end
  end

  def reply(_), do: {:error, :protocol}

  @spec result(term()) :: {:ok, result()} | failure()
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

  @spec object(term(), [String.t()]) :: {:ok, %{String.t() => term()}} | failure()
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
