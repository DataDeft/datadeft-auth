defmodule DatadeftAuth.Connection do
  @moduledoc false
  use GenServer
  alias DatadeftAuth.{Error, Protocol}

  @typep pending_request ::
           %{from: nil, monitor: nil, timer: reference()}
           | %{from: GenServer.from(), monitor: reference(), timer: reference()}

  # The uint32 maximum plus one is an exhausted-ID sentinel, never a wire ID.
  @typep next_id :: 1..0x100000000
  @typep state(id) :: %{
           port: port() | nil,
           ready: boolean(),
           buffer: Protocol.buffer(),
           pending: %{optional(Protocol.request_id()) => pending_request()},
           next_id: id,
           executable: String.t() | nil,
           timeout: 1..60_000,
           max_pending: 1..1024,
           restart_delay: 1..5000,
           backoff: 1..5000
         }

  @typep state :: state(next_id())

  @typep call_result ::
           {:reply, DatadeftAuth.status_result(), state()} | {:noreply, state()}

  # Default and inclusive upper limit per integer option; :name and
  # :executable are validated separately.
  @int_options [
    request_timeout: {1000, 60_000},
    max_pending: {32, 1024},
    restart_delay: {100, 5000}
  ]
  @defaults Enum.map(@int_options, fn {key, {default, _limit}} -> {key, default} end)
  @allowed [:name, :executable] ++ Keyword.keys(@int_options)
  # Reconnect backoff doubles up to the highest configurable restart delay.
  @backoff_limit @int_options |> Keyword.fetch!(:restart_delay) |> elem(1)

  @spec start_link(DatadeftAuth.options()) :: GenServer.on_start()
  def start_link(opts) do
    if valid_options?(opts) do
      GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
    else
      {:error, %Error{code: :configuration}}
    end
  end

  @impl true
  @spec init(DatadeftAuth.options()) :: {:ok, state()}
  def init(opts) do
    Process.flag(:trap_exit, true)

    opts = Keyword.merge(@defaults, opts)
    restart_delay = Keyword.fetch!(opts, :restart_delay)

    state = %{
      port: nil,
      ready: false,
      buffer: <<>>,
      pending: %{},
      next_id: 1,
      executable: Keyword.get(opts, :executable, default_executable()),
      timeout: Keyword.fetch!(opts, :request_timeout),
      max_pending: Keyword.fetch!(opts, :max_pending),
      restart_delay: restart_delay,
      backoff: restart_delay
    }

    send(self(), :connect)
    {:ok, state}
  end

  @impl true
  @spec handle_call(:status, GenServer.from(), state()) :: call_result()
  def handle_call(:status, _from, %{ready: false} = state),
    do: {:reply, error(:unavailable), state}

  def handle_call(:status, from, state) do
    cond do
      map_size(state.pending) >= state.max_pending ->
        {:reply, error(:overloaded), state}

      state.next_id > 0xFFFFFFFF ->
        {:reply, error(:unavailable), disconnect(state, :unavailable)}

      true ->
        case send_request(state, "ping", from) do
          {:ok, state} -> {:noreply, state}
          :error -> {:reply, error(:unavailable), disconnect(state, :unavailable)}
        end
    end
  end

  @impl true
  @spec handle_info(term(), state()) :: {:noreply, state()}
  def handle_info(:connect, %{port: nil} = state) do
    case open(state.executable) do
      {:ok, port} ->
        state = %{state | port: port, buffer: <<>>, ready: false, next_id: 1}

        case send_request(state, "handshake", nil) do
          {:ok, state} -> {:noreply, state}
          :error -> {:noreply, disconnect(state, :unavailable)}
        end

      :error ->
        {:noreply, schedule_restart(state)}
    end
  end

  def handle_info({port, {:data, chunk}}, %{port: port} = state) do
    case Protocol.feed(state.buffer, chunk) do
      {:ok, frames, buffer} ->
        case replies(frames, %{state | buffer: buffer}) do
          {:ok, state} -> {:noreply, state}
          {:error, state} -> {:noreply, disconnect(state, :protocol)}
        end

      _ ->
        {:noreply, disconnect(state, :protocol)}
    end
  end

  def handle_info({:deadline, port, id}, %{port: port} = state) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        {:noreply, state}

      {%{from: nil}, _} ->
        {:noreply, disconnect(state, :timeout)}

      {pending, rest} ->
        finish(pending, error(:timeout))
        {:noreply, %{state | pending: rest}}
    end
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    pending =
      Enum.reduce(state.pending, %{}, fn {id, item}, acc ->
        if item.monitor == monitor do
          Process.cancel_timer(item.timer)
          acc
        else
          Map.put(acc, id, item)
        end
      end)

    {:noreply, %{state | pending: pending}}
  end

  def handle_info({port, {:exit_status, _}}, %{port: port} = state),
    do: {:noreply, disconnect(state, :unavailable)}

  def handle_info({port, :eof}, %{port: port} = state),
    do: {:noreply, disconnect(state, :unavailable)}

  def handle_info({:EXIT, port, _}, %{port: port} = state),
    do: {:noreply, disconnect(state, :unavailable)}

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  @spec terminate(term(), state()) :: :ok
  def terminate(_, state) do
    close(state.port)
    Enum.each(state.pending, fn {_, pending} -> finish(pending, error(:unavailable)) end)
    :ok
  end

  # OTP 25+ invokes this callback, but Elixir only declares it since 1.17.
  # Keep redaction on every supported OTP without an unknown-callback warning.
  @impl {:format_status, 1} in GenServer.behaviour_info(:callbacks)
  @spec format_status(:gen_server.format_status()) :: :gen_server.format_status()
  def format_status(status) do
    Map.new(status, fn
      {:log, _} -> {:log, []}
      {key, _} when key in [:state, :message, :reason] -> {key, :redacted}
      entry -> entry
    end)
  end

  @spec replies([Protocol.frame()], state()) :: {:ok, state()} | {:error, state()}
  defp replies(frames, state) do
    Enum.reduce_while(frames, {:ok, state}, fn frame, {:ok, state} ->
      case reply(frame, state) do
        {:ok, state} -> {:cont, {:ok, state}}
        _ -> {:halt, {:error, state}}
      end
    end)
  end

  @spec reply(Protocol.frame(), state()) :: {:ok, state()} | :error
  defp reply(frame, state) do
    with {:ok, id, result} <- Protocol.reply(frame),
         true <- id < state.next_id do
      case Map.pop(state.pending, id) do
        # Late/cancelled read-only request; never reused.
        {nil, _} ->
          {:ok, state}

        {%{from: nil} = pending, rest} when result == :handshake ->
          finish(pending, :ok)
          {:ok, %{state | ready: true, pending: rest, backoff: state.restart_delay}}

        {%{from: from} = pending, rest} when from != nil and result == :ping ->
          finish(pending, {:ok, :transport_ready})
          {:ok, %{state | pending: rest}}

        _ ->
          :error
      end
    else
      _ -> :error
    end
  end

  @spec send_request(state(Protocol.request_id()), Protocol.operation(), GenServer.from() | nil) ::
          {:ok, state()} | :error
  defp send_request(state, operation, from) do
    id = state.next_id
    # nosuspend avoids blocking the GenServer on a busy OS pipe.
    if Port.command(state.port, Protocol.request(id, operation), [:nosuspend]) do
      monitor = if from, do: Process.monitor(elem(from, 0)), else: nil
      timer = Process.send_after(self(), {:deadline, state.port, id}, state.timeout)
      pending = %{from: from, timer: timer, monitor: monitor}
      {:ok, %{state | pending: Map.put(state.pending, id, pending), next_id: id + 1}}
    else
      :error
    end
  rescue
    ArgumentError -> :error
  end

  @spec disconnect(state(), Error.code()) :: state()
  defp disconnect(state, code) do
    close(state.port)
    Enum.each(state.pending, fn {_, pending} -> finish(pending, error(code)) end)
    schedule_restart(%{state | port: nil, ready: false, pending: %{}, buffer: <<>>})
  end

  @spec schedule_restart(state()) :: state()
  defp schedule_restart(state) do
    Process.send_after(self(), :connect, state.backoff)
    %{state | backoff: min(state.backoff * 2, @backoff_limit)}
  end

  @spec finish(pending_request(), DatadeftAuth.status_result() | :ok) :: :ok | nil
  defp finish(pending, result) do
    Process.cancel_timer(pending.timer)
    if pending.monitor, do: Process.demonitor(pending.monitor, [:flush])
    if pending.from, do: GenServer.reply(pending.from, result)
  end

  @spec open(String.t() | nil) :: {:ok, port()} | :error
  defp open(path) do
    {:ok,
     Port.open(
       {:spawn_executable, String.to_charlist(path)},
       [
         :binary,
         :stream,
         :use_stdio,
         :exit_status,
         :eof,
         :hide,
         {:busy_limits_port, {4096, 8192}},
         {:busy_limits_msgq, {4096, 8192}}
       ]
     )}
  rescue
    _ -> :error
  end

  @spec close(port() | nil) :: true | :ok
  defp close(nil), do: :ok

  defp close(port) do
    Port.close(port)
  rescue
    ArgumentError -> :ok
  end

  @spec default_executable() :: String.t()
  defp default_executable do
    :code.priv_dir(:datadeft_auth) |> to_string() |> Path.join("datadeft-auth-port")
  end

  @spec valid_options?(term()) :: boolean()
  defp valid_options?(opts) when is_list(opts) do
    Keyword.keyword?(opts) and valid_keys?(Keyword.keys(opts)) and
      Enum.all?(@int_options, fn {key, {default, limit}} ->
        value = Keyword.get(opts, key, default)
        is_integer(value) and value > 0 and value <= limit
      end) and valid_path?(Keyword.get(opts, :executable)) and valid_name?(opts)
  end

  defp valid_options?(_), do: false

  @spec valid_keys?([atom()]) :: boolean()
  defp valid_keys?(keys), do: Enum.all?(keys, &(&1 in @allowed)) and keys == Enum.uniq(keys)

  @spec valid_name?(keyword()) :: boolean()
  defp valid_name?(opts) do
    case Keyword.fetch(opts, :name) do
      :error -> true
      {:ok, name} -> is_atom(name) and name != nil
    end
  end

  @spec valid_path?(term()) :: boolean()
  defp valid_path?(nil), do: true

  defp valid_path?(path) when is_binary(path),
    do: Path.type(path) == :absolute and not String.contains?(path, <<0>>)

  defp valid_path?(_), do: false

  @spec error(Error.code()) :: {:error, Error.t()}
  defp error(code), do: {:error, %Error{code: code}}
end
