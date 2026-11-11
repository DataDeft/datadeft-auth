defmodule DatadeftAuth.Connection do
  @moduledoc false
  use GenServer
  alias DatadeftAuth.{Error, Protocol}

  # Default and inclusive upper limit per integer option; :name and
  # :executable are validated separately. The public bound types in
  # DatadeftAuth mirror these limits (typespecs cannot reference attributes).
  @restart_delay_limit 5000
  @int_options [
    request_timeout: {1000, 60_000},
    max_pending: {32, 1024},
    restart_delay: {100, @restart_delay_limit}
  ]
  @defaults Enum.map(@int_options, fn {key, {default, _limit}} -> {key, default} end)
  @allowed [:name, :executable, :config] ++ Keyword.keys(@int_options)

  @typep pending_request ::
           %{operation: Protocol.operation(), from: nil, monitor: nil, timer: reference()}
           | %{
               operation: Protocol.operation(),
               from: GenServer.from(),
               monitor: reference(),
               timer: reference()
             }

  # The uint32 maximum plus one is an exhausted-ID sentinel, never a wire ID.
  @typep next_id :: 1..0x100000000
  @typep state :: %{
           port: port() | nil,
           ready: boolean(),
           buffer: Protocol.buffer(),
           pending: %{optional(Protocol.request_id()) => pending_request()},
           next_id: next_id(),
           executable: String.t(),
           config: map() | nil,
           timeout: DatadeftAuth.request_timeout(),
           max_pending: DatadeftAuth.max_pending(),
           restart_delay: DatadeftAuth.restart_delay(),
           backoff: DatadeftAuth.restart_delay()
         }

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
      # An explicit nil selects the bundled default, same as omitting the key.
      executable: Keyword.get(opts, :executable) || default_executable(),
      config: Keyword.get(opts, :config),
      timeout: Keyword.fetch!(opts, :request_timeout),
      max_pending: Keyword.fetch!(opts, :max_pending),
      restart_delay: restart_delay,
      backoff: restart_delay
    }

    send(self(), :connect)
    {:ok, state}
  end

  @impl true
  @spec handle_call(:status, GenServer.from(), state()) ::
          {:reply, DatadeftAuth.status_result(), state()} | {:noreply, state()}
  def handle_call(:status, _from, %{ready: false} = state),
    do: {:reply, error(:unavailable), state}

  def handle_call(:status, from, state), do: admit(state, :ping, %{}, from)

  # Authentication operations need the initialized executable: without a
  # config the transport is health-only by design.
  def handle_call({:auth, _operation, _payload}, _from, %{config: nil} = state),
    do: {:reply, error(:configuration), state}

  def handle_call({:auth, _operation, _payload}, _from, %{ready: false} = state),
    do: {:reply, error(:unavailable), state}

  def handle_call({:auth, operation, payload}, from, state),
    do: admit(state, operation, payload, from)

  @spec admit(state(), Protocol.operation(), map(), GenServer.from()) ::
          {:reply, {:error, Error.t()}, state()} | {:noreply, state()}
  defp admit(state, operation, payload, from) do
    cond do
      map_size(state.pending) >= state.max_pending ->
        {:reply, error(:overloaded), state}

      state.next_id > Protocol.max_request_id() ->
        {:reply, error(:unavailable), disconnect(state, :unavailable)}

      true ->
        case send_request(state, operation, payload, from) do
          {:ok, state} -> {:noreply, state}
          :busy -> {:reply, error(:overloaded), state}
          :too_large -> {:reply, error(:bad_request), state}
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

        case send_request(state, :handshake, %{}, nil) do
          {:ok, state} -> {:noreply, state}
          # A fresh pipe should never be busy; treat it like any send failure.
          _ -> {:noreply, disconnect(state, :unavailable)}
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
          {:disconnect, code, state} -> {:noreply, disconnect(state, code)}
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

  @spec replies([Protocol.frame()], state()) ::
          {:ok, state()} | {:disconnect, Error.code(), state()}
  defp replies(frames, state) do
    Enum.reduce_while(frames, {:ok, state}, fn frame, {:ok, state} ->
      case reply(frame, state) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:disconnect, code} -> {:halt, {:disconnect, code, state}}
      end
    end)
  end

  @spec reply(Protocol.frame(), state()) :: {:ok, state()} | {:disconnect, Error.code()}
  defp reply(frame, state) do
    with {:ok, id, result} <- Protocol.reply(frame),
         true <- id < state.next_id do
      case Map.pop(state.pending, id) do
        # Late/cancelled read-only request; never reused.
        {nil, _} ->
          {:ok, state}

        {%{from: nil, operation: :handshake} = pending, rest} when result == :handshake ->
          finish(pending, :ok)
          handshaken(%{state | pending: rest, backoff: state.restart_delay})

        {%{from: nil, operation: :init} = pending, rest} ->
          finish(pending, :ok)

          case result do
            :init -> {:ok, %{state | ready: true, pending: rest}}
            # A refused configuration cannot heal by itself; the bounded
            # restart loop keeps the owner alive while the app is fixed.
            {:error, _code} -> {:disconnect, :configuration}
            _ -> {:disconnect, :protocol}
          end

        {%{from: from, operation: operation} = pending, rest} when from != nil ->
          case deliver(operation, result) do
            {:ok, value} ->
              finish(pending, value)
              {:ok, %{state | pending: rest}}

            :error ->
              {:disconnect, :protocol}
          end

        _ ->
          {:disconnect, :protocol}
      end
    else
      _ -> {:disconnect, :protocol}
    end
  end

  # Readiness: transport-only connections are ready at handshake; configured
  # connections only once the executable accepted the initialization.
  @spec handshaken(state()) :: {:ok, state()} | {:disconnect, Error.code()}
  defp handshaken(%{config: nil} = state), do: {:ok, %{state | ready: true}}

  defp handshaken(state) do
    case send_request(state, :init, state.config, nil) do
      {:ok, state} -> {:ok, state}
      :too_large -> {:disconnect, :configuration}
      _ -> {:disconnect, :unavailable}
    end
  end

  # Route a reply to its caller: the echoed operation must match the pending
  # one; a per-request failure keeps the connection up.
  @spec deliver(Protocol.operation(), Protocol.result()) ::
          {:ok, DatadeftAuth.status_result() | {:ok, term()}} | :error
  defp deliver(:ping, :ping), do: {:ok, {:ok, :transport_ready}}
  defp deliver(operation, {operation, value}), do: {:ok, {:ok, value}}
  defp deliver(_operation, {:error, code}), do: {:ok, error(code)}
  defp deliver(_, _), do: :error

  # The exhausted-ID sentinel is never sent; this fails closed if a caller
  # skips the admit guard. A busy pipe or oversized payload consumes no ID.
  @spec send_request(state(), Protocol.operation(), map(), GenServer.from() | nil) ::
          {:ok, state()} | :busy | :too_large | :error
  defp send_request(state, operation, payload, from) do
    id = state.next_id
    frame = Protocol.request(id, operation, payload)

    cond do
      id > Protocol.max_request_id() ->
        :error

      byte_size(frame) > Protocol.max_frame() + 4 ->
        :too_large

      # nosuspend avoids blocking the GenServer on a busy OS pipe; a full
      # pipe rejects only this request instead of dropping the connection.
      Port.command(state.port, frame, [:nosuspend]) ->
        monitor = if from, do: Process.monitor(elem(from, 0)), else: nil
        timer = Process.send_after(self(), {:deadline, state.port, id}, state.timeout)
        pending = %{operation: operation, from: from, timer: timer, monitor: monitor}
        {:ok, %{state | pending: Map.put(state.pending, id, pending), next_id: id + 1}}

      true ->
        :busy
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
    %{state | backoff: min(state.backoff * 2, @restart_delay_limit)}
  end

  @spec finish(pending_request(), DatadeftAuth.status_result() | :ok) :: :ok | nil
  defp finish(pending, result) do
    Process.cancel_timer(pending.timer)
    if pending.monitor, do: Process.demonitor(pending.monitor, [:flush])
    if pending.from, do: GenServer.reply(pending.from, result)
  end

  @spec open(String.t()) :: {:ok, port()} | :error
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

  defp close(nil), do: :ok

  defp close(port) do
    Port.close(port)
  rescue
    ArgumentError -> :ok
  end

  defp default_executable do
    :code.priv_dir(:datadeft_auth) |> to_string() |> Path.join("datadeft-auth-port")
  end

  @spec valid_options?(term()) :: boolean()
  defp valid_options?(opts) when is_list(opts) do
    Keyword.keyword?(opts) and valid_keys?(Keyword.keys(opts)) and
      Enum.all?(@int_options, fn {key, {default, limit}} ->
        value = Keyword.get(opts, key, default)
        is_integer(value) and value > 0 and value <= limit
      end) and valid_path?(Keyword.get(opts, :executable)) and valid_name?(opts) and
      valid_config?(Keyword.get(opts, :config))
  end

  defp valid_options?(_), do: false

  # The executable validates the configuration's content fail-closed; here we
  # only require the shape that makes the init frame sendable at all. nil
  # keeps the transport health-only.
  defp valid_config?(nil), do: true

  defp valid_config?(config) when is_map(config) do
    match?(%{mode: mode} when mode in [:fake, :aws], config) and
      case Jason.encode(config) do
        {:ok, encoded} -> byte_size(encoded) <= Protocol.max_frame() - 128
        _ -> false
      end
  end

  defp valid_config?(_), do: false

  defp valid_keys?(keys), do: Enum.all?(keys, &(&1 in @allowed)) and keys == Enum.uniq(keys)

  # A nil name is any-atom-valid and GenServer treats it as unregistered.
  defp valid_name?(opts) do
    case Keyword.fetch(opts, :name) do
      :error -> true
      {:ok, name} -> is_atom(name)
    end
  end

  defp valid_path?(nil), do: true

  defp valid_path?(path) when is_binary(path),
    do: Path.type(path) == :absolute and not String.contains?(path, <<0>>)

  defp valid_path?(_), do: false

  defp error(code), do: {:error, %Error{code: code}}
end
