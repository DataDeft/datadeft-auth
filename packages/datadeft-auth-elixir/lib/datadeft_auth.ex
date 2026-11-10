defmodule DatadeftAuth do
  @moduledoc """
  Framework-independent authentication using a supervised, separate Rust process.

  This first infrastructure packet implements process startup and health only.
  Authentication, AWS configuration and key initialization are not implemented yet.
  A healthy transport does not mean authentication is configured or available.

  Add `{DatadeftAuth, name: MyAuth}` to your application's supervision tree.
  Native work never runs inside BEAM. No request is automatically replayed after
  a timeout or worker failure.
  """

  alias DatadeftAuth.{Connection, Error}

  @typedoc "Transport options. Executable paths are trusted deployment configuration."
  @type option ::
          {:name, atom()}
          | {:executable, String.t() | nil}
          | {:request_timeout, 1..60_000}
          | {:max_pending, 1..1024}
          | {:restart_delay, 1..5000}

  @typedoc "Optional transport settings; duplicate and unknown keys are rejected."
  @type options :: [option()]

  @typedoc "Transport health only, not authentication or AWS readiness."
  @type status_result :: {:ok, :transport_ready} | {:error, Error.t()}

  @doc "Starts the transport owner. Readiness is asynchronous and checked with status/1."
  @spec start_link() :: GenServer.on_start()
  @spec start_link(options()) :: GenServer.on_start()
  def start_link(opts \\ []), do: Connection.start_link(opts)

  @doc false
  @spec child_spec(options()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Checks transport health only; returns a fixed diagnostic error when unavailable."
  @spec status(GenServer.server()) :: status_result()
  def status(server) do
    GenServer.call(server, :status, :infinity)
  catch
    :exit, _ -> {:error, %Error{code: :unavailable}}
  end
end
