defmodule BanditMagicLink do
  @moduledoc false
  use Application

  alias BanditMagicLink.{Mailbox, Memory, Router}
  alias DatadeftAuth.MagicLink.Core.LookupKey
  alias DatadeftAuth.MagicLink.Plug, as: Web
  alias DatadeftAuth.MagicLink.Service.{Flow, Request, Session}
  alias DatadeftAuth.Token.Keyring

  @impl true
  def start(_type, _args) do
    with {:ok, port} <- port() do
      origin = "http://127.0.0.1:#{port}"

      with {:ok, mailbox} <- Mailbox.create(origin) do
        start_demo(port, origin, mailbox)
      end
    end
  end

  @impl true
  def stop(mailbox) do
    Mailbox.remove(mailbox)
    :ok
  end

  defp start_demo(port, origin, mailbox) do
    case build_web(origin, mailbox) do
      {:ok, web} ->
        children = [
          Memory,
          {Bandit,
           plug: {Router, {web, port}},
           scheme: :http,
           ip: {127, 0, 0, 1},
           port: port,
           startup_log: false}
        ]

        case Supervisor.start_link(children, strategy: :one_for_all) do
          {:ok, pid} ->
            IO.puts("Listening: " <> origin)
            IO.puts("Private mailbox: " <> Mailbox.path(mailbox))
            {:ok, pid, mailbox}

          {:error, _} ->
            startup_failure(mailbox)
        end

      {:error, _} ->
        startup_failure(mailbox)
    end
  end

  defp startup_failure(mailbox) do
    Mailbox.remove(mailbox)
    {:error, :demo_start_failed}
  end

  defp build_web(origin, mailbox) do
    now = System.system_time(:second)
    mint_until = now + 86_400
    clock = fn -> {:ok, System.system_time(:second)} end
    repo = {Memory, Memory}
    io = %{repository: repo, limiter: repo, outbox: {Mailbox, mailbox}, clock: clock}
    consent = {"demo-terms-v1", "demo-privacy-v1"}

    with {:ok, lookup} <- LookupKey.new(:crypto.strong_rand_bytes(32)),
         {:ok, confirm} <- Keyring.new(:confirm, [slot("demo_confirm", mint_until, 300)]),
         {:ok, session} <- Keyring.new(:session, [slot("demo_session", mint_until, 2_592_000)]),
         {:ok, request} <- Request.new(lookup, consent, io),
         {:ok, flow} <- Flow.new(lookup, {confirm, session}, consent, io),
         {:ok, sessions} <- Session.new(session, repo, clock) do
      Web.new(origin, request, flow, sessions, insecure_local: true)
    end
  end

  defp slot(id, mint_until, retention) do
    {:active, id, :crypto.strong_rand_bytes(32), mint_until, mint_until + retention}
  end

  defp port do
    case Integer.parse(System.get_env("PORT", "4000")) do
      {port, ""} when port in 1024..65_535 -> {:ok, port}
      _ -> {:error, :invalid_demo_port}
    end
  end
end
