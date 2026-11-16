defmodule DatadeftAuthConfirmationOutcomeTest do
  use ExUnit.Case, async: false
  import DatadeftAuth.TestSupport
  alias DatadeftAuth.Error

  test "a lost confirmation reply is not replayed after reconnect" do
    executable = fake(:confirm_crash)
    marker = Path.join(Path.dirname(executable), "confirms")

    pid =
      start_supervised!(
        {DatadeftAuth,
         [executable: executable, config: fake_config(), request_timeout: 2000, restart_delay: 30]}
      )

    ready(pid)
    previous = os_pid(pid)

    assert {:error, %Error{code: :unavailable}} =
             DatadeftAuth.confirm(pid, "fixture-flow", "fixture-confirmation")

    eventually(fn ->
      DatadeftAuth.status(pid) == {:ok, :transport_ready} and os_pid(pid) != previous
    end)

    # Further calls and a fresh init must not resubmit the mutating request.
    for _ <- 1..5, do: assert(DatadeftAuth.status(pid) == {:ok, :transport_ready})
    assert File.read!(marker) == "1"
    assert :sys.get_state(pid).pending == %{}
    refute_receive {_, {:ok, %DatadeftAuth.Session{}}}
  end

  test "a confirmation after its deadline is discarded, not delivered or replayed" do
    executable = fake(:confirm_late)
    marker = Path.join(Path.dirname(executable), "confirms")

    pid =
      start_supervised!(
        {DatadeftAuth,
         [executable: executable, config: fake_config(), request_timeout: 600, restart_delay: 30]}
      )

    ready(pid)
    previous = os_pid(pid)

    assert {:error, %Error{code: :timeout}} =
             DatadeftAuth.confirm(pid, "fixture-flow", "fixture-confirmation")

    assert :sys.get_state(pid).pending == %{}
    # The fixture finishes after 900 ms; this ping queues behind that reply.
    # A mismatched late reply must not satisfy the ping or restart the child.
    assert {:ok, :transport_ready} = DatadeftAuth.status(pid)
    assert os_pid(pid) == previous
    assert File.read!(marker) == "1"
    assert :sys.get_state(pid).pending == %{}
    refute_receive {_, {:ok, %DatadeftAuth.Session{}}}
  end
end
