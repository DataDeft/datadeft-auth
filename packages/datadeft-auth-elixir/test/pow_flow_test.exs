defmodule DatadeftAuthPowFlowTest do
  use ExUnit.Case, async: false
  import DatadeftAuth.TestSupport
  alias DatadeftAuth.{Error, PowChallenge, PowVerification}

  defp start_with_pow(pow) do
    config = Map.put(fake_config(), :pow, pow)
    pid = start_supervised!({DatadeftAuth, [config: config]})
    ready(pid)
    pid
  end

  # Mirrors the shipping browser client: decimal nonces into
  # hex(SHA-256(chg <> non)) until `dif` leading zero hex characters appear.
  defp solve(%PowChallenge{chg: chg, dif: dif}) do
    target = String.duplicate("0", dif)

    Stream.iterate(0, &(&1 + 1))
    |> Enum.find_value(fn nonce ->
      non = Integer.to_string(nonce)
      sol = Base.encode16(:crypto.hash(:sha256, chg <> non), case: :lower)
      String.starts_with?(sol, target) && {sol, non}
    end)
  end

  test "a solved challenge is admitted exactly its per-solve budget and is redacted" do
    pid = start_with_pow(%{difficulty: 1, proof_budget_per_solve: 2})

    assert {:ok, %PowChallenge{dif: 1} = challenge} = DatadeftAuth.pow_challenge(pid)
    {sol, non} = solve(challenge)

    solution = %{
      "chg" => challenge.chg,
      "sol" => sol,
      "non" => non,
      "tim" => challenge.tim,
      "tag" => challenge.tag
    }

    # Every failed verification check is one uniform refusal.
    assert {:ok, %PowVerification{admitted: false, proof_cookie: nil}} =
             DatadeftAuth.pow_verify(pid, %{solution | "sol" => String.duplicate("f", 64)})

    assert {:ok, %PowVerification{admitted: true, proof_cookie: cookie} = verification} =
             DatadeftAuth.pow_verify(pid, solution)

    # The bearer proof value never appears in Inspect output.
    refute inspect(verification) =~ cookie

    # One solve buys exactly its per-solve budget over the proof's lifetime.
    assert {:ok, %{admitted: true}} = DatadeftAuth.pow_admit(pid, cookie)
    assert {:ok, %{admitted: true}} = DatadeftAuth.pow_admit(pid, cookie)
    assert {:ok, %{admitted: false}} = DatadeftAuth.pow_admit(pid, cookie)
    # A garbage cookie is the same uniform refusal, never an error detail.
    assert {:ok, %{admitted: false}} = DatadeftAuth.pow_admit(pid, "garbage")
  end

  test "a client-echoed dif is dropped and malformed solutions are refused locally" do
    pid = start_with_pow(%{difficulty: 1, proof_budget_per_solve: 1})
    assert {:ok, challenge} = DatadeftAuth.pow_challenge(pid)
    {sol, non} = solve(challenge)

    # Atom keys and the echoed dif are what a Phoenix controller holds after
    # decoding the client's JSON; both are accepted.
    solution = %{
      chg: challenge.chg,
      sol: sol,
      non: non,
      dif: challenge.dif,
      tim: challenge.tim,
      tag: challenge.tag
    }

    assert {:ok, %PowVerification{admitted: true}} = DatadeftAuth.pow_verify(pid, solution)

    for malformed <- [
          Map.put(solution, :extra, "x"),
          Map.delete(solution, :sol),
          %{solution | non: 7}
        ] do
      assert {:error, %Error{code: :bad_request}} = DatadeftAuth.pow_verify(pid, malformed)
    end

    # Local refusals consume nothing; the transport stays ready.
    assert {:ok, :transport_ready} = DatadeftAuth.status(pid)
  end

  test "without the pow key every pow operation is a configuration error" do
    pid = start_supervised!({DatadeftAuth, [config: fake_config()]})
    ready(pid)

    assert {:error, %Error{code: :configuration}} = DatadeftAuth.pow_challenge(pid)
    assert {:error, %Error{code: :configuration}} = DatadeftAuth.pow_admit(pid, "anything")
  end

  test "an out-of-range pow policy is a refused configuration at startup" do
    config = Map.put(fake_config(), :pow, %{difficulty: 0, proof_budget_per_solve: 2})
    pid = start_supervised!({DatadeftAuth, [config: config, restart_delay: 5000]})

    Process.sleep(300)
    assert Process.alive?(pid)
    assert {:error, %Error{code: :unavailable}} = DatadeftAuth.status(pid)
  end
end
