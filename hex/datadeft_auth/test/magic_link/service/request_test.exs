defmodule DatadeftAuth.MagicLink.Service.RequestTest do
  use ExUnit.Case, async: true

  alias DatadeftAuth.MagicLink.Core.{Email, Lookup, LookupKey, Token}
  alias DatadeftAuth.MagicLink.Service.{LocaleAllowlist, Request}

  @now 1_780_000_000
  @email "alice+auth@example.test"

  defmodule Adapter do
    def check_rate_limit({pid, opts}, key, limit, window, now) do
      send(pid, {:limit, key, limit, window, now})

      Map.get(
        opts[:decisions] || %{},
        Enum.at(String.split(key, ":"), 1) <>
          ":" <> Enum.at(String.split(key, ":"), 3),
        {:ok, :allowed}
      )
    end

    def put_magic_link_if_absent({pid, opts}, record) do
      send(pid, {:persist, record})
      Keyword.get(opts, :persist, :ok)
    end

    def enqueue_magic_link({pid, opts}, email) do
      send(pid, {:deliver, email})
      Keyword.get(opts, :deliver, :ok)
    end
  end

  test "validates consent and address before clock, limits, storage or delivery" do
    {service, _} = service()
    assert Request.request(service, @email, false, true) == {:error, :bad_request}
    assert Request.request(service, @email, true, "true") == {:error, :bad_request}

    assert Request.request(service, "Alice <alice@example.test>", true, true) ==
             {:error, :bad_request}

    refute_received _
  end

  test "charges exact keyed budgets and persists one matching challenge before outbox" do
    {:ok, locales} = LocaleAllowlist.new("en", ["de-AT", "de-DE"])
    {service, key} = service(locales: locales)

    assert {:ok, :sent} =
             Request.request(service, " Alice+AUTH@EXAMPLE.TEST ", true, true, "DE_at")

    assert_receive :clock
    {:ok, email} = Email.normalize(@email)
    {:ok, email_hmac} = Lookup.email(key, email)
    suffix = Lookup.storage_value(email_hmac)

    for {bucket, limit, window} <- [
          {"request:email:short", 3, 900},
          {"request:email:daily", 10, 86_400},
          {"outbox:email:hourly", 3, 3600},
          {"outbox:email:daily", 10, 86_400}
        ] do
      rate_key = "magic-link:" <> bucket <> ":" <> suffix
      assert_receive {:limit, ^rate_key, ^limit, ^window, @now}
    end

    assert_receive {:persist, record}
    assert_receive {:deliver, message}
    assert record.email == email
    assert record.terms_version == "terms-1"
    assert record.privacy_version == "privacy-1"
    assert record.consented_at_unix == @now
    assert record.expires_at_unix == @now + 600
    assert record.consumed_at_unix == nil
    assert message.email == email
    assert message.expires_at_unix == record.expires_at_unix
    assert message.locale == "de-AT"
    assert {:ok, selector} = Lookup.selector(key, message.token)
    assert {:ok, verifier} = Lookup.verifier(key, message.token)
    assert Lookup.matches?(selector, record.selector_lookup_hmac)
    assert Lookup.matches?(verifier, record.verifier_hash)
    refute inspect(message) =~ Token.value(message.token)
    refute inspect(message) =~ @email
    refute inspect(service) =~ inspect(:binary.copy(<<0x55>>, 32))
  end

  test "all buckets charge on denial and a dependency failure overrides a denial" do
    decisions = %{"request:short" => {:ok, :denied}, "outbox:daily" => {:ok, :denied}}
    {service, _} = service(decisions: decisions)

    assert Request.request(service, @email, true, true) ==
             {:ok, {:throttled, :email_short_window}}

    for _ <- 1..4, do: assert_receive({:limit, _, _, _, @now})
    refute_received {:persist, _}
    refute_received {:deliver, _}

    {service, _} = service(decisions: Map.put(decisions, "outbox:hourly", {:error, :unavailable}))
    assert Request.request(service, @email, true, true) == {:error, :unavailable}
    for _ <- 1..4, do: assert_receive({:limit, _, _, _, @now})
    refute_received {:persist, _}
    refute_received {:deliver, _}
  end

  test "does not send if persistence fails; outbox outage is distinct" do
    {service, _} = service(persist: {:error, :conditional_write_failed})
    assert Request.request(service, @email, true, true) == {:error, :unavailable}
    assert_receive {:persist, _}
    refute_received {:deliver, _}

    {service, _} = service(deliver: {:error, :unavailable})
    assert Request.request(service, @email, true, true) == {:error, :outbox_unavailable}
    assert_receive {:persist, _}
    assert_receive {:deliver, %{locale: nil}}
  end

  test "locale allows only configured tags and ignores malformed or oversized request hints" do
    assert {:error, :invalid_locale_allowlist} = LocaleAllowlist.new("EN", [])
    assert {:error, :invalid_locale_allowlist} = LocaleAllowlist.new("en", ["en"])
    assert {:error, :invalid_locale_allowlist} = LocaleAllowlist.new("en", ["de-AT-extra"])
    assert {:ok, list} = LocaleAllowlist.new("en", ["de-AT", "de-DE"])
    assert LocaleAllowlist.resolve(list, "de-de") == "de-DE"
    assert LocaleAllowlist.resolve(list, "de_CH") == "de-AT"

    for hint <- ["de\nAT", "de-É", "de_" <> String.duplicate("a", 33), " DE ", nil] do
      {service, _} = service(locales: list)
      assert {:ok, :sent} = Request.request(service, @email, true, true, hint)
      assert_receive {:deliver, %{locale: "en"}}
    end
  end

  defp service(opts \\ []) do
    {:ok, key} = LookupKey.new(:binary.copy(<<0x55>>, 32))
    pid = self()
    io = {Adapter, {pid, opts}}

    clock = fn ->
      send(pid, :clock)
      {:ok, @now}
    end

    assert {:ok, service} =
             Request.new(
               key,
               {"terms-1", "privacy-1"},
               %{repository: io, limiter: io, outbox: io, clock: clock},
               Keyword.take(opts, [:locales])
             )

    {service, key}
  end
end
