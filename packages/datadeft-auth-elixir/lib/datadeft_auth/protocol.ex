defmodule DatadeftAuth.Protocol do
  @moduledoc false
  alias DatadeftAuth.{
    DevMagicLink,
    FlowState,
    Landing,
    PowChallenge,
    PowVerification,
    Session,
    Validation
  }

  @max_frame 16384
  @max_request_id 0xFFFFFFFF

  # Typespecs cannot reference module attributes; the literals mirror them.
  @typedoc "Nonzero uint32 wire ID, never reused within one Port connection."
  @type request_id :: 1..0xFFFFFFFF

  @typedoc "Closed operation set; encoded as strings on the wire."
  @type operation ::
          :handshake
          | :ping
          | :init
          | :request_link
          | :landing
          | :flow_state
          | :confirm
          | :validate_session
          | :logout
          | :fake_last_magic_link
          | :pow_challenge
          | :pow_verify
          | :pow_admit

  # Per-request application failures the executable may reply instead of a
  # success result; protocol faults never use this shape.
  @error_codes %{
    "overloaded" => :overloaded,
    "configuration" => :configuration,
    "bad_request" => :bad_request,
    "rejected" => :rejected,
    "unavailable" => :unavailable,
    "internal" => :internal
  }

  @typedoc "Reply result: the echoed operation with its value, or a failure."
  @type result ::
          :handshake
          | :ping
          | :init
          | {:request_link, String.t()}
          | {:landing, Landing.t()}
          | {:flow_state, FlowState.t()}
          | {:confirm, Session.t()}
          | {:validate_session, Validation.t()}
          | {:logout, boolean()}
          | {:fake_last_magic_link, DevMagicLink.t()}
          | {:pow_challenge, PowChallenge.t()}
          | {:pow_verify, PowVerification.t()}
          | {:pow_admit, boolean()}
          | {:error,
             :overloaded | :configuration | :bad_request | :rejected | :unavailable | :internal}

  @type failure :: {:error, :protocol}

  @typedoc "JSON body without its four-byte length prefix; validated at the boundary."
  @type frame :: binary()

  @typedoc "An incomplete prefix or body retained between raw Port chunks."
  @type buffer :: binary()

  @type feed_result :: {:ok, [frame()], buffer()} | failure()

  @spec max_frame() :: 16384
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

  @spec request(request_id(), operation(), map()) :: binary()
  def request(id, operation, payload \\ %{}) do
    data = Jason.encode!(%{version: 1, id: id, operation: operation, payload: payload})
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
      {"operation", operation} -> result(operation, value)
      _ -> {:error, :protocol}
    end
  end

  defp result(_), do: {:error, :protocol}

  defp result("handshake", value) do
    with {:ok, result} <- object(value, ["operation", "build_version", "max_frame_bytes"]),
         %{"build_version" => version, "max_frame_bytes" => @max_frame} <- result,
         true <- version == build_version() do
      {:ok, :handshake}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("ping", value) do
    case object(value, ["operation"]) do
      {:ok, _} -> {:ok, :ping}
      _ -> {:error, :protocol}
    end
  end

  defp result("init", value) do
    case object(value, ["operation"]) do
      {:ok, _} -> {:ok, :init}
      _ -> {:error, :protocol}
    end
  end

  defp result("request_link", value) do
    with {:ok, result} <- object(value, ["operation", "reason"]),
         %{"reason" => reason} when is_binary(reason) <- result do
      {:ok, {:request_link, reason}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("landing", value) do
    with {:ok, result} <-
           object(value, [
             "operation",
             "usable",
             "confirm_cookie",
             "confirmation",
             "account",
             "cookie_max_age_secs"
           ]) do
      case result do
        %{
          "usable" => true,
          "confirm_cookie" => cookie,
          "confirmation" => confirmation,
          "account" => account,
          "cookie_max_age_secs" => max_age
        }
        when is_binary(cookie) and is_binary(confirmation) and is_binary(account) and
               is_integer(max_age) and max_age >= 0 ->
          {:ok,
           {:landing,
            %Landing{
              usable: true,
              confirm_cookie: cookie,
              confirmation: confirmation,
              account: account,
              cookie_max_age_secs: max_age
            }}}

        %{
          "usable" => false,
          "confirm_cookie" => nil,
          "confirmation" => nil,
          "account" => nil,
          "cookie_max_age_secs" => nil
        } ->
          {:ok, {:landing, %Landing{usable: false}}}

        _ ->
          {:error, :protocol}
      end
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("flow_state", value) do
    with {:ok, result} <- object(value, ["operation", "usable", "account", "confirmation"]) do
      case result do
        %{"usable" => true, "account" => account, "confirmation" => confirmation}
        when is_binary(account) and is_binary(confirmation) ->
          {:ok,
           {:flow_state, %FlowState{usable: true, account: account, confirmation: confirmation}}}

        %{"usable" => false, "account" => nil, "confirmation" => nil} ->
          {:ok, {:flow_state, %FlowState{usable: false}}}

        _ ->
          {:error, :protocol}
      end
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("confirm", value) do
    with {:ok, result} <-
           object(value, ["operation", "session_cookie", "user_id", "user_created", "country"]),
         %{
           "session_cookie" => cookie,
           "user_id" => user_id,
           "user_created" => created,
           "country" => country
         }
         when is_binary(cookie) and is_binary(user_id) and is_boolean(created) and
                (is_binary(country) or is_nil(country)) <- result do
      {:ok,
       {:confirm,
        %Session{
          session_cookie: cookie,
          user_id: user_id,
          user_created: created,
          country: country
        }}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("validate_session", value) do
    with {:ok, result} <-
           object(value, ["operation", "valid", "user_id", "refreshed_cookie"]) do
      case result do
        %{"valid" => true, "user_id" => user_id, "refreshed_cookie" => refreshed}
        when is_binary(user_id) and (is_binary(refreshed) or is_nil(refreshed)) ->
          {:ok,
           {:validate_session,
            %Validation{valid: true, user_id: user_id, refreshed_cookie: refreshed}}}

        %{"valid" => false, "user_id" => nil, "refreshed_cookie" => nil} ->
          {:ok, {:validate_session, %Validation{valid: false}}}

        _ ->
          {:error, :protocol}
      end
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("logout", value) do
    with {:ok, result} <- object(value, ["operation", "revoked"]),
         %{"revoked" => revoked} when is_boolean(revoked) <- result do
      {:ok, {:logout, revoked}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("fake_last_magic_link", value) do
    with {:ok, result} <-
           object(value, ["operation", "found", "magic_link_url", "expires_at_unix"]) do
      case result do
        %{"found" => true, "magic_link_url" => url, "expires_at_unix" => expires}
        when is_binary(url) and is_integer(expires) and expires >= 0 ->
          {:ok,
           {:fake_last_magic_link,
            %DevMagicLink{found: true, magic_link_url: url, expires_at_unix: expires}}}

        %{"found" => false, "magic_link_url" => nil, "expires_at_unix" => nil} ->
          {:ok, {:fake_last_magic_link, %DevMagicLink{found: false}}}

        _ ->
          {:error, :protocol}
      end
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("pow_challenge", value) do
    with {:ok, result} <- object(value, ["operation", "chg", "dif", "tim", "tag"]),
         %{"chg" => chg, "dif" => dif, "tim" => tim, "tag" => tag}
         when is_binary(chg) and is_integer(dif) and dif in 1..64 and is_binary(tim) and
                is_binary(tag) <- result do
      {:ok, {:pow_challenge, %PowChallenge{chg: chg, dif: dif, tim: tim, tag: tag}}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("pow_verify", value) do
    with {:ok, result} <-
           object(value, ["operation", "admitted", "proof_cookie", "mint_to_verify_ms"]) do
      case result do
        %{"admitted" => true, "proof_cookie" => cookie, "mint_to_verify_ms" => delta}
        when is_binary(cookie) and ((is_integer(delta) and delta >= 0) or is_nil(delta)) ->
          {:ok,
           {:pow_verify,
            %PowVerification{admitted: true, proof_cookie: cookie, mint_to_verify_ms: delta}}}

        %{"admitted" => false, "proof_cookie" => nil, "mint_to_verify_ms" => nil} ->
          {:ok, {:pow_verify, %PowVerification{admitted: false}}}

        _ ->
          {:error, :protocol}
      end
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("pow_admit", value) do
    with {:ok, result} <- object(value, ["operation", "admitted"]),
         %{"admitted" => admitted} when is_boolean(admitted) <- result do
      {:ok, {:pow_admit, admitted}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result("error", value) do
    with {:ok, result} <- object(value, ["operation", "code"]),
         %{"code" => code} <- result,
         {:ok, code} <- Map.fetch(@error_codes, code) do
      {:ok, {:error, code}}
    else
      _ -> {:error, :protocol}
    end
  end

  defp result(_, _), do: {:error, :protocol}

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
