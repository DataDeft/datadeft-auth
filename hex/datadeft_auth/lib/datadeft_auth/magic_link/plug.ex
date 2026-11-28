if Code.ensure_loaded?(Plug.Conn) do
  defmodule DatadeftAuth.MagicLink.Plug do
    @moduledoc """
    Optional Plug helpers over the Rust-compatible magic-link services. The
    application owns routing, rendering, a trusted edge and request admission
    (including any PoW). Mount the body-reading helpers before global body
    parsers. Keep confirmation and flow-state routes under /auth.

    Endpoints send and halt the connection, except successful authenticate/2,
    which returns a no-store connection ready for the app to render. A fixed,
    secret-free reason is available in conn.private[:datadeft_auth_reason].
    Never log the connection, URL query, headers, bodies or cookie values.
    """
    import Plug.Conn
    alias DatadeftAuth.MagicLink.Core.ConfirmCookie
    alias DatadeftAuth.MagicLink.Plug.{Config, Input}
    alias DatadeftAuth.MagicLink.Service.{Flow, Request, Session, SessionRecord}

    @bad_request ~s({"error":"bad_request","message":"Invalid request."})
    @unavailable ~s({"error":"unavailable","message":"The service is temporarily unavailable. Try again later."})
    @unauthorized ~s({"error":"unauthorized","message":"Sign in again."})
    @confirm "dd_auth_confirm"
    @session "dd_session"
    @security_headers [
      {"cache-control", "no-store"},
      {"referrer-policy", "strict-origin"},
      {"x-frame-options", "DENY"},
      {"content-security-policy",
       "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}
    ]

    @enforce_keys [:request, :flow, :session, :origin, :opts, :idle]
    defstruct [:request, :flow, :session, :origin, :opts, :idle]
    @opaque t :: %__MODULE__{}

    @doc """
    Combine matching services and require one canonical public HTTPS origin
    for unsafe requests. Options: :confirm_page, :after_sign_in and
    :after_logout (fixed absolute paths only); :insecure_local for explicit
    loopback HTTP; :country_header only when a trusted edge overwrites it and
    direct origin access is blocked. Country binding is off by default.
    """
    @spec new(binary(), Request.t(), Flow.t(), Session.t(), keyword()) ::
            {:ok, t()} | {:error, :invalid_config}
    def new(origin, request, flow, session, opts \\ [])

    def new(
          origin,
          %Request{} = request,
          %Flow{} = flow,
          %Session{ages: {idle, absolute}} = session,
          opts
        ) do
      with {:ok, opts} <- Config.validate(origin, opts),
           true <- flow.policy.session_absolute == absolute,
           true <- flow.policy.country_policy == session.country_policy,
           true <- request.ttl == flow.policy.magic_link_ttl and request.versions == flow.versions do
        {:ok,
         %__MODULE__{
           origin: origin,
           request: request,
           flow: flow,
           session: session,
           opts: opts,
           idle: idle
         }}
      else
        _ -> {:error, :invalid_config}
      end
    end

    def new(_, _, _, _, _), do: {:error, :invalid_config}

    @doc "Handle POST JSON request. Sent and throttled produce the same public 200."
    @spec request(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def request(%Plug.Conn{method: "POST"} = conn, %__MODULE__{} = config) do
      case Input.request_body(conn) do
        {:ok, {email, terms, privacy, locale}, conn} ->
          case Request.request(config.request, email, terms, privacy, locale) do
            {:ok, :sent} ->
              conn |> reason("magic_link_request_sent") |> json(200, ~s({"status":"ok"}))

            {:ok, {:throttled, bucket}} ->
              conn
              |> reason("magic_link_request_throttled_" <> Atom.to_string(bucket))
              |> json(200, ~s({"status":"ok"}))

            {:error, cause} ->
              refusal(conn, cause)
          end

        {:error, cause, conn} ->
          refusal(conn, cause)
      end
    end

    def request(conn, %__MODULE__{}), do: refusal(conn, :bad_request)

    @doc """
    Scanner-safe GET. Redirect usable and unusable links to the same static
    path, without reflecting the token. Rejected GETs never clear existing flow.
    """
    @spec open(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def open(%Plug.Conn{method: "GET"} = conn, %__MODULE__{} = config) do
      case land(conn, config) do
        {:ok, conn, _} ->
          redirect(conn, config.opts.confirm_page)

        {:error, :magic_link_unavailable} ->
          conn
          |> security_headers()
          |> reason("magic_link_unusable")
          |> redirect(config.opts.confirm_page)

        {:error, cause} ->
          conn |> security_headers() |> refusal(cause)
      end
    end

    def open(conn, %__MODULE__{}), do: conn |> security_headers() |> refusal(:bad_request)

    @doc """
    Server-rendered alternative to open/2. The renderer receives the account
    label and nonce; it must HTML-escape both and present a same-origin POST
    form. The helper adds no-store/framing/referrer protections and the cookie.
    """
    @spec landing(Plug.Conn.t(), t(), (binary(), binary() -> iodata())) :: Plug.Conn.t()
    def landing(%Plug.Conn{method: "GET"} = conn, %__MODULE__{} = config, render)
        when is_function(render, 2) do
      case land(conn, config) do
        {:ok, conn, result} ->
          page = render.(result.account, ConfirmCookie.confirmation(result.flow))
          conn |> put_resp_content_type("text/html") |> finish(200, page)

        {:error, :magic_link_unavailable} ->
          conn
          |> security_headers()
          |> reason("magic_link_unusable")
          |> put_resp_content_type("text/html")
          |> finish(
            200,
            "<!doctype html><h1>Unable to continue sign in</h1><p>Request a new link.</p>"
          )

        {:error, cause} ->
          conn |> security_headers() |> refusal(cause)
      end
    end

    def landing(conn, %__MODULE__{}, _), do: conn |> security_headers() |> refusal(:bad_request)

    @doc "Scanner-safe, same-origin GET for the account and independent confirmation value."
    @spec flow_state(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def flow_state(conn, %__MODULE__{} = config) do
      conn =
        conn
        |> security_headers()
        |> put_resp_header("cross-origin-resource-policy", "same-origin")

      if conn.method == "GET" and Input.same_origin_fetch?(conn) do
        with {:ok, cookie} <- Input.cookie(conn, @confirm),
             {:ok, state} <- Flow.read_state(config.flow, cookie),
             {:ok, body} <-
               Jason.encode(
                 Jason.OrderedObject.new(
                   usable: true,
                   account: state.account,
                   confirmation: state.confirmation
                 )
               ) do
          json(conn, 200, body)
        else
          {:error, error} when error in [:invalid_cookie, :magic_link_unavailable] ->
            conn |> clear(config, :confirm) |> reason("magic_link_unusable") |> unusable()

          {:error, :internal} ->
            conn |> clear(config, :confirm) |> refusal(:internal)

          {:error, :unavailable} ->
            refusal(conn, :unavailable)

          _ ->
            refusal(conn, :internal)
        end
      else
        conn |> reason("magic_link_same_origin_required") |> unusable()
      end
    end

    @doc "Only a same-origin POST may consume a link. Redirect after committing, using a fixed path."
    @spec confirm(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def confirm(conn, %__MODULE__{} = config) do
      conn = security_headers(conn)

      if Input.same_origin_post?(conn, config.origin) do
        case Input.cookie(conn, @confirm) do
          {:ok, cookie} -> confirm_body(conn, config, cookie)
          {:error, _} -> confirmation_error(conn, config, :magic_link_unavailable)
        end
      else
        conn |> reason("magic_link_same_origin_required") |> invalid_confirmation()
      end
    end

    @doc """
    Authenticate and, if due, refresh a live session. A failed refresh doesn't
    end a valid session. Success returns the updated unsent connection and the
    authoritative record. Failure returns a sent and halted 401 or 503.
    """
    @spec authenticate(Plug.Conn.t(), t()) ::
            {:ok, Plug.Conn.t(), SessionRecord.t()} | {:error, Plug.Conn.t()}
    def authenticate(conn, %__MODULE__{} = config) do
      conn = security_headers(conn)

      with {:ok, cookie} <- Input.cookie(conn, @session),
           {:ok, validated} <- Session.validate(config.session, cookie, country(conn, config)) do
        {:ok, refresh(conn, config, validated), Session.record(validated)}
      else
        {:error, error} -> {:error, session_refusal(conn, config, error)}
      end
    end

    @doc "Only a same-origin POST may revoke. Do not clear a live session cookie when revocation fails."
    @spec logout(Plug.Conn.t(), t()) :: Plug.Conn.t()
    def logout(conn, %__MODULE__{} = config) do
      conn = security_headers(conn)

      if Input.same_origin_post?(conn, config.origin) do
        with {:ok, cookie} <- Input.cookie(conn, @session),
             {:ok, record} <- Session.validate_for_logout(config.session, cookie) do
          case Session.revoke(config.session, record.session_id) do
            :ok -> conn |> clear(config, :session) |> redirect(config.opts.after_logout)
            {:error, cause} -> session_refusal(conn, config, cause)
          end
        else
          {:error, cause} -> session_refusal(conn, config, cause)
        end
      else
        refusal(conn, :bad_request)
      end
    end

    @doc "Apply the default no-store, strict-origin and no-framing headers to an unsent auth response."
    @spec security_headers(Plug.Conn.t()) :: Plug.Conn.t()
    def security_headers(conn), do: merge_resp_headers(conn, @security_headers)

    defp land(conn, config) do
      with {:ok, result} <- Flow.land(config.flow, Input.token(conn.query_string)),
           {:ok, conn} <-
             set_cookie(
               security_headers(conn),
               config,
               :confirm,
               ConfirmCookie.cookie_value(result.flow),
               result.cookie_max_age_secs
             ) do
        {:ok, conn, result}
      end
    end

    defp confirm_body(conn, config, cookie) do
      case Input.confirmation_body(conn) do
        {:ok, nonce, conn} ->
          case Flow.confirm(config.flow, cookie, nonce, country(conn, config)) do
            {:ok, result} ->
              case set_cookie(conn, config, :session, result.session_cookie, config.idle) do
                {:ok, conn} ->
                  conn |> clear(config, :confirm) |> redirect(config.opts.after_sign_in)

                {:error, cause} ->
                  confirmation_error(conn, config, cause)
              end

            {:error, cause} ->
              confirmation_error(conn, config, cause)
          end

        {:error, cause, conn} ->
          confirmation_error(conn, config, cause)
      end
    end

    defp confirmation_error(conn, config, cause) do
      conn =
        if Flow.temporary_state_action(cause) == :clear,
          do: clear(conn, config, :confirm),
          else: conn

      if shape_error?(cause) do
        conn |> reason(http_reason(cause)) |> invalid_confirmation()
      else
        refusal(conn, cause)
      end
    end

    defp invalid_confirmation(conn),
      do: conn |> put_resp_content_type("text/html") |> finish(400, "Invalid confirmation.")

    defp unusable(conn), do: json(conn, 200, ~s({"usable":false}))

    defp refresh(conn, config, validated) do
      case Session.refresh(config.session, validated) do
        {:ok, nil} ->
          conn

        {:ok, fresh} ->
          case set_cookie(conn, config, :session, fresh, config.idle) do
            {:ok, updated} -> updated
            {:error, _} -> reason(conn, "session_refresh_internal")
          end

        {:error, :unavailable} ->
          reason(conn, "session_refresh_unavailable")

        {:error, :invalid_session} ->
          reason(conn, "session_refresh_stale")

        {:error, _} ->
          reason(conn, "session_refresh_internal")
      end
    end

    defp session_refusal(conn, config, invalid)
         when invalid in [:invalid_cookie, :invalid_session] do
      conn
      |> clear(config, :session)
      |> reason("session_invalid")
      |> put_resp_header("www-authenticate", "DD-Session")
      |> json(401, @unauthorized)
    end

    defp session_refusal(conn, _, :unavailable),
      do: conn |> reason("session_unavailable") |> json(503, @unavailable)

    defp session_refusal(conn, _, _),
      do: conn |> reason("session_internal") |> json(503, @unavailable)

    defp country(conn, config), do: Input.country(conn, config.opts.country_header)

    defp set_cookie(conn, config, kind, value, age)
         when (kind == :confirm and age in 1..300) or (kind == :session and age in 1..2_592_000) do
      if Input.cookie_value?(value),
        do: {:ok, cookie_header(conn, config, kind, value, age, "")},
        else: {:error, :internal}
    end

    defp set_cookie(_, _, _, _, _), do: {:error, :internal}

    defp clear(conn, config, kind),
      do: cookie_header(conn, config, kind, "", 0, "; Expires=Thu, 01 Jan 1970 00:00:00 GMT")

    defp cookie_header(conn, config, kind, value, age, expires) do
      {name, path} = if kind == :confirm, do: {@confirm, "/auth"}, else: {@session, "/"}
      secure = if config.opts.insecure_local, do: "", else: "; Secure"

      header =
        "#{name}=#{value}; Path=#{path}; HttpOnly#{secure}; SameSite=Lax; Max-Age=#{age}#{expires}"

      prepend_resp_headers(conn, [{"set-cookie", header}])
    end

    defp refusal(conn, cause) do
      conn = reason(conn, http_reason(cause))

      if shape_error?(cause),
        do: json(conn, 400, @bad_request),
        else: json(conn, 503, @unavailable)
    end

    defp shape_error?(cause),
      do:
        cause in [
          :bad_request,
          :unsupported_media_type,
          :payload_too_large,
          :magic_link_unavailable
        ]

    defp http_reason(:bad_request), do: "magic_link_bad_request"
    defp http_reason(:unsupported_media_type), do: "magic_link_unsupported_media_type"
    defp http_reason(:payload_too_large), do: "magic_link_payload_too_large"
    defp http_reason(:magic_link_unavailable), do: "magic_link_unusable"
    defp http_reason(:unavailable), do: "magic_link_dependency_unavailable"
    defp http_reason(:outbox_unavailable), do: "magic_link_outbox_unavailable"
    defp http_reason(_), do: "magic_link_internal"

    defp reason(conn, label), do: put_private(conn, :datadeft_auth_reason, label)
    defp redirect(conn, path), do: conn |> put_resp_header("location", path) |> finish(303, "")

    defp json(conn, status, body) do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("content-type", "application/json")
      |> finish(status, body)
    end

    defp finish(conn, status, body), do: conn |> send_resp(status, body) |> halt()
  end

  defimpl Inspect, for: DatadeftAuth.MagicLink.Plug do
    def inspect(_, _), do: "#DatadeftAuth.MagicLink.Plug<redacted>"
  end
end
