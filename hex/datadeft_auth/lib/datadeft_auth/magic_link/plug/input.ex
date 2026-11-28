if Code.ensure_loaded?(Plug.Conn) do
  defmodule DatadeftAuth.MagicLink.Plug.Input do
    @moduledoc false

    import Plug.Conn, only: [get_req_header: 2, read_body: 2]

    @json "application/json"
    @form "application/x-www-form-urlencoded"
    @max_body 4096
    @max_query 768
    @max_cookie_fields 128
    @max_cookie_bytes 8192
    @max_cookie_value 4096
    @cookie_octets ~r/\A[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+\z/

    def request_body(conn) do
      case bounded_body(conn, [@json]) do
        {:ok, body, conn, @json} -> decode_request(conn, body)
        {:error, _, _} = error -> error
      end
    end

    def confirmation_body(conn) do
      case bounded_body(conn, [@json, @form]) do
        {:ok, body, conn, type} -> decode_confirmation(conn, body, type)
        {:error, _, _} = error -> error
      end
    end

    defp decode_request(conn, body) do
      with {:ok, fields} <- json_fields(body),
           email = fields["email"],
           terms = fields["terms_accepted"],
           privacy = fields["privacy_accepted"],
           locale = fields["locale"],
           true <- is_binary(email) and is_boolean(terms) and is_boolean(privacy),
           true <- is_nil(locale) or is_binary(locale),
           true <-
             map_size(fields) == 3 or (map_size(fields) == 4 and Map.has_key?(fields, "locale")) do
        {:ok, {email, terms, privacy, locale}, conn}
      else
        _ -> {:error, :bad_request, conn}
      end
    end

    defp decode_confirmation(conn, body, type) do
      with {:ok, %{"confirmation" => nonce} = fields} <- confirmation_fields(body, type),
           true <- map_size(fields) == 1 and is_binary(nonce) do
        {:ok, nonce, conn}
      else
        _ -> {:error, :bad_request, conn}
      end
    end

    def token(<<"token=", value::binary>> = query)
        when byte_size(query) <= @max_query and byte_size(value) > 0 do
      if Regex.match?(~r/\A[\x00-\x7F]+\z/, value) and
           :binary.match(value, ["&", "%", "="]) == :nomatch,
         do: value,
         else: ""
    end

    def token(_), do: ""

    def same_origin_post?(%{method: "POST"} = conn, origin) do
      get_req_header(conn, "origin") == [origin] and
        get_req_header(conn, "sec-fetch-site") in [[], ["same-origin"]]
    end

    def same_origin_post?(_, _), do: false

    def same_origin_fetch?(conn),
      do: get_req_header(conn, "sec-fetch-site") == ["same-origin"]

    def country(_, nil), do: nil

    def country(conn, header) do
      case get_req_header(conn, header) do
        [<<a, b>> = code] when a in ?A..?Z and b in ?A..?Z -> code
        _ -> nil
      end
    end

    def cookie(conn, name) do
      fields = get_req_header(conn, "cookie")

      if length(fields) <= @max_cookie_fields and
           Enum.reduce(fields, 0, &(byte_size(&1) + &2)) <= @max_cookie_bytes do
        fields
        |> Enum.reduce_while(nil, fn field, selected ->
          case select_pairs(:binary.split(field, ";", [:global]), name, selected) do
            :invalid -> {:halt, :invalid}
            next -> {:cont, next}
          end
        end)
        |> case do
          value when is_binary(value) -> {:ok, value}
          _ -> {:error, :invalid_cookie}
        end
      else
        {:error, :invalid_cookie}
      end
    end

    def cookie_value?(value) when is_binary(value) and byte_size(value) in 1..@max_cookie_value,
      do: Regex.match?(@cookie_octets, value)

    def cookie_value?(_), do: false

    defp select_pairs([], _, selected), do: selected

    defp select_pairs([pair | rest], name, selected) do
      # Rust trims SP and HTAB on the whole pair but not on either side of '='.
      pair = Regex.replace(~r/\A[ \t]+|[ \t]+\z/, pair, "")

      case :binary.split(pair, "=") do
        [^name, value] ->
          if is_nil(selected) and cookie_value?(value),
            do: select_pairs(rest, name, value),
            else: :invalid

        _ ->
          select_pairs(rest, name, selected)
      end
    end

    defp bounded_body(conn, allowed) do
      with {:ok, mime} <- content_type(conn, allowed),
           :ok <- content_length(conn) do
        case read_body(conn,
               length: @max_body + 1,
               read_length: @max_body + 1,
               read_timeout: 5_000
             ) do
          {:ok, body, next} when byte_size(body) in 1..@max_body -> {:ok, body, next, mime}
          {:ok, "", next} -> {:error, :bad_request, next}
          {status, _, next} when status in [:ok, :more] -> {:error, :payload_too_large, next}
          {:error, _} -> {:error, :bad_request, conn}
        end
      else
        {:error, reason} -> {:error, reason, conn}
      end
    end

    defp content_type(conn, allowed) do
      case get_req_header(conn, "content-type") do
        [type] ->
          [mime | _] = :binary.split(type, ";")
          mime = mime |> String.trim() |> String.downcase(:ascii)

          if mime in allowed,
            do: {:ok, mime},
            else: {:error, :unsupported_media_type}

        _ ->
          {:error, :unsupported_media_type}
      end
    end

    defp content_length(conn) do
      case get_req_header(conn, "content-length") do
        [] ->
          :ok

        [value] when byte_size(value) <= 20 ->
          case Integer.parse(value) do
            {size, ""} when size in 0..@max_body -> :ok
            {size, ""} when size > @max_body -> {:error, :payload_too_large}
            _ -> {:error, :bad_request}
          end

        _ ->
          {:error, :bad_request}
      end
    end

    defp json_fields(body) do
      case Jason.decode(body, objects: :ordered_objects) do
        {:ok, %Jason.OrderedObject{values: pairs}} ->
          fields = Map.new(pairs)
          if map_size(fields) == length(pairs), do: {:ok, fields}, else: :error

        _ ->
          :error
      end
    end

    defp confirmation_fields(body, @json), do: json_fields(body)

    defp confirmation_fields(body, @form) do
      with [pair] <- :binary.split(body, "&", [:global, :trim_all]),
           [key, value] <- :binary.split(pair, "=") do
        {:ok, %{URI.decode_www_form(key) => URI.decode_www_form(value)}}
      else
        _ -> :error
      end
    rescue
      ArgumentError -> :error
    end
  end
end
