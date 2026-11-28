if Code.ensure_loaded?(Plug.Conn) do
  defmodule DatadeftAuth.MagicLink.Plug.Config do
    @moduledoc false

    @defaults [
      insecure_local: false,
      country_header: nil,
      confirm_page: "/auth/magic-link/confirm",
      after_sign_in: "/auth/magic-link/complete",
      after_logout: "/"
    ]

    def validate(origin, opts) do
      with true <- Keyword.keyword?(opts),
           {:ok, opts} <- Keyword.validate(opts, @defaults),
           local when is_boolean(local) <- opts[:insecure_local],
           true <- valid_origin?(origin, local),
           true <- header?(opts[:country_header]),
           true <-
             Enum.all?([:confirm_page, :after_sign_in, :after_logout], &safe_path?(opts[&1])) do
        {:ok, Map.new(opts)}
      else
        _ -> {:error, :invalid_config}
      end
    end

    defp valid_origin?(origin, local) when is_binary(origin) and byte_size(origin) <= 270 do
      case Regex.run(~r/\A(https?):\/\/([a-z0-9.-]+)(?::([0-9]{1,5}))?\z/, origin) do
        [_, scheme, host] ->
          valid_host?(host) and valid_scheme?(scheme, host, local)

        [_, scheme, host, port] ->
          valid_host?(host) and valid_scheme?(scheme, host, local) and valid_port?(port, scheme)

        _ ->
          false
      end
    end

    defp valid_origin?(_, _), do: false

    defp valid_scheme?("https", _, false), do: true
    defp valid_scheme?("http", host, true) when host in ["127.0.0.1", "localhost"], do: true
    defp valid_scheme?(_, _, _), do: false

    defp valid_host?(host) when byte_size(host) <= 253 do
      labels = :binary.split(host, ".", [:global])

      if Regex.match?(~r/\A[0-9.]+\z/, host) do
        length(labels) == 4 and Enum.all?(labels, &canonical_number?(&1, 0..255))
      else
        Enum.all?(labels, &Regex.match?(~r/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/, &1))
      end
    end

    defp valid_host?(_), do: false

    defp valid_port?(value, scheme) do
      canonical_number?(value, 1..65_535) and
        {value, scheme} not in [{"80", "http"}, {"443", "https"}]
    end

    defp canonical_number?(value, range) do
      case Integer.parse(value) do
        {n, ""} -> n in range and Integer.to_string(n) == value
        _ -> false
      end
    end

    defp header?(nil), do: true

    defp header?(name) when is_binary(name) and byte_size(name) in 1..128,
      do: Regex.match?(~r/\A[a-z][a-z0-9-]*\z/, name)

    defp header?(_), do: false

    # Fixed paths, never user input. Restrict to an unescaped absolute path
    # without a query, fragment, dot segment or token (which contains dots).
    defp safe_path?(path) when is_binary(path) and byte_size(path) in 1..2048,
      do: Regex.match?(~r|\A/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]*\z|, path)

    defp safe_path?(_), do: false
  end
end
