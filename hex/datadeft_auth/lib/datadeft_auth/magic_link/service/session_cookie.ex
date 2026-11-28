defmodule DatadeftAuth.MagicLink.Service.SessionCookie do
  @moduledoc """
  Rust-compatible session cookie framing and cryptographic validation.

  Opening a cookie does not authorize access. The service must also validate the
  country policy, live session, revocation and account status before use. The
  original issue time must be preserved on an authorized sliding refresh.
  """
  alias DatadeftAuth.MagicLink.Service.SessionId
  alias DatadeftAuth.Token.{BoundCookie, Keyring}

  @enforce_keys [:session_id, :country, :issued_at_unix, :last_activity_unix]
  defstruct [:session_id, :country, :issued_at_unix, :last_activity_unix]

  @type t :: %__MODULE__{
          session_id: SessionId.t(),
          country: String.t() | nil,
          issued_at_unix: non_neg_integer(),
          last_activity_unix: non_neg_integer()
        }

  @doc "Mint after service policy checks. The result is bearer material; never log it."
  @spec mint(Keyring.t(), SessionId.t(), String.t() | nil, non_neg_integer(), non_neg_integer()) ::
          {:ok, binary()} | {:error, atom()}
  def mint(%Keyring{purpose: :session} = ring, %SessionId{} = id, country, now, issued) do
    with {:ok, id} <- SessionId.parse(SessionId.value(id)),
         {:ok, country} <- encode_country(country) do
      value = SessionId.value(id)
      body = <<1, byte_size(value), value::binary, byte_size(country), country::binary>>
      BoundCookie.mint(body, ring, now, issued, now)
    else
      _ -> {:error, :invalid_input}
    end
  end

  def mint(_, _, _, _, _), do: {:error, :invalid_input}

  @doc "Authenticate framing and both age bounds (idle, absolute), not live session state."
  @spec open(Keyring.t(), binary(), non_neg_integer(), {non_neg_integer(), non_neg_integer()}) ::
          {:ok, t()} | {:error, :invalid_token}
  def open(%Keyring{purpose: :session} = ring, cookie, now, ages) do
    with {:ok, frame} <- BoundCookie.open(cookie, ring, now, ages),
         <<1, 68, id::binary-size(68), size, country::binary-size(size)>> <- frame.body,
         {:ok, id} <- SessionId.parse(id),
         {:ok, country} <- decode_country(country) do
      {:ok,
       %__MODULE__{
         session_id: id,
         country: country,
         issued_at_unix: frame.iat,
         last_activity_unix: frame.timestamp
       }}
    else
      _ -> {:error, :invalid_token}
    end
  end

  def open(_, _, _, _), do: {:error, :invalid_token}

  defp encode_country(nil), do: {:ok, ""}
  defp encode_country(<<a, b>> = country) when a in ?A..?Z and b in ?A..?Z, do: {:ok, country}
  defp encode_country(_), do: {:error, :invalid_input}

  defp decode_country(""), do: {:ok, nil}
  defp decode_country(country), do: encode_country(country)
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Service.SessionCookie do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Service.SessionCookie<redacted>"
end
