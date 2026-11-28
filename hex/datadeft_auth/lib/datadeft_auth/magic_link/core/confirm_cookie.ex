defmodule DatadeftAuth.MagicLink.Core.ConfirmCookie do
  @moduledoc """
  Rust-compatible scanner-safe flow cookie with role-bound selector, verifier and
  account hashes, explicit expiry, and a separate confirmation nonce.

  The service must also bind the cookie to live challenge/account state and
  enforce same-origin POST before committing authentication. Reading a cookie
  is only for rendering flow state; it must never consume the challenge.
  """
  alias DatadeftAuth.MagicLink.Core.Lookup
  alias DatadeftAuth.Token.{BoundCookie, Keyring}

  @max_age 300
  @max_time 4_294_967_295

  defmodule Minted do
    @moduledoc false
    @enforce_keys [:cookie, :nonce]
    defstruct [:cookie, :nonce]
    @opaque t :: %__MODULE__{cookie: binary(), nonce: binary()}
  end

  @enforce_keys [:selector, :verifier, :account, :expires_at_unix, :nonce]
  defstruct [:selector, :verifier, :account, :expires_at_unix, :nonce]

  @type t :: %__MODULE__{
          selector: Lookup.t(),
          verifier: Lookup.t(),
          account: Lookup.t(),
          expires_at_unix: non_neg_integer(),
          nonce: binary()
        }
  @type bindings :: {Lookup.t(), Lookup.t(), Lookup.t()}
  @type entropy :: (pos_integer() -> {:ok, binary()} | {:error, term()})

  @doc """
  Mint bound flow state. Entropy must be an independent CSPRNG draw in production.
  The caller must cap expiry by the challenge's remaining lifetime.
  """
  @spec mint(Keyring.t(), bindings(), non_neg_integer(), non_neg_integer(), entropy()) ::
          {:ok, Minted.t()} | {:error, atom()}
  def mint(
        %Keyring{purpose: :confirm} = ring,
        {%Lookup{kind: :selector, bytes: <<_::256>> = selector},
         %Lookup{kind: :verifier, bytes: <<_::256>> = verifier},
         %Lookup{kind: :email, bytes: <<_::256>> = account}},
        expiry,
        now,
        entropy
      )
      when is_function(entropy, 1) do
    if is_integer(expiry) and expiry in 0..@max_time and is_integer(now) and
         now in 0..@max_time and expiry >= now and expiry <= now + @max_age do
      with {:ok, nonce} <- draw_nonce(entropy),
           body =
             <<1, selector::binary, verifier::binary, account::binary, nonce::binary, expiry::32>>,
           {:ok, cookie} <- BoundCookie.mint(body, ring, now, now, now) do
        {:ok, %Minted{cookie: cookie, nonce: nonce}}
      end
    else
      {:error, :invalid_timestamp}
    end
  end

  def mint(_, _, _, _, _), do: {:error, :invalid_input}

  @doc "Explicit bearer cookie access for the HTTP adapter. Do not log."
  @spec cookie_value(Minted.t()) :: binary()
  def cookie_value(%Minted{cookie: cookie}), do: cookie

  @doc "Canonical confirmation for the same-origin page or POST. Do not log."
  @spec confirmation(Minted.t() | t()) :: binary()
  def confirmation(%Minted{nonce: nonce}), do: Base.encode16(nonce, case: :lower)
  def confirmation(%__MODULE__{nonce: nonce}), do: Base.encode16(nonce, case: :lower)

  @doc "Open fresh flow state for rendering without consuming the challenge."
  @spec read(Keyring.t(), binary(), non_neg_integer(), pos_integer()) ::
          {:ok, t()} | {:error, :invalid_token}
  def read(%Keyring{purpose: :confirm} = ring, cookie, now, max_age)
      when is_integer(max_age) and max_age in 1..@max_age do
    with {:ok, frame} <- BoundCookie.open(cookie, ring, now, {max_age, max_age}),
         <<1, selector::binary-size(32), verifier::binary-size(32), account::binary-size(32),
           nonce::binary-size(32), expiry::32>> <- frame.body,
         true <- expiry >= frame.iat and expiry >= now and expiry <= frame.iat + max_age do
      {:ok,
       %__MODULE__{
         selector: %Lookup{kind: :selector, bytes: selector},
         verifier: %Lookup{kind: :verifier, bytes: verifier},
         account: %Lookup{kind: :email, bytes: account},
         expires_at_unix: expiry,
         nonce: nonce
       }}
    else
      _ -> {:error, :invalid_token}
    end
  end

  def read(_, _, _, _), do: {:error, :invalid_token}

  @doc "Open fresh flow state and check the exact, separately submitted nonce."
  @spec verify(Keyring.t(), binary(), binary(), non_neg_integer(), pos_integer()) ::
          {:ok, t()} | {:error, :invalid_token}
  def verify(ring, cookie, confirmation, now, max_age)
      when is_binary(confirmation) and byte_size(confirmation) == 64 do
    with {:ok, submitted} <- Base.decode16(confirmation, case: :lower),
         {:ok, state} <- read(ring, cookie, now, max_age),
         true <- :crypto.hash_equals(submitted, state.nonce) do
      {:ok, state}
    else
      _ -> {:error, :invalid_token}
    end
  end

  def verify(_, _, _, _, _), do: {:error, :invalid_token}

  defp draw_nonce(entropy) do
    case entropy.(32) do
      {:ok, <<_::256>> = nonce} -> {:ok, nonce}
      _ -> {:error, :entropy_unavailable}
    end
  end
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.ConfirmCookie do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.ConfirmCookie<redacted>"
end

defimpl Inspect, for: DatadeftAuth.MagicLink.Core.ConfirmCookie.Minted do
  def inspect(_, _), do: "#DatadeftAuth.MagicLink.Core.ConfirmCookie.Minted<redacted>"
end
