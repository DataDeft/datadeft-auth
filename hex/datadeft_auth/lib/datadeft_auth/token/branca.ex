defmodule DatadeftAuth.Token.Branca do
  @moduledoc """
  Bounded Branca primitives backed by the existing Rust token core.

  Low-level cryptographic authentication only: decode does NOT check freshness,
  purpose, key windows, account or session validity. Never authorize with its
  result alone. Cookie helpers must impose those checks.

  Inputs and outputs contain secrets; do not log or inspect them. Encoding uses
  an independent OS CSPRNG nonce per call. NIF calls run on dirty CPU schedulers.
  """
  alias DatadeftAuth.Native

  @spec encode(binary(), binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :invalid_input | :unavailable}
  def encode(payload, key, timestamp)
      when is_binary(payload) and byte_size(payload) <= 1024 and is_binary(key) and
             byte_size(key) == 32 and is_integer(timestamp) and timestamp in 0..4_294_967_295,
      do: Native.branca_encode(payload, key, timestamp)

  def encode(_, _, _), do: {:error, :invalid_input}

  @spec decode(binary(), binary()) ::
          {:ok, {non_neg_integer(), binary(), binary()}}
          | {:error, :invalid_token | :unavailable}
  def decode(token, key)
      when is_binary(token) and byte_size(token) <= 1437 and is_binary(key) and
             byte_size(key) == 32,
      do: Native.branca_decode(token, key)

  def decode(_, _), do: {:error, :invalid_token}
end
