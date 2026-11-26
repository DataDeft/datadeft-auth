defmodule DatadeftAuth.Native do
  @moduledoc false
  use Rustler,
    otp_app: :datadeft_auth,
    crate: "datadeft_auth_nif",
    path: "native/datadeft_auth_nif",
    mode: :release,
    load_from: {:datadeft_auth, "priv/native/datadeft_auth_nif"}

  # Load failure never selects another crypto implementation.
  def branca_encode(_payload, _key, _timestamp), do: :erlang.nif_error(:nif_not_loaded)
  def branca_decode(_token, _key), do: :erlang.nif_error(:nif_not_loaded)
end
