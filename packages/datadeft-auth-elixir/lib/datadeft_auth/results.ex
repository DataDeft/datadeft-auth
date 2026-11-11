# Public result structs. Every field holding bearer or secret material is
# excluded from Inspect so values cannot leak through logs or crash reports.

defmodule DatadeftAuth.Landing do
  @moduledoc """
  Scanner-safe landing outcome. `confirm_cookie` is the temporary flow
  state the application stores client-side (HttpOnly cookie); `confirmation`
  is the value the confirmation page submits. Both are secrets and are
  redacted in `Inspect`. The answer shape is uniform for every unusable link.
  """
  @derive {Inspect, except: [:confirm_cookie, :confirmation]}
  @enforce_keys [:usable]
  defstruct [:usable, :confirm_cookie, :confirmation, :account, :cookie_max_age_secs]

  @typedoc "Usable landings carry the flow secrets; unusable ones carry nothing."
  @type t :: %__MODULE__{
          usable: boolean(),
          confirm_cookie: String.t() | nil,
          confirmation: String.t() | nil,
          account: String.t() | nil,
          cookie_max_age_secs: non_neg_integer() | nil
        }
end

defmodule DatadeftAuth.FlowState do
  @moduledoc """
  Read-only flow state for redirect-landing pages. On `usable: false` the
  application clears its confirm cookie. `confirmation` is redacted.
  """
  @derive {Inspect, except: [:confirmation]}
  @enforce_keys [:usable]
  defstruct [:usable, :account, :confirmation]

  @type t :: %__MODULE__{
          usable: boolean(),
          account: String.t() | nil,
          confirmation: String.t() | nil
        }
end

defmodule DatadeftAuth.Session do
  @moduledoc """
  Successful confirmation outcome. `session_cookie` is the bearer session
  value (set it HttpOnly, Secure, with the configured lifetimes) and is
  redacted in `Inspect`.
  """
  @derive {Inspect, except: [:session_cookie]}
  @enforce_keys [:session_cookie, :user_id, :user_created]
  defstruct [:session_cookie, :user_id, :user_created, :country]

  @type t :: %__MODULE__{
          session_cookie: String.t(),
          user_id: String.t(),
          user_created: boolean(),
          country: String.t() | nil
        }
end

defmodule DatadeftAuth.Validation do
  @moduledoc """
  Session validation outcome. A `refreshed_cookie` (redacted in `Inspect`)
  re-issues the session cookie with the same `Set-Cookie` settings on a
  `no-store` response; nil means the presented cookie stays.
  """
  @derive {Inspect, except: [:refreshed_cookie]}
  @enforce_keys [:valid]
  defstruct [:valid, :user_id, :refreshed_cookie]

  @type t :: %__MODULE__{
          valid: boolean(),
          user_id: String.t() | nil,
          refreshed_cookie: String.t() | nil
        }
end

defmodule DatadeftAuth.DevMagicLink do
  @moduledoc """
  Fake-mode test helper result: the newest outbox email's landing URL for an
  address. The URL carries the bearer token and is redacted in `Inspect`.
  Never available outside `mode: :fake`.
  """
  @derive {Inspect, except: [:magic_link_url]}
  @enforce_keys [:found]
  defstruct [:found, :magic_link_url, :expires_at_unix]

  @type t :: %__MODULE__{
          found: boolean(),
          magic_link_url: String.t() | nil,
          expires_at_unix: non_neg_integer() | nil
        }
end
