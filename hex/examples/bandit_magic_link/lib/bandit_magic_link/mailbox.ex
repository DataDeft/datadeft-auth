defmodule BanditMagicLink.Mailbox do
  @moduledoc false
  alias DatadeftAuth.MagicLink.Core.{Email, Token}

  @enforce_keys [:dir, :origin]
  defstruct [:dir, :origin]

  def create(origin) do
    suffix = Base.url_encode64(:crypto.strong_rand_bytes(18), padding: false)
    dir = Path.join(System.tmp_dir!(), "dd-auth-bandit-" <> suffix)

    case File.mkdir(dir) do
      :ok ->
        case File.chmod(dir, 0o700) do
          :ok ->
            {:ok, %__MODULE__{dir: dir, origin: origin}}

          {:error, _} ->
            File.rmdir(dir)
            {:error, :mailbox_unavailable}
        end

      {:error, _} ->
        {:error, :mailbox_unavailable}
    end
  end

  def path(%__MODULE__{dir: dir}), do: Path.join(dir, "inbox.txt")

  def remove(%__MODULE__{dir: dir}), do: File.rm_rf(dir)

  def enqueue_magic_link(mailbox, mail) do
    if Email.value(mail.email) == "alice@example.test" do
      deliver(mailbox, mail)
    else
      # This example never delivers email or renders real addresses.
      :ok
    end
  end

  defp deliver(mailbox, mail) do
    pending =
      Path.join(mailbox.dir, Base.url_encode64(:crypto.strong_rand_bytes(18), padding: false))

    delivery = mailbox.origin <> "/auth/magic-link/open?token=" <> Token.value(mail.token)

    result =
      with :ok <- File.write(pending, "", [:exclusive]),
           :ok <- File.chmod(pending, 0o600),
           :ok <- File.write(pending, delivery <> "\n"),
           :ok <- File.rename(pending, path(mailbox)) do
        :ok
      else
        _ -> {:error, :unavailable}
      end

    if result != :ok, do: File.rm(pending)
    result
  end
end
