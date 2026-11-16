#!/bin/sh
# Verify the Elixir package inside an official `elixir` image, Debian or
# Alpine (musl). CI runs it through `docker run` with the checkout mounted at
# the working directory; locally:
#   docker run --rm -v "$PWD:/work" -w /work elixir:1.19-otp-28-alpine \
#     sh packages/datadeft-auth-elixir/scripts/ci_image_verify.sh
# It installs the native build tools, stable Rust and mise, then runs the
# same `elixir-verify` task as the host jobs. Runs as root in a throwaway
# container.
set -eu

# Record the distribution and libc in the job log.
grep PRETTY_NAME /etc/os-release
ldd --version 2>&1 | head -n 1 || true

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache build-base curl git
else
  apt-get update
  apt-get install -y --no-install-recommends build-essential ca-certificates curl git
fi

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y --profile minimal --default-toolchain stable
curl --proto '=https' --tlsv1.2 -sSf https://mise.run | sh
PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export PATH

# The mounted checkout is owned by another user.
git config --global --add safe.directory '*'
mix local.hex --force
mix local.rebar --force

# The workspace's bun and node tools serve other tasks and have no musl
# builds; elixir-verify needs neither.
MISE_TRUSTED_CONFIG_PATHS="$PWD" MISE_DISABLE_TOOLS=bun,node mise run elixir-verify
