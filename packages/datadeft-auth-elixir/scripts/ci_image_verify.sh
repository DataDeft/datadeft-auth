#!/bin/sh
# Verify the Elixir package inside an official `elixir` image, Debian or
# Alpine (musl). CI runs it through `docker run` with the checkout mounted at
# the working directory; locally:
#   docker run --rm -v "$PWD:/work" -w /work elixir:1.19-otp-28-alpine \
#     sh packages/datadeft-auth-elixir/scripts/ci_image_verify.sh
# It installs the native build tools, a pinned mise and a pinned rustup-init
# (each checked against its SHA-256 before it runs; no installer is piped to
# a shell), then runs the same `elixir-verify` task as the host jobs. Runs as
# root in a throwaway container.
set -eu

MISE_VERSION=2026.11.8
RUSTUP_VERSION=1.29.3

# Record the distribution and libc in the job log.
grep PRETTY_NAME /etc/os-release
ldd --version 2>&1 | head -n 1 || true

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache build-base curl git
  libc=musl
else
  apt-get update
  apt-get install -y --no-install-recommends build-essential ca-certificates curl git
  libc=gnu
fi

# Digests from the mise release's SHASUMS256.txt and rustup's
# rustup-init.sha256 files; update them together with the versions above.
case "$(uname -m)-$libc" in
  x86_64-musl)
    mise_arch=x64
    mise_sha=1fe64489a99b6227b7f7e67ae4dd3293c20ecbbcd74b1367456010359383e712
    rustup_sha=1552169aba2836777136ccff7a381e95c17233b5d8250cd5e10ae3cb971bfcfc ;;
  x86_64-gnu)
    mise_arch=x64
    mise_sha=1fe64489a99b6227b7f7e67ae4dd3293c20ecbbcd74b1367456010359383e712
    rustup_sha=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;;
  aarch64-musl)
    mise_arch=arm64
    mise_sha=3febd613b6e49f928acdacda006662cee252f160ebc3fc48f5197260e61dc758
    rustup_sha=956deacdc27ab82ae7ac821d5d3e9e95e4795d476d17efe99743bb8531ca1031 ;;
  aarch64-gnu)
    mise_arch=arm64
    mise_sha=3febd613b6e49f928acdacda006662cee252f160ebc3fc48f5197260e61dc758
    rustup_sha=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;;
  *) echo "unsupported platform: $(uname -m)-$libc" >&2; exit 1 ;;
esac

# Downloads $1 to $2 and refuses to keep it unless it matches the digest $3.
fetch_verified() {
  curl --proto '=https' --tlsv1.2 -sSfL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c -
  chmod +x "$2"
}

bin="$HOME/.local/bin"
mkdir -p "$bin"
# The static musl build of mise runs on both glibc and musl hosts.
fetch_verified \
  "https://github.com/jdx/mise/releases/download/v$MISE_VERSION/mise-v$MISE_VERSION-linux-$mise_arch-musl" \
  "$bin/mise" "$mise_sha"
fetch_verified \
  "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$(uname -m)-unknown-linux-$libc/rustup-init" \
  /tmp/rustup-init "$rustup_sha"
/tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain stable
PATH="$HOME/.cargo/bin:$bin:$PATH"
export PATH

# The mounted checkout is owned by another user.
git config --global --add safe.directory '*'
mix local.hex --force
mix local.rebar --force

# The workspace's bun and node tools serve other tasks and have no musl
# builds; elixir-verify needs neither.
MISE_TRUSTED_CONFIG_PATHS="$PWD" MISE_DISABLE_TOOLS=bun,node mise run elixir-verify
