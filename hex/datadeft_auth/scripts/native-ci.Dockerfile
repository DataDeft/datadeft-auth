# Source-build matrix only; never used as a production application image.
ARG RUST_IMAGE
ARG BEAM_IMAGE
FROM ${RUST_IMAGE} AS rust
FROM ${BEAM_IMAGE}
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN if command -v apk >/dev/null; then apk add --no-cache build-base; \
    elif ! command -v cc >/dev/null; then apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*; fi
