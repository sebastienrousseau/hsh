# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Multi-stage Docker image for the `hsh` CLI.
#
#  - `builder` stage compiles the static (musl) binary.
#  - `runtime` stage is a distroless image carrying only the binary plus
#    the CA certificates needed for any future KMS network calls.
#
# Build:
#   docker buildx build --platform=linux/amd64,linux/arm64 \
#       -t ghcr.io/sebastienrousseau/hsh:0.0.9 \
#       -f pkg/docker/Dockerfile .
# ---------------------------------------------------------------------------

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --bin hsh \
    --target "$(uname -m)-unknown-linux-musl"

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="hsh"
LABEL org.opencontainers.image.description="Enterprise password hashing on the command line."
LABEL org.opencontainers.image.url="https://github.com/sebastienrousseau/hsh"
LABEL org.opencontainers.image.source="https://github.com/sebastienrousseau/hsh"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Pull the right binary based on the build platform.
ARG TARGETARCH
COPY --from=builder /src/target/*-unknown-linux-musl/release/hsh /usr/local/bin/hsh

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/hsh"]
CMD ["--help"]
