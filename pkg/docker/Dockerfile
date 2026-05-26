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

# Base images pinned by digest (Scorecard PinnedDependencies). Update
# the digest + comment together when rolling forward to a new tag.
FROM rust:1.85-alpine@sha256:4333721398de61f53ccbe53b0b855bcc4bb49e55828e8f652d7a8ac33dd0c118 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --bin hsh \
    --target "$(uname -m)-unknown-linux-musl"

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
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
