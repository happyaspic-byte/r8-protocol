# syntax=docker/dockerfile:1
FROM rust:1.97.1-slim AS builder
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends cmake make clang perl pkg-config && rm -rf /var/lib/apt/lists/*
COPY rust/ ./rust/
WORKDIR /workspace/rust
RUN cargo build --release --locked -p r8d --bin r8d -p r8ping --bin r8ping

FROM debian:bookworm-slim
RUN useradd -u 10001 -r -s /usr/sbin/nologin r8user
WORKDIR /app
COPY --from=builder /workspace/rust/target/release/r8d /usr/local/bin/r8d
COPY --from=builder /workspace/rust/target/release/r8ping /usr/local/bin/r8ping
USER r8user
ENTRYPOINT ["/usr/local/bin/r8d"]
CMD ["--address", "8:1::1", "--bind", "127.0.0.1:52808"]
