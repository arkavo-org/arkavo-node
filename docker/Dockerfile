# Multi-stage build for Arkavo Node

# Stage 1: Build the node
FROM rust:latest as builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y clang libssl-dev llvm libudev-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# Set up Rust toolchain
# Note: rust:latest already has stable. We need to ensure wasm target is there.
RUN rustup target add wasm32-unknown-unknown && \
    rustup component add rust-src

WORKDIR /arkavo

# Copy workspace files
COPY Cargo.toml Cargo.lock ./

# Copy configuration
COPY .cargo ./.cargo

# Copy source code
COPY node ./node
COPY runtime ./runtime
COPY pallets ./pallets
COPY libs ./libs

# Build the node in release mode
RUN cargo build --release --package arkavo-node

# Stage 2: Runtime image
FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates curl libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Create user for running the node
RUN useradd -m -u 1000 -U -s /bin/sh -d /arkavo arkavo

WORKDIR /arkavo

# Copy the compiled binary
COPY --from=builder /arkavo/target/release/arkavo-node /usr/local/bin/

# Set ownership
RUN chown -R arkavo:arkavo /arkavo

# Switch to non-root user
USER arkavo

# Expose P2P, RPC, and WebSocket ports
EXPOSE 30333 9933 9944

# Set default command
ENTRYPOINT ["/usr/local/bin/arkavo-node"]
CMD ["--dev", "--unsafe-rpc-external", "--rpc-cors=all"]