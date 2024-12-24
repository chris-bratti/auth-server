# Get started with a build env with Rust nightly
FROM rustlang/rust:nightly-bullseye AS builder

# If you’re using stable, use this instead
# FROM rust:1.74-bullseye as builder

# Install cargo-binstall, which makes it easier to install other
# cargo extensions like cargo-leptos
RUN wget https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz
RUN tar -xvf cargo-binstall-x86_64-unknown-linux-musl.tgz
RUN cp cargo-binstall /usr/local/cargo/bin

# Install cargo-leptos
RUN cargo binstall cargo-leptos -y

# Add the WASM target
RUN rustup target add wasm32-unknown-unknown

# Install diesel for database setup
RUN cargo install diesel_cli --no-default-features --features "postgres"

# Make an /app dir, which everything will eventually live in
RUN mkdir -p /app
WORKDIR /app
COPY Cargo.toml Cargo.lock entrypoint.sh ./
COPY assets ./assets
COPY end2end ./end2end
COPY migrations ./migrations
COPY src ./src
COPY style ./style
ADD auto-encryption /app/auto-encryption
ADD encryption-libs /app/encryption-libs

# Build the app
RUN cargo leptos build --release -vv

FROM debian:bullseye-slim AS runtime
WORKDIR /app
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && apt-get install -y postgresql-client \
  && apt-get -y install libpq-dev \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

# Copy the server binary to the /app directory
COPY --from=builder /app/target/release/auth-server /app/

# /target/site contains our JS/WASM/CSS, etc.
COPY --from=builder /app/target/site /app/site

COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/cargo/bin/

# Copy Cargo.toml if it’s needed at runtime
COPY --from=builder /app/Cargo.toml /app/

COPY --from=builder /app/migrations /app/migrations

COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh


# Set any required env variables and
ENV RUST_LOG="info"
ENV LEPTOS_SITE_ADDR="0.0.0.0:3000"
ENV LEPTOS_SITE_ROOT="site"
EXPOSE 3000

# Initialize DB and start server
ENTRYPOINT [ "/app/entrypoint.sh" ]