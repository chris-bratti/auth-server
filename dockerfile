FROM rust:1.82.0-bullseye AS builder

# Install OpenSSL development libraries
#RUN apt-get update -y && apt-get install -y --no-install-recommends \
 #   libssl-dev pkg-config build-essential && \
 #   rm -rf /var/lib/apt/lists/*

# Make an /app dir, which everything will eventually live in
RUN mkdir -p /app
WORKDIR /app
COPY Cargo.toml Cargo.lock entrypoint.sh ./
COPY migrations ./migrations
COPY src ./src

# Build the app
RUN cargo build --release

RUN cargo install diesel_cli --no-default-features --features "postgres"

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

COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/cargo/bin/

# Copy Cargo.toml if it’s needed at runtime
COPY --from=builder /app/Cargo.toml /app/

COPY --from=builder /app/migrations /app/migrations

COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh

# Set any required env variables and
ENV RUST_LOG="info"
EXPOSE 8080

# Initialize DB and start server
ENTRYPOINT [ "/app/entrypoint.sh" ]