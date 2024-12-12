-- Your SQL goes here
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    first_name text NOT NULL,
    last_name text NOT NULL,
    username text NOT NULL,
    pass_hash text NOT NULL,
    email text NOT NULL,
    verified boolean NOT NULL,
    two_factor boolean NOT NULL,
    two_factor_token text,
    locked boolean NOT NULL,
    pass_retries integer,
    last_failed_attempt TIMESTAMP
);

CREATE TABLE IF NOT EXISTS  verification_tokens (
    id SERIAL PRIMARY KEY,
    confirm_token text NOT NULL,
    confirm_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) UNIQUE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    reset_token text NOT NULL,
    reset_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) UNIQUE
);

CREATE TABLE IF NOT EXISTS  api_keys (
    id SERIAL PRIMARY KEY,
    app_name text NOT NULL UNIQUE,
    api_key text NOT NULL
);

CREATE TABLE IF NOT EXISTS  oauth_clients (
    id SERIAL PRIMARY KEY,
    app_name text NOT NULL UNIQUE,
    contact_email text NOT NULL,
    client_id text NOT NULL UNIQUE,
    client_secret text NOT NULL UNIQUE,
    redirect_url text NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES oauth_clients(id),
    refresh_token TEXT NOT NULL,
    token_id TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL,
    UNIQUE (client_id, username)
);