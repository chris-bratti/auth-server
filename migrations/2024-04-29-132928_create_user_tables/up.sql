-- Your SQL goes here
CREATE TABLE users (
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

CREATE TABLE verification_tokens (
    id SERIAL PRIMARY KEY,
    confirm_token text NOT NULL,
    confirm_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    reset_token text NOT NULL,
    reset_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    app_name text NOT NULL UNIQUE,
    api_key text NOT NULL,
);