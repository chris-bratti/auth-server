-- Create table structure
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

CREATE TABLE IF NOT EXISTS verification_tokens (
    id SERIAL PRIMARY KEY,
    confirm_token text NOT NULL,
    confirm_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    reset_token text NOT NULL,
    reset_token_expiry TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
);