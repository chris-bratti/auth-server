-- Your SQL goes here
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    username text NOT NULL UNIQUE,
    email text NOT NULL,
    pass_hash text NOT NULL,
    initialized boolean NOT NULL,
    two_factor_token text,
    locked boolean NOT NULL,
    pass_retries integer,
    last_failed_attempt TIMESTAMP
);