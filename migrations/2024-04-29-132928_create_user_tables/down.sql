-- This file should undo anything in `up.sql`
DROP TABLE password_reset_tokens;
DROP TABLE verification_tokens;
DROP TABLE users;
DROP TABLE api_keys;
DROP TABLE oauth_clients;
DROP TABLE refresh_tokens