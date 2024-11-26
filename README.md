# Auth-Server
## An authentication server written in Rust

## Features:
### Security
- Secure password & reset token hashing with Argon2
- Secure email encryption with AES256-GCM
- Two factor authentication with Time-Based One Time Passwords (TOTP)
- JWT-based tokens
- Password retry limits - lock accounts after too many failed tries
- User verification through securely generated email links
- Verification & password reset tokens expire after 20 minutes
- SMTP via TLS
- HTTPS
- API key authentication

### Easy to use
- Easy two factor authentication enrollment with QR code based secrets
- Password reset capabilities - generates a secure reset token sent to user's email
- Persistent session storage using Actix Web & Redis - user's sessions are saved with persistent session cookies to avoid repeated authentication

### Persistent storage
- User data persisted with Postgres DB
- Full CRUD operations built with Diesel
- Database initialization and migrations supported via Diesel
- Automated DB bootstrapping - `init-db.sh` and `init.sql` files automate database, user, and table creation!

## Endpoints

Check out the [endpoints.md](https://raw.githubusercontent.com/chris-bratti/auth-server/master/endpoints.md) file for documentation on the various endpoints

## Dockerized!

This project can be run in a docker container! And it has everything you need to connect and bootstrap your postgres database.

### 1. Download the docker-compose

```
$ wget https://raw.githubusercontent.com/chris-bratti/auth-server/master/docker-compose.yml
```

### 2. Set your env values

Download the template `.env` file by running:

```
$ wget https://raw.githubusercontent.com/chris-bratti/auth-server/master/example.env

$ mv example.env .env
```

And then updating the values for your app

Note that **all encryption keys need to be 32 characters long**. Generate these strings with whatever method you'd like, ex:

```
$ cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
```

### 3. Generate self-signed SSL certificate
Generate a self-signed certificate locally by running the following, **updating the `subj` to your own custom values**

```
# Create a new directory for your certs
$ mkdir certs && cd certs

# Creates private key and cert, update -subj
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -sha256 -subj "/C=US/ST=New-York/L=Buffalo/O=YourOrg/OU=YourDepartment/CN=localhost"

# Creates a password-less version of private key
$ openssl rsa -in key.pem -out private.pem
```

And then update the `docker-compose.yaml` to mount the `certs` directory to the container:

```
services:
  auth-server:
    ...
    volumes:
      - path/to/certs:/app/certs
```

### 4. Start the containers
After running `docker-compose up -d`, you should have the following containers:

1. `auth-server` - Container for the authentication server
2. `auth-postgres` - The postgres container for your database
3. `auth-reds` - The Redis cache for session storage

## Running locally

Running the project locally will require installing Rust and some other dependencies

Prerequisites: 
- A running postgres instance - check the `docker-compose.yaml` for an example for running in Docker
- A database and configured schema - check the `init-db.sh` and `init.sql` for the commands to create the expected schema
- A running Redis instance - also available in the `docker-compose.yaml` file

Setup instructions:

### 1. Clone the repo and edit the `.env` file:
```
$ git clone https://github.com/chris-bratti/auth-server.git

$ cd auth-server

$ cp example.env .env

$ nano .env
```

Check the `Dockerized!` section for more info on the `.env` file. Make sure to uncomment the `DATABASE_URL` and `REDIS_CONNECTION_STRING` vars for local testing

### 3. Generate SSL certificates

Check the `Dockerized!` section for steps, the app will expect the `certs` folder in the project root directory

### 4. Build and run
```
$ cargo build --release

$ cargo run --release
```

The server will start on port 8080 and will only be reachable via HTTPS

## Generating and adding API Keys
The `/auth` endpoint uses API key authentication. API keys are generated by the application, hashed & stored in the database, and loaded on application startup (or manually, we'll get to that)

An API key can be generated after the server is started either locally or with Docker:

### Docker
```
$ docker run --rm --env-file .env --network=auth-server_auth auth-server:latest add-api-key --app-name app_name --auth-key adminkey
```
Where:

- `.env` is the `.env` file passed into the `docker-compose.yaml`
- `app-name` is a unique name for the service that will be using the API key
- `auth-key` is the `ADMIN_KEY` that was provided to the container in the `docker-compose.yaml`

You will be given a generated API key. Make sure you copy it somewhere safe, **API keys cannot be retrieved once they've been generated**

### Locally
Similar to Docker:
```
$ cargo run -- add-api-key --app-name app_name --auth-key adminkey
```

### Loading API keys into the app
The server saves API keys to the database and loads them into an in-memory cache on server startup. **API key validation only happens against the in-memory cache**. In order to refresh the API keys, you can hit an internal endpoint:

```
POST `https://localhost:8080/internal/reloadkeys
--header 'X-Admin-Key: adminkey'
```

Using the `ADMIN_KEY` for the server. The app will then reload all the API keys from the database and update the cache.

## Contributions

**This repo is open to contributions** - feel free to open a PR for any changes, updates, or refactors as you see fit. I am *quite* open to feedback on this project - if you have some good ideas I would love to see them :)


## Libraries, Frameworks, and Technologies
### A list of the libraries and frameworks used in this project
- [Actix Web](https://github.com/actix/actix-web) (via Leptos integration) - a powerful, pragmatic, and extremely fast web framework for Rust
- [Diesel](https://github.com/diesel-rs/diesel) - a safe, extensible ORM and Query Builder for Rust
- [PostgreSQL](https://www.postgresql.org/) - a powerful, open source object-relational database system 
- [Redis](https://github.com/redis/redis) - a key-value based in-memory database
- [Lettre](https://github.com/lettre/lettre) - a mailer library for Rust
- [Maud](https://github.com/lambda-fairy/maud) - an HTML template engine for Rust
- [RustCrypt Argon2](https://docs.rs/argon2/latest/argon2/) - a Pure Rust implementation of the Argon2 password hashing function.
- [totp-rs](https://github.com/constantoine/totp-rs) - RFC-compliant TOTP implementation with QR code generation

