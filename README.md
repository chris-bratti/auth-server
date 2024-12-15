# Auth-Server
## An OAuth authentication server written in Rust

## Features:

### OAuth
- Full OAuth Authorization Code flow - secures user data with JWT `access_tokens`
- User-locked `access_tokens` - tokens are only valid for one user and have built in expiration
- UI for user-facing login

### Security
- OAuth Authorization Code authentication
- Secure password & reset token hashing with Argon2
- Secure email encryption with AES256-GCM
- Two factor authentication with Time-Based One Time Passwords (TOTP)
- JWT-based tokens
- Password retry limits - lock accounts after too many failed tries
- User verification through securely generated email links
- Verification & password reset tokens expire after 20 minutes
- SMTP via TLS
- User-only pages - ensure only authenticated users can access sensitive pages
- HTTPS

### User friendly
- Easy to navigate UI built with Leptos
- Simple and fast two factor authentication enrollment with QR code based secrets
- Password reset capabilities - generates a secure reset token sent to user's email
- Persistent session storage using Actix Web & Redis - user's sessions are saved with persistent session cookies to avoid repeated authentication

### Persistent storage
- Data persisted with Postgres DB
- Full CRUD operations built with Diesel
- Database connection pooling with R2D2
- Database initialization and migrations supported via Diesel
- Caching using Redis to speed up operations and avoid large amount of DB calls

## Endpoints

Check out the [endpoints.md](https://github.com/chris-bratti/auth-server/blob/master/endpoints.md) file for documentation on the various endpoints

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

## Contributions

**This repo is open to contributions** - feel free to open a PR for any changes, updates, or refactors as you see fit. I am *quite* open to feedback on this project - if you have some good ideas I would love to see them :)


## Libraries, Frameworks, and Technologies
### A list of the libraries and frameworks used in this project
- [Leptos](https://github.com/leptos-rs/leptos) - a full-stack, isomorphic Rust web framework leveraging fine-grained reactivity to build declarative user interfaces
- [Actix Web](https://github.com/actix/actix-web) - a powerful, pragmatic, and extremely fast web framework for Rust
- [Diesel](https://github.com/diesel-rs/diesel) - a safe, extensible ORM and Query Builder for Rust
- [R2D2](https://docs.rs/r2d2/latest/r2d2/) - A generic connection pool for Rust
- [PostgreSQL](https://www.postgresql.org/) - a powerful, open source object-relational database system 
- [Redis](https://docs.rs/redis/latest/redis/) - a Rust implementation of a client library for Redis
- [Lettre](https://github.com/lettre/lettre) - a mailer library for Rust
- [Maud](https://github.com/lambda-fairy/maud) - an HTML template engine for Rust
- [RustCrypt Argon2](https://docs.rs/argon2/latest/argon2/) - a Pure Rust implementation of the Argon2 password hashing function
- [totp-rs](https://github.com/constantoine/totp-rs) - RFC-compliant TOTP implementation with QR code generation

