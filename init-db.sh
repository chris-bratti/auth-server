#!/bin/sh
# Creates database if it doesn't already exist
init_db() {
    echo "Creating databse ${DATABASE_NAME}"
    if psql -h leptos_postgres -U master -tc "SELECT 1 FROM pg_database WHERE datname = '${DATABASE_NAME}'" | grep -q 1; then
        echo "Database already exists"
    else
        psql -h leptos_postgres -U master -c "CREATE DATABASE ${DATABASE_NAME}"
    fi

    if psql -h leptos_postgres -U master -b ${DATABASE_NAME} -tc "SELECT 1 from information_schema.tables where table_name = 'users'" | grep -q 1; then
        echo "Tables already exist"
    else
        psql -h leptos_postgres -U master -b ${DATABASE_NAME} -f init.sql
    fi
}

echo "Parsing command"

if [[ $# -gt 0 ]]; then
    echo "Running with command: $@"
    # Pass the arguments to the Rust application
    exec /app/auth-server "$@"
else
    # Default behavior: Initialize the database and start the server
    init_db
    echo "Starting server..."
    exec /app/auth-server
fi
