#!/bin/sh

# Creates database if it doesn't already exist
init_db() {
    echo "Creating database ${DATABASE_NAME}"
    if psql -h localhost -U master -tc "SELECT 1 FROM pg_database WHERE datname = '${DATABASE_NAME}'" | grep -q 1; then
        echo "Database already exists"
    else
        psql -h localhost -U master -c "CREATE DATABASE ${DATABASE_NAME}"
    fi

    if psql -h localhost -U master -d "${DATABASE_NAME}" -tc "SELECT 1 FROM information_schema.tables WHERE table_name = 'users'" | grep -q 1; then
        echo "Tables already exist"
    else
        psql -h localhost -U master -d "${DATABASE_NAME}" -f init.sql
    fi
}

echo "Parsing command"
init_db
#if [ $# -gt 0 ]; then
#    echo "Running with command: $@"
#    exec /app/auth-server "$@"
#else
#init_db
#    echo "Starting server..."
#    exec /app/auth-server
#fi
