#!/bin/sh
# Creates database if it doesn't already exist
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

echo "Starting the application..."
exec /app/auth_leptos
