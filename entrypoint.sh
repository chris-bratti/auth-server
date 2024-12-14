#!/bin/sh

echo "Running diesel migrations"
/usr/local/cargo/bin/diesel database setup
echo "Running application"
exec /app/auth-server
