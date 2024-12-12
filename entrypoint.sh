#!/bin/sh

echo "Parsing command"
if [ $# -gt 0 ]; then
    echo "Running with command: $@"
    exec /app/auth-server "$@"
else
    echo "Running diesel migrations"
    /usr/local/cargo/bin/diesel database setup
    echo "Running application"
    exec /app/auth-server
fi
