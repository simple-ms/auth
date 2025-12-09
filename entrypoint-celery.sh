#!/bin/bash
set -e

echo "Waiting for database..."
sleep 5

echo "Starting Celery worker (skipping migrations)..."
exec "$@"
