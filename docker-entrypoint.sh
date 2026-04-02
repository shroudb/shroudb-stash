#!/bin/sh
set -e

# Fix ownership of /data when mounted as a volume (e.g., Railway, Docker)
# Volume mounts override build-time chown, so we fix it at runtime.
if [ "$(id -u)" = "0" ]; then
    chown -R shroudb:shroudb /data
    exec su-exec shroudb "$@"
fi

# Already running as shroudb (e.g., Kubernetes with securityContext)
exec "$@"
