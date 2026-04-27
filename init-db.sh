#!/bin/bash
# Postgres bootstrap: create the `livesafe` database alongside the primary.
#
# Runs under the official postgres image's /docker-entrypoint-initdb.d
# hook during first-boot AND on every restart of an existing data dir.
# Must be idempotent: CREATE DATABASE is not re-runnable, so we gate on
# pg_catalog presence. (A-041)
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE livesafe'
    WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'livesafe')\gexec

    GRANT ALL PRIVILEGES ON DATABASE livesafe TO exochain;
EOSQL
