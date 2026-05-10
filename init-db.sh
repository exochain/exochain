#!/bin/bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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
