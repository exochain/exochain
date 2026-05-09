#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'sybil-cli secret boundary test failed: %s\n' "$1" >&2
  exit 1
}

SOURCE="tools/sybil-cli/graph_schema.py"

[[ -f "$SOURCE" ]] || fail "missing $SOURCE"

if grep -En 'password[[:space:]]*=[[:space:]]*["'\'']password["'\'']|username[[:space:]]*=[[:space:]]*["'\'']neo4j["'\'']|bolt://localhost:7687' "$SOURCE" >/dev/null; then
  fail "Neo4j connection settings must come from required environment variables, not literals"
fi

for required in NEO4J_URI NEO4J_USERNAME NEO4J_PASSWORD; do
  if ! grep -Fn "$required" "$SOURCE" >/dev/null; then
    fail "$SOURCE must read required $required configuration"
  fi
done

if ! grep -Fn 'Missing required Neo4j configuration' "$SOURCE" >/dev/null; then
  fail "$SOURCE must fail closed with a clear missing-configuration error"
fi

env -u NEO4J_URI -u NEO4J_USERNAME -u NEO4J_PASSWORD python3 - <<'PY'
import runpy
import sys
import types

graph_module = types.ModuleType("langchain.graphs.neo4j_graph")

class Neo4jGraph:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

graph_module.Neo4jGraph = Neo4jGraph
sys.modules["langchain"] = types.ModuleType("langchain")
sys.modules["langchain.graphs"] = types.ModuleType("langchain.graphs")
sys.modules["langchain.graphs.neo4j_graph"] = graph_module

try:
    runpy.run_path("tools/sybil-cli/graph_schema.py")
except RuntimeError as error:
    if "Missing required Neo4j configuration: NEO4J_URI" not in str(error):
        raise
else:
    raise SystemExit("graph_schema.py must fail closed when Neo4j env is missing")
PY

NEO4J_URI='bolt://neo4j.internal:7687' \
NEO4J_USERNAME='sybil-operator' \
NEO4J_PASSWORD='correct-horse-battery-staple' \
python3 - <<'PY'
import runpy
import sys
import types

graph_module = types.ModuleType("langchain.graphs.neo4j_graph")

class Neo4jGraph:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

graph_module.Neo4jGraph = Neo4jGraph
sys.modules["langchain"] = types.ModuleType("langchain")
sys.modules["langchain.graphs"] = types.ModuleType("langchain.graphs")
sys.modules["langchain.graphs.neo4j_graph"] = graph_module

namespace = runpy.run_path("tools/sybil-cli/graph_schema.py")
graph = namespace["graph"]
assert graph.kwargs == {
    "url": "bolt://neo4j.internal:7687",
    "username": "sybil-operator",
    "password": "correct-horse-battery-staple",
}
PY

printf 'sybil-cli secret boundary test passed\n'
