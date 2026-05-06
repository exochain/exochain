import os

from langchain.graphs.neo4j_graph import Neo4jGraph


def required_neo4j_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required Neo4j configuration: {name}")
    return value


def build_graph() -> Neo4jGraph:
    return Neo4jGraph(
        url=required_neo4j_env("NEO4J_URI"),
        username=required_neo4j_env("NEO4J_USERNAME"),
        password=required_neo4j_env("NEO4J_PASSWORD"),
    )


graph = build_graph()

# Example Cypher Model Definitions:
# :Interaction - {id, text, timestamp, model}
# :MemoryObject - {embedding, tags}
# :Session - {id, started_at, archetype}

# Relationships:
# (:Interaction)-[:EMBEDDED_IN]->(:MemoryObject)
# (:Interaction)-[:EMANATES_FROM]->(:Session)
# (:MemoryObject)-[:TRACES_BACK_TO]->(:UPK)
