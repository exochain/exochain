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

"""Vector memory interface.

NOTE: External services (Weaviate) are optional for the MVP. The key point for
"gravity transfer" is that *writes* can be gated by decision.forum policy.
"""

from langchain.vectorstores import Weaviate
from langchain.embeddings import OpenAIEmbeddings

from utils import load_upk

def get_memory_vector_store():
    return Weaviate.from_texts(
        texts=[],  # Will fill dynamically
        embedding=OpenAIEmbeddings(),
        weaviate_url="http://localhost:8080"
    )

def store_memory(text_chunk, tags, *, decision_id: str | None = None):
    upk = load_upk()
    policy = (upk.get("governance") or {}).get("decision_forum") or {}
    required_for = set(policy.get("required_for") or [])
    if policy.get("enabled") and "memory_write" in required_for and not decision_id:
        raise ValueError(
            "decision.forum policy requires decision_id for memory writes. "
            "Create a Decision Record first and pass its id."
        )

    vs = get_memory_vector_store()
    vs.add_texts([text_chunk], metadatas=[{"tags": tags, "decision_id": decision_id}])
