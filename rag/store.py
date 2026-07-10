"""
RAG knowledge store backed by Qdrant + FastEmbed.

This is the single abstraction the rest of the platform uses to talk to the
vector store. The Phase 5 agent tools (query_mitre_attack, query_runbooks) are
built against this exact interface, so swapping their stubs for real retrieval
is a no-op for the agents.

Design:
- Embeddings are computed locally with FastEmbed (ONNX, no external API). The
  model is pre-baked into the worker image (see common/Dockerfile) at
  `rag_embedding_cache_dir`, so runtime never downloads it.
- Qdrant point IDs must be UUIDs or ints, so human-readable doc IDs (e.g.
  "T1110") are mapped to a stable uuid5 and the original ID is kept in the
  payload. This makes ingestion idempotent — re-running updates in place.
- Embedding is CPU-bound and runs in a thread so it never blocks the event
  loop.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Optional

from fastembed import TextEmbedding
from qdrant_client import AsyncQdrantClient, models

from common.config import settings

logger = logging.getLogger("soc.rag.store")

# Fixed namespace so uuid5(doc_id) is stable across runs/processes.
_UUID_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

MITRE_COLLECTION = "mitre_attack"
RUNBOOKS_COLLECTION = "runbooks"
PAST_CASES_COLLECTION = "past_cases"
COLLECTIONS = (MITRE_COLLECTION, RUNBOOKS_COLLECTION, PAST_CASES_COLLECTION)


class RAGStore:
    """Vector-search knowledge store over MITRE ATT&CK, runbooks, and past cases."""

    def __init__(self, client: Optional[AsyncQdrantClient] = None):
        # `client` injectable for testing (e.g. in-memory Qdrant).
        self.client = client or AsyncQdrantClient(
            host=settings.qdrant_host,
            port=settings.qdrant_port,
        )
        self.vector_size = settings.rag_vector_size
        self.n_results = settings.rag_n_results
        self.model_name = settings.rag_embedding_model
        self.cache_dir = settings.rag_embedding_cache_dir
        self._embedder: Optional[TextEmbedding] = None

    # -- embedding ----------------------------------------------------------

    @property
    def embedder(self) -> TextEmbedding:
        if self._embedder is None:
            self._embedder = TextEmbedding(
                model_name=self.model_name,
                cache_dir=self.cache_dir,
            )
        return self._embedder

    async def _embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts (runs the CPU-bound model off the event loop)."""
        def _run() -> list[list[float]]:
            return [vec.tolist() for vec in self.embedder.embed(texts)]
        return await asyncio.to_thread(_run)

    # -- schema -------------------------------------------------------------

    async def ensure_collections(self) -> None:
        """Create the knowledge collections if they don't already exist."""
        existing = {c.name for c in (await self.client.get_collections()).collections}
        for name in COLLECTIONS:
            if name not in existing:
                await self.client.create_collection(
                    collection_name=name,
                    vectors_config=models.VectorParams(
                        size=self.vector_size,
                        distance=models.Distance.COSINE,
                    ),
                )
                logger.info("Created Qdrant collection '%s'", name)
        logger.info("RAG collections ready: %s", ", ".join(COLLECTIONS))

    @staticmethod
    def _point_id(collection: str, doc_id: str) -> str:
        return str(uuid.uuid5(_UUID_NAMESPACE, f"{collection}:{doc_id}"))

    # -- writes -------------------------------------------------------------

    async def add_document(
        self,
        collection: str,
        doc_id: str,
        text: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Upsert a single document (used by the feedback loop)."""
        await self.add_documents(collection, [(doc_id, text, metadata or {})])

    async def add_documents(
        self,
        collection: str,
        docs: list[tuple[str, str, dict[str, Any]]],
    ) -> None:
        """Upsert a batch of (doc_id, text, metadata) tuples."""
        if not docs:
            return
        vectors = await self._embed([text for _, text, _ in docs])
        points = [
            models.PointStruct(
                id=self._point_id(collection, doc_id),
                vector=vector,
                payload={"doc_id": doc_id, "text": text, **(metadata or {})},
            )
            for (doc_id, text, metadata), vector in zip(docs, vectors)
        ]
        await self.client.upsert(collection_name=collection, points=points)
        logger.info("Upserted %d document(s) into '%s'", len(points), collection)

    # -- reads --------------------------------------------------------------

    async def query(
        self,
        collection: str,
        text: str,
        n_results: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Semantic search a collection.

        Returns a list of {"document": str, "metadata": dict, "score": float}
        ordered by relevance (highest cosine similarity first).
        """
        limit = n_results or self.n_results
        vector = (await self._embed([text]))[0]
        response = await self.client.query_points(
            collection_name=collection,
            query=vector,
            limit=limit,
            with_payload=True,
        )
        results: list[dict[str, Any]] = []
        for hit in response.points:
            payload = hit.payload or {}
            document = payload.get("text", "")
            metadata = {k: v for k, v in payload.items() if k != "text"}
            results.append({"document": document, "metadata": metadata, "score": hit.score})
        return results

    async def close(self) -> None:
        await self.client.close()
