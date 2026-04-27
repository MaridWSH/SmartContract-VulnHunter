"""ChromaDB store abstraction for VulnHunter RAG."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class VulnStore:
    """ChromaDB-based vector store for vulnerability findings."""

    def __init__(self, persist_dir: Optional[str] = None):
        self._client = None
        self._collection = None
        self._persist_dir = persist_dir or "./chroma"
        self._init()

    def _init(self) -> None:
        try:
            import chromadb
            from chromadb.config import Settings

            self._client = chromadb.Client(
                Settings(
                    persist_directory=self._persist_dir,
                )
            )
            self._collection = self._client.get_or_create_collection("vulnhunter_kb")
        except Exception as exc:
            logger.warning(f"ChromaDB init failed: {exc}")
            self._client = None

    def add(
        self,
        documents: List[str],
        metadatas: List[Dict[str, any]],
        ids: List[str],
    ) -> None:
        if self._collection is None:
            return
        try:
            self._collection.add(documents=documents, metadatas=metadatas, ids=ids)
            if hasattr(self._client, "persist"):
                self._client.persist()
        except Exception as exc:
            logger.warning(f"ChromaDB add failed: {exc}")

    def query(
        self, query_text: str, n_results: int = 5, filter_metadata: Optional[Dict] = None
    ) -> List[Dict[str, any]]:
        if self._collection is None:
            return []
        try:
            kwargs = {"query_texts": [query_text], "n_results": n_results}
            if filter_metadata:
                kwargs["where"] = filter_metadata
            result = self._collection.query(**kwargs)
            documents = result.get("documents", [[]])[0]
            metadatas = result.get("metadatas", [[]])[0]
            distances = result.get("distances", [[]])[0]
            return [
                {
                    "document": doc,
                    "metadata": meta,
                    "distance": dist,
                }
                for doc, meta, dist in zip(documents, metadatas, distances)
            ]
        except Exception as exc:
            logger.warning(f"ChromaDB query failed: {exc}")
            return []

    def count(self) -> int:
        if self._collection is None:
            return 0
        try:
            return self._collection.count()
        except Exception:
            return 0

    def reset(self) -> None:
        if self._collection is None:
            return
        try:
            self._collection.delete(where={})
        except Exception as exc:
            logger.warning(f"ChromaDB reset failed: {exc}")
