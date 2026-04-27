"""Ingest pashov audit reports into ChromaDB RAG."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import List

from vulnhunter.rag.store import VulnStore

logger = logging.getLogger(__name__)


def ingest_pashov_audits(repo_path: str, store: VulnStore | None = None) -> int:
    """Ingest markdown audit reports from a cloned pashov/audits repo.

    Args:
        repo_path: Path to cloned https://github.com/pashov/audits
        store: VulnStore instance (creates default if None)

    Returns:
        Number of documents ingested
    """
    store = store or VulnStore()
    root = Path(repo_path)
    if not root.exists():
        logger.error(f"pashov audits repo not found at {repo_path}")
        return 0

    md_files = list(root.rglob("*.md"))
    logger.info(f"Found {len(md_files)} markdown files in pashov audits")

    documents: List[str] = []
    metadatas: List[dict] = []
    ids: List[str] = []

    for idx, fp in enumerate(md_files, 1):
        try:
            text = fp.read_text(encoding="utf-8")
            chunks = _chunk_by_sections(text)
            for chunk_idx, chunk in enumerate(chunks):
                doc_id = f"pashov_{idx}_{chunk_idx}"
                content_hash = hashlib.sha256(chunk.encode()).hexdigest()[:16]
                # Skip if already exists with same content hash (idempotent)
                existing = store.query(chunk, n_results=1)
                if existing:
                    meta = existing[0].get("metadata", {})
                    if meta.get("content_hash") == content_hash:
                        continue

                documents.append(chunk)
                metadatas.append(
                    {
                        "source": "pashov",
                        "source_url": str(fp),
                        "severity": "unknown",
                        "vuln_type": "unknown",
                        "protocol_type": "unknown",
                        "year": "unknown",
                        "content_hash": content_hash,
                    }
                )
                ids.append(doc_id)
        except Exception as exc:
            logger.warning(f"Failed to process {fp}: {exc}")

    if documents:
        store.add(documents, metadatas, ids)
        logger.info(f"Ingested {len(documents)} pashov chunks")
    return len(documents)


def _chunk_by_sections(text: str, max_chars: int = 512) -> List[str]:
    """Split text into chunks at header boundaries."""
    lines = text.splitlines()
    chunks: List[str] = []
    current: List[str] = []
    for line in lines:
        if line.startswith(("## ", "### ")) and current:
            chunk_text = "\n".join(current).strip()
            if len(chunk_text) > 50:
                chunks.append(chunk_text[:max_chars])
            current = [line]
        else:
            current.append(line)
    if current:
        chunk_text = "\n".join(current).strip()
        if len(chunk_text) > 50:
            chunks.append(chunk_text[:max_chars])
    return chunks


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ingest_pashov_audits.py <repo_path>")
        sys.exit(1)
    count = ingest_pashov_audits(sys.argv[1])
    print(f"Ingested {count} documents")
