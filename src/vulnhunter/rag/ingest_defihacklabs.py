"""Ingest DeFiHackLabs PoCs into ChromaDB RAG."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import List

from vulnhunter.rag.store import VulnStore

logger = logging.getLogger(__name__)


def ingest_defihacklabs(repo_path: str, store: VulnStore | None = None) -> int:
    """Ingest PoC code from a cloned DeFiHackLabs repo.

    Args:
        repo_path: Path to cloned https://github.com/SunWeb3Sec/DeFiHackLabs
        store: VulnStore instance (creates default if None)

    Returns:
        Number of documents ingested
    """
    store = store or VulnStore()
    root = Path(repo_path)
    if not root.exists():
        logger.error(f"DeFiHackLabs repo not found at {repo_path}")
        return 0

    # Find Solidity PoC files
    sol_files = list(root.rglob("*.sol"))
    logger.info(f"Found {len(sol_files)} Solidity files in DeFiHackLabs")

    documents: List[str] = []
    metadatas: List[dict] = []
    ids: List[str] = []

    for idx, fp in enumerate(sol_files, 1):
        try:
            text = fp.read_text(encoding="utf-8")
            # Chunk by function
            chunks = _chunk_by_functions(text)
            for chunk_idx, chunk in enumerate(chunks):
                doc_id = f"defihacklabs_{idx}_{chunk_idx}"
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
                        "source": "defihacklabs",
                        "source_url": str(fp),
                        "severity": "high",
                        "vuln_type": "unknown",
                        "protocol_type": "defi",
                        "year": "unknown",
                        "content_hash": content_hash,
                    }
                )
                ids.append(doc_id)
        except Exception as exc:
            logger.warning(f"Failed to process {fp}: {exc}")

    if documents:
        store.add(documents, metadatas, ids)
        logger.info(f"Ingested {len(documents)} DeFiHackLabs chunks")
    return len(documents)


def _chunk_by_functions(text: str, max_chars: int = 512) -> List[str]:
    """Split Solidity code into function-level chunks."""
    lines = text.splitlines()
    chunks: List[str] = []
    current: List[str] = []
    in_function = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("function ") or stripped.startswith("constructor("):
            if current:
                chunk_text = "\n".join(current).strip()
                if len(chunk_text) > 30:
                    chunks.append(chunk_text[:max_chars])
            current = [line]
            in_function = True
        elif in_function and stripped == "}":
            current.append(line)
            chunk_text = "\n".join(current).strip()
            if len(chunk_text) > 30:
                chunks.append(chunk_text[:max_chars])
            current = []
            in_function = False
        else:
            current.append(line)

    if current:
        chunk_text = "\n".join(current).strip()
        if len(chunk_text) > 30:
            chunks.append(chunk_text[:max_chars])
    return chunks


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ingest_defihacklabs.py <repo_path>")
        sys.exit(1)
    count = ingest_defihacklabs(sys.argv[1])
    print(f"Ingested {count} documents")
