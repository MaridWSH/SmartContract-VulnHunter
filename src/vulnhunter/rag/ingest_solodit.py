"""Ingest Solodit findings into ChromaDB RAG."""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import List

from vulnhunter.rag.store import VulnStore

logger = logging.getLogger(__name__)


def ingest_solodit(repo_path: str, store: VulnStore | None = None) -> int:
    """Ingest markdown findings from a cloned solodit_content repo.

    Args:
        repo_path: Path to cloned https://github.com/solodit/solodit_content
        store: VulnStore instance (creates default if None)

    Returns:
        Number of documents ingested
    """
    store = store or VulnStore()
    root = Path(repo_path)
    if not root.exists():
        logger.error(f"Solodit repo not found at {repo_path}")
        return 0

    md_files = list(root.rglob("*.md"))
    logger.info(f"Found {len(md_files)} markdown files in Solodit repo")

    documents: List[str] = []
    metadatas: List[dict] = []
    ids: List[str] = []

    for idx, fp in enumerate(md_files, 1):
        try:
            text = fp.read_text(encoding="utf-8")
            # Chunk by sections (## headers)
            chunks = _chunk_markdown(text)
            for chunk_idx, chunk in enumerate(chunks):
                doc_id = f"solodit_{idx}_{chunk_idx}"
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
                        "source": "solodit",
                        "source_url": str(fp),
                        "severity": _extract_severity(chunk),
                        "vuln_type": _extract_vuln_type(chunk),
                        "protocol_type": "unknown",
                        "year": _extract_year(text),
                        "content_hash": content_hash,
                    }
                )
                ids.append(doc_id)
        except Exception as exc:
            logger.warning(f"Failed to process {fp}: {exc}")

    if documents:
        store.add(documents, metadatas, ids)
        logger.info(f"Ingested {len(documents)} Solodit chunks")
    return len(documents)


def _chunk_markdown(text: str, max_chars: int = 512) -> List[str]:
    """Split markdown into chunks at header boundaries."""
    lines = text.splitlines()
    chunks: List[str] = []
    current: List[str] = []
    for line in lines:
        if line.startswith("## ") and current:
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


def _extract_severity(text: str) -> str:
    m = re.search(r"(?i)severity[:\s]*(critical|high|medium|low)", text)
    return m.group(1).lower() if m else "unknown"


def _extract_vuln_type(text: str) -> str:
    types = [
        "reentrancy", "overflow", "access control", "oracle",
        "flash loan", "governance", "timelock", "delegatecall",
    ]
    text_lower = text.lower()
    for t in types:
        if t in text_lower:
            return t
    return "unknown"


def _extract_year(text: str) -> str:
    m = re.search(r"20\d{2}", text)
    return m.group(0) if m else "unknown"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ingest_solodit.py <repo_path>")
        sys.exit(1)
    count = ingest_solodit(sys.argv[1])
    print(f"Ingested {count} documents")
