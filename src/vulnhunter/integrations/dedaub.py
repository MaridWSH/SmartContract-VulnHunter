"""Dedaub API integration for high-quality contract decompilation."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class DecompiledContract:
    """Result of decompiling a contract via Dedaub."""

    address: str
    chain_id: int
    source_code: str
    function_signatures: dict[str, str]
    storage_layout: Optional[dict] = None
    decompiler_version: str = ""
    unresolved_operands: int = 0
    total_operands: int = 0

    @property
    def resolution_rate(self) -> float:
        if self.total_operands == 0:
            return 0.0
        return (self.total_operands - self.unresolved_operands) / self.total_operands


class DedaubClient:
    """Client for the Dedaub decompilation API."""

    BASE_URL = "https://api.dedaub.com/api"

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        self._session = requests.Session()
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    def is_available(self) -> bool:
        """Check if the API key is configured."""
        return self._api_key is not None and len(self._api_key) > 0

    def decompile(
        self,
        address: str,
        chain_id: int = 1,
        cache_dir: Optional[str] = None,
    ) -> Optional[DecompiledContract]:
        """Decompile a contract at the given address.

        Args:
            address: Contract address (with or without 0x prefix)
            chain_id: Chain ID (1=Ethereum mainnet, etc.)
            cache_dir: Directory to cache decompilation results

        Returns:
            DecompiledContract if successful, None otherwise
        """
        if not self.is_available():
            logger.warning("Dedaub API key not configured")
            return None

        # Normalize address
        address = address.lower().strip()
        if not address.startswith("0x"):
            address = "0x" + address

        # Check cache
        if cache_dir:
            cache_path = Path(cache_dir) / f"{chain_id}_{address}.json"
            if cache_path.exists():
                logger.debug(f"Using cached decompilation for {address}")
                return self._load_from_cache(cache_path)

        try:
            # Submit decompilation job
            response = self._session.post(
                f"{self.BASE_URL}/decompile",
                json={"address": address, "chain_id": chain_id},
                timeout=30,
            )
            response.raise_for_status()
            job = response.json()
            job_id = job.get("job_id")

            if not job_id:
                logger.error(f"No job_id in Dedaub response: {job}")
                return None

            # Poll for completion
            result = self._poll_job(job_id, timeout=300)
            if not result:
                return None

            contract = self._parse_result(address, chain_id, result)

            # Save to cache
            if cache_dir and contract:
                self._save_to_cache(Path(cache_dir) / f"{chain_id}_{address}.json", contract, result)

            return contract

        except requests.exceptions.RequestException as exc:
            logger.warning(f"Dedaub API request failed: {exc}")
            return None
        except Exception as exc:
            logger.warning(f"Dedaub decompilation failed: {exc}")
            return None

    def _poll_job(self, job_id: str, timeout: int = 300) -> Optional[dict]:
        """Poll for job completion."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self._session.get(
                    f"{self.BASE_URL}/jobs/{job_id}",
                    timeout=30,
                )
                response.raise_for_status()
                status = response.json()

                if status.get("status") == "completed":
                    return status.get("result")
                elif status.get("status") == "failed":
                    logger.error(f"Dedaub job {job_id} failed: {status.get('error')}")
                    return None

                time.sleep(5)
            except Exception as exc:
                logger.warning(f"Poll error: {exc}")
                time.sleep(5)

        logger.warning(f"Dedaub job {job_id} timed out after {timeout}s")
        return None

    def _parse_result(self, address: str, chain_id: int, result: dict) -> DecompiledContract:
        """Parse API result into DecompiledContract."""
        return DecompiledContract(
            address=address,
            chain_id=chain_id,
            source_code=result.get("source", ""),
            function_signatures=result.get("functions", {}),
            storage_layout=result.get("storage"),
            decompiler_version=result.get("version", ""),
            unresolved_operands=result.get("unresolved_operands", 0),
            total_operands=result.get("total_operands", 0),
        )

    def _load_from_cache(self, path: Path) -> DecompiledContract:
        import json

        with open(path) as f:
            data = json.load(f)
        return self._parse_result(data["address"], data["chain_id"], data)

    def _save_to_cache(self, path: Path, contract: DecompiledContract, result: dict) -> None:
        import json

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(
                {
                    "address": contract.address,
                    "chain_id": contract.chain_id,
                    **result,
                },
                f,
                indent=2,
            )
