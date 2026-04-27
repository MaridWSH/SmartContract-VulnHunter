"""Tenderly fork integration for PoC validation against mainnet state."""

from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class TenderlyClient:
    """Client for Tenderly fork API."""

    def __init__(self, access_key: str, account_slug: str, project_slug: str):
        self.access_key = access_key
        self.account_slug = account_slug
        self.project_slug = project_slug
        self.base_url = "https://api.tenderly.co/api/v1"
        self._client = httpx.AsyncClient(
            headers={"X-Access-Key": access_key},
            timeout=30.0,
        )

    async def create_fork(
        self, chain_id: int = 1, block_number: Optional[int] = None
    ) -> "ForkHandle":
        """Create a new Tenderly fork."""
        url = f"{self.base_url}/account/{self.account_slug}/project/{self.project_slug}/fork"
        payload = {"network_id": str(chain_id)}
        if block_number:
            payload["block_number"] = block_number

        resp = await self._client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        fork_id = data["simulation_fork"]["id"]
        rpc_url = f"https://rpc.tenderly.co/fork/{fork_id}"
        return ForkHandle(self, fork_id, rpc_url)

    async def delete_fork(self, fork_id: str) -> None:
        url = f"{self.base_url}/account/{self.account_slug}/project/{self.project_slug}/fork/{fork_id}"
        try:
            resp = await self._client.delete(url)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"Failed to delete Tenderly fork {fork_id}: {exc}")


class ForkHandle:
    """Context manager for a Tenderly fork."""

    def __init__(self, client: TenderlyClient, fork_id: str, rpc_url: str):
        self.client = client
        self.fork_id = fork_id
        self.rpc_url = rpc_url

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.delete_fork(self.fork_id)
        return False
