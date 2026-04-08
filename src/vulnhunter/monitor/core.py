"""Vaulthunter 24/7 Continuous Monitoring System.

Monitors blockchain for new contracts, upgrades, and suspicious activity.
Integrates with VulnHunter for automated scanning.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable
import time

sys.path.insert(0, "/home/ubuntu/SC-CLI/src")

from vulnhunter.core.orchestrator import Orchestrator
from vulnhunter.core.task import Task
from vulnhunter.config import get_config


@dataclass
class MonitoredTarget:
    """A target being monitored by Vaulthunter."""

    id: str
    name: str
    target_type: str  # 'contract', 'repo', 'directory'
    path: str
    scan_interval: int = 3600  # seconds
    last_scan: Optional[datetime] = None
    last_findings_count: int = 0
    is_active: bool = True
    alert_threshold: str = "MEDIUM"  # MINIMUM severity to alert
    webhook_url: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanEvent:
    """An event from a scan."""

    timestamp: datetime
    target_id: str
    severity: str
    finding_type: str
    description: str
    location: str
    similar_vulns: List[Dict] = field(default_factory=list)


class VaulthunterMonitor:
    """24/7 continuous monitoring for smart contract security."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = get_config()
        self.targets: Dict[str, MonitoredTarget] = {}
        self.orchestrator: Optional[Orchestrator] = None
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._alert_handlers: List[Callable] = []
        self._storage_path = Path("./vaulthunter-data")
        self._storage_path.mkdir(exist_ok=True)

    async def start(self):
        """Start the 24/7 monitoring loop."""
        self._running = True
        self.orchestrator = Orchestrator(max_concurrent=3, config=self.config)

        # Load persisted targets
        self._load_targets()

        # Start monitoring tasks
        for target_id in self.targets:
            task = asyncio.create_task(self._monitor_target(target_id))
            self._tasks.append(task)

        # Start heartbeat
        heartbeat_task = asyncio.create_task(self._heartbeat())
        self._tasks.append(heartbeat_task)

        print(f"[Vaulthunter] Started monitoring {len(self.targets)} targets")

        # Wait for all tasks
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def stop(self):
        """Stop the monitoring loop."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        print("[Vaulthunter] Stopped monitoring")

    def add_target(self, target: MonitoredTarget) -> str:
        """Add a new target to monitor."""
        self.targets[target.id] = target
        self._save_targets()

        # Start monitoring if running
        if self._running:
            task = asyncio.create_task(self._monitor_target(target.id))
            self._tasks.append(task)

        return target.id

    def remove_target(self, target_id: str) -> bool:
        """Remove a target from monitoring."""
        if target_id in self.targets:
            del self.targets[target_id]
            self._save_targets()
            return True
        return False

    def list_targets(self) -> List[MonitoredTarget]:
        """List all monitored targets."""
        return list(self.targets.values())

    def on_alert(self, handler: Callable):
        """Register an alert handler."""
        self._alert_handlers.append(handler)

    async def _monitor_target(self, target_id: str):
        """Monitor a single target continuously."""
        while self._running:
            try:
                target = self.targets.get(target_id)
                if not target or not target.is_active:
                    await asyncio.sleep(60)
                    continue

                # Check if it's time to scan
                if target.last_scan:
                    elapsed = (datetime.utcnow() - target.last_scan).total_seconds()
                    if elapsed < target.scan_interval:
                        await asyncio.sleep(min(60, target.scan_interval - elapsed))
                        continue

                # Run scan
                await self._scan_target(target)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Vaulthunter] Error monitoring {target_id}: {e}")
                await asyncio.sleep(300)  # Wait 5 min on error

    async def _scan_target(self, target: MonitoredTarget):
        """Scan a target and process findings."""
        print(f"[Vaulthunter] Scanning {target.name}...")

        from vulnhunter.commands.scan import get_available_adapters
        from vulnhunter.core.sarif_merger import SarifMerger
        from vulnhunter.core.deduplicator import Deduplicator

        # Get adapters
        adapters = get_available_adapters(target.path)
        if not adapters:
            print(f"[Vaulthunter] No adapters available for {target.name}")
            return

        # Create tasks
        scan_tasks = [
            Task(tool=name, target=target.path, timeout_seconds=600) for name, _ in adapters
        ]
        adapter_dict = {name: adapter for name, adapter in adapters}

        # Run scan
        results = await self.orchestrator.run_parallel(scan_tasks, adapter_dict)

        # Collect findings
        all_findings = []
        for task_result in results:
            if task_result.status.value == "COMPLETED" and task_result.result:
                if isinstance(task_result.result, list):
                    all_findings.extend(task_result.result)
                else:
                    all_findings.append(task_result.result)

        # Enrich with Solodit
        try:
            from vulnhunter.solodit.enricher import SoloditEnricher

            enricher = SoloditEnricher()
            enriched = await enricher.enrich_findings(all_findings)
            all_findings = enriched
        except Exception as e:
            print(f"[Vaulthunter] Solodit enrichment failed: {e}")

        # Check for alerts
        new_findings = len(all_findings) - target.last_findings_count
        if new_findings > 0:
            await self._trigger_alert(target, all_findings, new_findings)

        # Update target
        target.last_scan = datetime.utcnow()
        target.last_findings_count = len(all_findings)
        self._save_targets()

        print(f"[Vaulthunter] Scan complete for {target.name}: {len(all_findings)} findings")

    async def _trigger_alert(self, target: MonitoredTarget, findings: List, new_count: int):
        """Trigger alerts for new findings."""
        # Filter by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        threshold_level = severity_order.get(target.alert_threshold, 2)

        alert_findings = []
        for finding in findings:
            sev = getattr(finding, "severity", "INFO")
            if severity_order.get(sev, 4) <= threshold_level:
                alert_findings.append(finding)

        if not alert_findings:
            return

        # Create alert
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "target": target.name,
            "target_id": target.id,
            "new_findings": new_count,
            "total_findings": len(findings),
            "severity_breakdown": self._count_by_severity(alert_findings),
            "findings": [
                {
                    "severity": getattr(f, "severity", "UNKNOWN"),
                    "type": getattr(f, "check", "unknown"),
                    "description": getattr(f, "description", "")[:200],
                }
                for f in alert_findings[:5]  # Top 5
            ],
        }

        # Send to handlers
        for handler in self._alert_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                print(f"[Vaulthunter] Alert handler error: {e}")

        # Webhook
        if target.webhook_url:
            await self._send_webhook(target.webhook_url, alert)

    async def _send_webhook(self, url: str, alert: Dict):
        """Send alert to webhook."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=alert) as resp:
                    print(f"[Vaulthunter] Webhook sent: {resp.status}")
        except Exception as e:
            print(f"[Vaulthunter] Webhook failed: {e}")

    def _count_by_severity(self, findings: List) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for f in findings:
            sev = getattr(f, "severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    async def _heartbeat(self):
        """Send periodic heartbeat."""
        while self._running:
            print(
                f"[Vaulthunter] Heartbeat - {len(self.targets)} targets, {datetime.utcnow().isoformat()}"
            )
            await asyncio.sleep(300)  # 5 minutes

    def _load_targets(self):
        """Load targets from storage."""
        targets_file = self._storage_path / "targets.json"
        if targets_file.exists():
            with open(targets_file) as f:
                data = json.load(f)
                for t in data:
                    target = MonitoredTarget(**t)
                    if isinstance(target.created_at, str):
                        target.created_at = datetime.fromisoformat(target.created_at)
                    if target.last_scan and isinstance(target.last_scan, str):
                        target.last_scan = datetime.fromisoformat(target.last_scan)
                    self.targets[target.id] = target

    def _save_targets(self):
        """Save targets to storage."""
        targets_file = self._storage_path / "targets.json"
        data = []
        for target in self.targets.values():
            t = asdict(target)
            # Convert datetime to string
            if isinstance(t["created_at"], datetime):
                t["created_at"] = t["created_at"].isoformat()
            if t["last_scan"] and isinstance(t["last_scan"], datetime):
                t["last_scan"] = t["last_scan"].isoformat()
            data.append(t)

        with open(targets_file, "w") as f:
            json.dump(data, f, indent=2)


# Global monitor instance
_monitor_instance: Optional[VaulthunterMonitor] = None


def get_monitor() -> VaulthunterMonitor:
    """Get the global monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = VaulthunterMonitor()
    return _monitor_instance
