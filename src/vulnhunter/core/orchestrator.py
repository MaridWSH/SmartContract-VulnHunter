from __future__ import annotations

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

from .task import Task, TaskStatus, Finding
from .results_store import ResultsStore
from ..adapters.base import ToolAdapter


class AppConfig:
    def __init__(self, default_timeout: int = 60):
        self.default_timeout = default_timeout


def get_config() -> AppConfig:
    return AppConfig()


class Orchestrator:
    def __init__(self, max_concurrent: int = 5, config: Optional[AppConfig] = None):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.config = config or get_config()
        self.results: List[Task] = []
        self.store = ResultsStore(Path("./vulnhunter_results"))

    def should_skip(self, task: Task) -> bool:
        existing = None
        if self.store.task_exists(task.id):
            existing = self.store.load_task(task.id)
        if existing and existing.status == TaskStatus.COMPLETED:
            task.status = existing.status
            task.started_at = existing.started_at
            task.completed_at = existing.completed_at
            task.result = existing.result
            task.error = existing.error
            task.exit_code = existing.exit_code
            return True
        return False

    async def run_task(self, task: Task, adapter: Optional[ToolAdapter]) -> Task:
        if self.should_skip(task):
            return task
        if adapter is None:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            task.error = f"No adapter available for tool '{task.tool}'"
            self.results.append(task)
            self.store.save_task(task)
            return task

        async with self.semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            try:
                timeout = getattr(self.config, "default_timeout", 60)
                findings = await asyncio.wait_for(
                    adapter.run(task.target), timeout=timeout
                )
                task.completed_at = datetime.utcnow()
                task.status = TaskStatus.COMPLETED
                task.exit_code = 0
                if isinstance(findings, list) and len(findings) > 0:
                    task.result = findings[0]
                else:
                    task.result = None
                task.error = None
            except asyncio.TimeoutError:
                task.completed_at = datetime.utcnow()
                task.status = TaskStatus.TIMEOUT
                task.error = "timeout"
                task.exit_code = -1
            except Exception as e:
                task.completed_at = datetime.utcnow()
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.exit_code = getattr(e, "errno", -1)
            finally:
                self.results.append(task)
                self.store.save_task(task)
                return task

    async def run_parallel(
        self, tasks: List[Task], adapters: Dict[str, ToolAdapter]
    ) -> List[Task]:
        coros = []
        for t in tasks:
            adapter = adapters.get(t.tool)
            if self.should_skip(t):
                # Already completed and persisted; skip re-execution
                coros.append(asyncio.sleep(0, result=t))
            elif adapter is None:
                t.status = TaskStatus.FAILED
                t.completed_at = datetime.utcnow()
                t.error = f"No adapter available for tool '{t.tool}'"
                self.results.append(t)
                self.store.save_task(t)
                coros.append(asyncio.sleep(0, result=t))
            else:
                coros.append(self.run_task(t, adapter))
        results = await asyncio.gather(*coros)
        return list(results)
