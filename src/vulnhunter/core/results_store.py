from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .task import Task


class ResultsStore:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, task_id: str) -> Path:
        return self.output_dir / f"{task_id}.json"

    def save_task(self, task: Task):
        path = self._path(task.id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(task.dict(by_alias=True, exclude_none=True), f, default=str)

    def load_task(self, task_id: str) -> Optional[Task]:
        path = self._path(task_id)
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        try:
            from .task import Task as _Task

            return _Task.parse_obj(data)
        except Exception:
            return None

    def task_exists(self, task_id: str) -> bool:
        return self._path(task_id).exists()
