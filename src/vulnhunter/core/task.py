from __future__ import annotations

import uuid
from enum import Enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    label: str
    detail: Optional[str] = None
    severity: Optional[str] = None
    data: Optional[dict] = None


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class Task(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str
    target: str
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Finding] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
