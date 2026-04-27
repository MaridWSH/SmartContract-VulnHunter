"""Code segment models for tree-sitter parsing."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class CodeSegment(BaseModel):
    file: str = Field(..., description="Source file path.")
    start_line: int = Field(..., description="1-based start line.")
    end_line: int = Field(..., description="1-based end line (inclusive).")
    kind: str = Field(..., description="contract | function | modifier | event | struct")
    name: str = Field(..., description="Identifier name.")
    source: str = Field(..., description="Full source text of the segment.")
    declared_visibility: Optional[str] = Field(None, description="public | external | internal | private")
    is_payable: bool = Field(False, description="Whether function is payable.")
