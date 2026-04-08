"""Git repository cloning functionality for VulnHunter."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    from git import Repo

    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from vulnhunter.config import get_config


class RepoCloner:
    """Clone git repositories for analysis."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or get_config()

    def clone(
        self,
        url: str,
        target_dir: Optional[Path] = None,
        branch: Optional[str] = None,
        depth: int = 1,
        token: Optional[str] = None,
    ) -> Path:
        """Clone a git repository.

        Args:
            url: Repository URL (HTTPS or SSH)
            target_dir: Directory to clone into (default: temp directory)
            branch: Branch to checkout (default: default branch)
            depth: Clone depth for shallow clones (default: 1)
            token: Personal access token for private repos

        Returns:
            Path to cloned repository

        Raises:
            RuntimeError: If git is not available or clone fails
        """
        if not GIT_AVAILABLE:
            raise RuntimeError("GitPython not installed. Run: pip install GitPython")

        # Handle private repos with token
        if token and "github.com" in url:
            url = url.replace("https://", f"https://{token}@")
        elif token and "gitlab.com" in url:
            url = url.replace("https://", f"https://oauth2:{token}@")

        # Determine target directory
        if target_dir is None:
            repo_name = self._extract_repo_name(url)
            target_dir = Path(tempfile.gettempdir()) / f"vulnhunter_{repo_name}"

        # Clone options
        clone_kwargs = {"depth": depth}
        if branch:
            clone_kwargs["branch"] = branch

        try:
            repo = Repo.clone_from(url, target_dir, **clone_kwargs)
            return Path(repo.working_dir)
        except Exception as e:
            raise RuntimeError(f"Failed to clone {url}: {e}")

    def _extract_repo_name(self, url: str) -> str:
        """Extract repository name from URL."""
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return path.split("/")[-1] if "/" in path else path

    def detect_language(self, repo_path: Path) -> str:
        """Detect the primary language of a repository.

        Args:
            repo_path: Path to cloned repository

        Returns:
            Detected language: solidity, vyper, rust, cairo, or unknown
        """
        files = list(repo_path.rglob("*"))

        # Check for Solidity
        if any(f.suffix == ".sol" for f in files):
            return "solidity"

        # Check for Vyper
        if any(f.suffix == ".vy" for f in files):
            return "vyper"

        # Check for Rust/Solana
        if any(f.name == "Cargo.toml" for f in files):
            return "rust"

        # Check for Cairo
        if any(f.suffix == ".cairo" for f in files):
            return "cairo"

        return "unknown"

    def parse_scope(self, repo_path: Path) -> list[str]:
        """Parse scope files to identify in-scope contracts.

        Args:
            repo_path: Path to cloned repository

        Returns:
            List of in-scope file paths
        """
        scope_files = [
            repo_path / "scope.md",
            repo_path / "SCOPE.md",
            repo_path / "README.md",
        ]

        in_scope = []
        for scope_file in scope_files:
            if scope_file.exists():
                content = scope_file.read_text()
                # Simple heuristic: extract file paths mentioned in scope
                # This is a placeholder for more sophisticated parsing
                break

        return in_scope
