from .base import BaseReporter
from .immunefi import ImmunefiReporter
from .code4rena import Code4renaReporter
from .sherlock import SherlockReporter
from .codehawks import CodehawksReporter
from typing import Type, Dict


def get_reporter(platform: str) -> BaseReporter:
    """Factory function to get a reporter instance by platform name.

    Args:
        platform: Platform name (case-insensitive)
                 Supported: 'immunefi', 'code4rena', 'sherlock', 'codehawks'

    Returns:
        BaseReporter: Instance of the appropriate reporter

    Raises:
        ValueError: If platform is not supported
    """
    reporters: Dict[str, Type[BaseReporter]] = {
        "immunefi": ImmunefiReporter,
        "code4rena": Code4renaReporter,
        "sherlock": SherlockReporter,
        "codehawks": CodehawksReporter,
    }

    platform_lower = platform.lower()
    if platform_lower not in reporters:
        raise ValueError(
            f"Unknown platform: {platform}. "
            f"Supported platforms: {', '.join(reporters.keys())}"
        )

    return reporters[platform_lower]()


def list_platforms() -> list[str]:
    """Return list of supported platform names."""
    return ["immunefi", "code4rena", "sherlock", "codehawks"]


__all__ = [
    "BaseReporter",
    "ImmunefiReporter",
    "Code4renaReporter",
    "SherlockReporter",
    "CodehawksReporter",
    "get_reporter",
    "list_platforms",
]
