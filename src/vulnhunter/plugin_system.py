"""Plugin system for vulnhunter using pluggy.

This module provides a plugin architecture that allows external packages
to extend vulnhunter functionality through hook-based plugins.
"""

import logging
from typing import Any, List

import pluggy
import typer

logger = logging.getLogger(__name__)

# Plugin hook namespace
PLUGIN_NAMESPACE = "vulnhunter"

# Entry point group for discovering plugins
ENTRY_POINT_GROUP = "vulnhunter.plugins"


class PluginHooks:
    """Hook specifications for vulnhunter plugins.

    Plugins implement these hooks to extend vulnhunter functionality.
    """

    @pluggy.Hookspec
    def register_commands(self, app: typer.Typer) -> None:
        """Register custom CLI commands with the vulnhunter application.

        Args:
            app: The typer.Typer application instance to register commands with.

        Example:
            def register_commands(self, app: typer.Typer) -> None:
                @app.command(name="my-command")
                def my_command():
                    print("Hello from plugin!")
        """
        ...


class PluginManager:
    """Manages plugin loading and registration for vulnhunter.

    This class handles discovery and loading of plugins via entry points,
    and manages hook calls for extending application functionality.

    Example:
        >>> manager = PluginManager()
        >>> manager.load_plugins()
        >>> manager.register_commands(app)
    """

    def __init__(self) -> None:
        """Initialize the plugin manager with hook specifications."""
        self.plugin_manager = pluggy.PluginManager(PLUGIN_NAMESPACE)
        self.plugin_manager.add_hookspecs(PluginHooks)
        self._loaded_plugins: List[str] = []

    def load_plugins(self) -> List[str]:
        """Load plugins from entry points.

        Discovers and loads plugins registered under the 'vulnhunter.plugins'
        entry point group. Each plugin module found is registered with the
        hook system.

        Returns:
            List of loaded plugin names.

        Raises:
            ImportError: If a plugin module cannot be imported.
            Exception: If a plugin fails to register.
        """
        loaded: List[str] = []

        try:
            # Get entry points for the plugin group
            eps = self.plugin_manager.get_plugin(ENTRY_POINT_GROUP)

            # Use importlib.metadata for Python 3.10+
            try:
                from importlib.metadata import entry_points
            except ImportError:
                from importlib_metadata import entry_points  # type: ignore

            all_eps = entry_points()

            # Handle different return types from entry_points()
            if hasattr(all_eps, "select"):
                # Python 3.10+ style
                plugin_eps = all_eps.select(group=ENTRY_POINT_GROUP)
            else:
                # Older style - dict-like
                plugin_eps = all_eps.get(ENTRY_POINT_GROUP, [])

            for ep in plugin_eps:
                try:
                    plugin = ep.load()
                    self.plugin_manager.register(plugin)
                    loaded.append(ep.name)
                    logger.info(f"Loaded plugin: {ep.name}")
                except Exception as exc:
                    logger.warning(f"Failed to load plugin {ep.name}: {exc}")

        except Exception as exc:
            logger.warning(f"Error loading plugins: {exc}")

        self._loaded_plugins = loaded
        return loaded

    def register_commands(self, app: typer.Typer) -> None:
        """Register commands from all loaded plugins.

        Calls the 'register_commands' hook on all registered plugins,
        allowing them to add custom CLI commands to the application.

        Args:
            app: The typer.Typer application instance.
        """
        results = self.plugin_manager.hook.register_commands(app=app)
        logger.debug(f"Registered commands from {len(results or [])} plugins")

    def get_loaded_plugins(self) -> List[str]:
        """Get list of successfully loaded plugin names.

        Returns:
            List of plugin names that were successfully loaded.
        """
        return self._loaded_plugins.copy()

    def is_plugin_loaded(self, name: str) -> bool:
        """Check if a specific plugin is loaded.

        Args:
            name: The name of the plugin to check.

        Returns:
            True if the plugin is loaded, False otherwise.
        """
        return name in self._loaded_plugins


# Global plugin manager instance
_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Get or create the global plugin manager instance.

    Returns:
        The global PluginManager instance.
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def reset_plugin_manager() -> None:
    """Reset the global plugin manager (useful for testing).

        Clears the cached plugin manager instance, forcing a new one
    to be created on the next call to get_plugin_manager().
    """
    global _plugin_manager
    _plugin_manager = None
