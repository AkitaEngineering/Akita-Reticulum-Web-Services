# src/akita_reticulum_web_services/plugins/hexagon/startup_logger.py

import logging
# Import base class using relative path from within the package
from ...hexagon_server import HexagonPluginBase

logger = logging.getLogger(__name__)

class StartupLoggerPlugin(HexagonPluginBase):
    """
    An example Akita Hexagon plugin that logs messages during server
    startup and shutdown lifecycle hooks.
    """

    def load(self):
        """Called when the plugin is initially loaded."""
        logger.info("StartupLoggerPlugin: Loaded.")
        # Could register paths here if needed

    def server_startup(self, config, destination):
        """Called just before the server starts listening."""
        logger.info("StartupLoggerPlugin: Server Startup Hook Called!")
        logger.info(f"  - Configured Serve Directory: {config.get('serve_directory', 'N/A')}")
        logger.info(f"  - Server Destination Hash: {destination.hash if destination else 'N/A'}")
        # Example: Could initialize a database connection here based on config

    def server_shutdown(self):
        """Called just before the Reticulum instance shuts down."""
        logger.info("StartupLoggerPlugin: Server Shutdown Hook Called!")
        # Example: Could close database connections here

    # This plugin doesn't handle requests directly, so other methods are not needed.

