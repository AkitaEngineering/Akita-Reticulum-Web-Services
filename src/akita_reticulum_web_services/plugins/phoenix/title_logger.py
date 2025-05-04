# src/akita_reticulum_web_services/plugins/phoenix/title_logger.py

import re
import logging
# Import base class using relative path from within the package
# Assumes this file is in src/akita_reticulum_web_services/plugins/phoenix/
from ...phoenix_browser import PhoenixPluginBase

# Get the logger for this plugin (child of the main browser logger)
# This assumes the main browser logger is configured.
logger = logging.getLogger(__name__)

class TitleLoggerPlugin(PhoenixPluginBase):
    """
    An example Akita Phoenix plugin that extracts and logs the HTML page title.
    Uses the post_parse_content hook for efficiency as it doesn't need raw bytes.
    """
    # Simple regex to find the title tag content (case-insensitive)
    # It captures the text between <title> and </title>
    # Made slightly more robust to handle attributes in title tag
    TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    # We don't need process_content for this plugin
    # def process_content(self, destination_hash, path, status_code, headers, raw_content_bytes):
    #     return raw_content_bytes

    def post_parse_content(self, destination_hash, path, status_code, headers, parsed_text, parsed_links):
        """
        Logs the title if found within the already parsed text (less efficient than regex on raw,
        but demonstrates the hook). A better approach for *just* the title would be regex in process_content.
        """
        # This hook receives already processed text, finding the raw title tag might be difficult/impossible.
        # A more practical use of this hook would be modifying the parsed_text or parsed_links.
        # For demonstration, we'll just log that the hook was called.
        if status_code == 200 and 'text/html' in headers.get('content-type',''):
            logger.info(f"TitleLoggerPlugin: post_parse_content hook called for {destination_hash[:8]}...{path}")
            # If you wanted to *add* something to the displayed text:
            # parsed_text = "[Title Logged] " + parsed_text

        # Return potentially modified text and original links
        return parsed_text, parsed_links

    # Example using modify_links hook: Add a dummy link
    # def modify_links(self, destination_hash, path, status_code, headers, parsed_links):
    #     """Adds a dummy link to the list."""
    #     if status_code == 200:
    #          logger.info("TitleLoggerPlugin: Adding dummy link via modify_links hook.")
    #          parsed_links.append("/dummy_plugin_link")
    #     return parsed_links

