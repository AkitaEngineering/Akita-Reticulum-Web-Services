# src/akita_reticulum_web_services/plugins/phoenix/title_logger.py

import re
import logging
# Import base class relative to the package structure
from ...phoenix_browser import PhoenixPluginBase

# Get the logger for this plugin (child of the main browser logger)
# This assumes the main browser logger is configured.
logger = logging.getLogger(__name__)

class TitleLoggerPlugin(PhoenixPluginBase):
    """
    A simple Akita Phoenix plugin that extracts and logs the HTML page title.
    """
    # Simple regex to find the title tag content (case-insensitive)
    # It captures the text between <title> and </title>
    # Made slightly more robust to handle attributes in title tag
    TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    def process_content(self, destination_hash, path, status_code, headers, raw_content_bytes):
        """
        Processes the raw HTML content to find and log the title tag.
        This hook runs *before* the default HTML parser.
        """
        # Only process successful responses with content
        if status_code == 200 and raw_content_bytes:
            try:
                # Decode cautiously, assuming UTF-8 or Latin-1 as fallbacks
                # This plugin only needs a small part, so full decoding might not be necessary
                # if performance were critical, but for simplicity, we decode a portion.
                decoded_head = None
                try:
                    # Try decoding based on headers if available, else default to utf-8
                    encoding = 'utf-8' # Default
                    content_type = headers.get('content-type', '').lower()
                    if 'charset=' in content_type:
                        try:
                            encoding = content_type.split('charset=')[-1].split(';')[0].strip()
                            # Validate encoding briefly
                            import codecs
                            codecs.lookup(encoding)
                        except (LookupError, IndexError):
                            logger.debug(f"Invalid charset in header, using default utf-8.")
                            encoding = 'utf-8'

                    # Limit the amount of data decoded for title search (e.g., first 4KB)
                    # This avoids decoding huge files just to find the title near the beginning.
                    decoded_head = raw_content_bytes[:4096].decode(encoding, errors='ignore')
                    logger.debug(f"Title search using encoding: {encoding}")

                except (LookupError, UnicodeDecodeError) as e:
                     # Fallback decoding if specified encoding fails or isn't found
                     logger.debug(f"Encoding '{encoding}' failed ({e}), falling back to utf-8/latin-1 for title search.")
                     try:
                         decoded_head = raw_content_bytes[:4096].decode('utf-8', errors='ignore')
                     except UnicodeDecodeError:
                         # If utf-8 fails, latin-1 is usually safe for finding ASCII tags
                         decoded_head = raw_content_bytes[:4096].decode('latin-1', errors='ignore')
                except Exception as e:
                     logger.error(f"Unexpected error during decoding for title search: {e}")
                     # Cannot proceed with title search if decoding fails badly

                # Search for title if decoding produced results
                if decoded_head:
                    match = self.TITLE_REGEX.search(decoded_head)
                    if match:
                        # Extract title, strip whitespace, replace internal newlines/tabs with spaces
                        title = ' '.join(match.group(1).split()).strip()
                        # Log the title using the plugin's logger
                        logger.info(f"Page Title Found: '{title}' (for {destination_hash[:8]}...{path})")
                        # Optionally, print to console as well:
                        # print(f"[Plugin: Title Logger] Title: {title}")
                    else:
                        logger.info(f"No <title> tag found in the first 4KB of {destination_hash[:8]}...{path}")
                else:
                     logger.warning("Could not decode start of content to search for title.")


            except Exception as e:
                # Log errors during plugin execution but don't crash the browser
                logger.error(f"TitleLoggerPlugin error processing content: {e}", exc_info=True)

        # IMPORTANT: Return the original content bytes unmodified,
        # as this plugin only inspects, it doesn't change the content for the main parser.
        return raw_content_bytes

