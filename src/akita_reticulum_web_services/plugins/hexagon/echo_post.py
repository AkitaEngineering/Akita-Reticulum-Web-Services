# src/akita_reticulum_web_services/plugins/hexagon/echo_post.py

import logging
from urllib.parse import parse_qs
# Import base class using relative path from within the package
from ...hexagon_server import HexagonPluginBase, send_response # Import send_response helper

logger = logging.getLogger(__name__)

class EchoPostPlugin(HexagonPluginBase):
    """
    An example Akita Hexagon plugin that handles POST requests to '/echo'
    and echoes back the received form data.
    """

    ECHO_PATH = '/echo' # The path this plugin handles

    def load(self):
        """Register the path handler when the plugin loads."""
        self.register_path_handler(self.ECHO_PATH, self)
        logger.info(f"EchoPostPlugin loaded and registered handler for {self.ECHO_PATH}")

    def handle_registered_path(self, link, request_line, method, path, headers, body_bytes, serve_directory):
        """Handles requests specifically for the registered '/echo' path."""

        if path != self.ECHO_PATH:
            logger.warning(f"EchoPostPlugin received mismatched path '{path}'. Declining.")
            return False # Let server handle (404)

        if method != "POST":
            status = 405; status_text = "Method Not Allowed"
            resp_headers = {"Allow": "POST", "Content-Type": "text/plain; charset=utf-8"}
            resp_body = b"405 Method Not Allowed: Only POST is supported on /echo."
            send_response(link, status, status_text, resp_headers, resp_body)
            logger.info(f"Sent 405 for non-POST request to {self.ECHO_PATH}")
            return True # Handled (with error)

        # --- Handle POST ---
        logger.info(f"EchoPostPlugin handling POST request to {self.ECHO_PATH}")
        status = 200; status_text = "OK"
        resp_headers = {"Content-Type": "text/plain; charset=utf-8"}
        resp_body_str = "Received POST data:\n"

        content_type = headers.get('content-type', '').lower()
        if 'application/x-www-form-urlencoded' in content_type:
            try:
                body_str = body_bytes.decode('utf-8')
                parsed_data = parse_qs(body_str, keep_blank_values=True)
                if parsed_data:
                    for key, values in parsed_data.items():
                        value_str = ", ".join(values) # Handle multiple values for same key
                        resp_body_str += f"- {key}: {value_str}\n"
                else: resp_body_str += "(No form data found in body)\n"
            except UnicodeDecodeError: logger.warning("Could not decode POST body as UTF-8."); resp_body_str += "(Error: Could not decode body)\n"; status = 400; status_text = "Bad Request"
            except Exception as e: logger.error(f"Error parsing form data: {e}"); resp_body_str += f"(Error parsing form data)\n"; status = 400; status_text = "Bad Request"
        else:
            resp_body_str += f"(Received unsupported content type: {content_type})\n"
            resp_body_str += f"Raw Body ({len(body_bytes)} bytes):\n"
            try: display_body = body_bytes[:200].decode('utf-8', errors='replace');
            if len(body_bytes) > 200: display_body += "..."; resp_body_str += display_body
            except Exception: resp_body_str += "(Could not decode body for display)"

        resp_body = resp_body_str.encode('utf-8')
        resp_headers['Content-Length'] = str(len(resp_body))
        send_response(link, status, status_text, resp_headers, resp_body)
        return True # Handled

