# src/akita_reticulum_web_services/hexagon_server.py

import RNS
import os
import threading
import time
import logging
import json
import mimetypes # For guessing content types
import importlib
import sys
from pathlib import Path

# --- Constants ---
SERVER_APP_NAME = "akita_web"
SERVER_ASPECT = "hexagon"
DEFAULT_SERVE_DIR = Path("./examples") # Default relative to where script is run
MAX_REQUEST_SIZE = 8192 # Increased max request size slightly
CONFIG_DIR = Path(os.path.expanduser("~/.config/akita-hexagon"))
DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.json"
SERVER_PLUGIN_DIR = Path(__file__).parent / "plugins" / "hexagon"

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__) # Module-specific logger
logger.addHandler(log_handler)
logger.setLevel(logging.INFO) # Default level, can be changed by config/args

# --- Global State ---
loaded_server_plugins = []

# --- Server Plugin Base Class ---
class HexagonPluginBase:
    """Base class for Akita Hexagon server plugins."""

    def process_request(self, link, request_line, headers, serve_directory):
        """
        Hook to process a request before default file serving.
        Plugins can handle the request entirely, modify parameters, or just observe.

        Args:
            link (RNS.Link): The client link object.
            request_line (str): The first line of the HTTP request (e.g., "GET /path HTTP/1.0").
            headers (dict): Dictionary of request headers (lowercase keys).
            serve_directory (Path): The configured base directory for serving files.

        Returns:
            bool: True if the request was fully handled by this plugin (prevents further processing).
                  False otherwise (allows default processing or other plugins to run).
        """
        # Default implementation does nothing and allows further processing
        return False

    def modify_response(self, link, request_line, req_headers, status_code, resp_headers, resp_body_bytes):
        """
        Hook to modify the response just before it's sent to the client.

        Args:
            link (RNS.Link): The client link object.
            request_line (str): The original request line.
            req_headers (dict): The original request headers.
            status_code (int): The status code determined by the server or previous plugins.
            resp_headers (dict): Response headers prepared by the server (lowercase keys).
                                 Modifications to this dict *will* be sent.
            resp_body_bytes (bytes): Response body prepared by the server.

        Returns:
            tuple: (new_status_code, new_resp_headers_dict, new_resp_body_bytes)
                   Return the original values to pass through unmodified.
                   Changes will be reflected in the final response sent to the client.
        """
        # Default implementation returns everything unmodified
        return status_code, resp_headers, resp_body_bytes

# --- Plugin Loading ---
def load_server_plugins():
    """Loads server plugins from the plugin directory."""
    global loaded_server_plugins
    loaded_server_plugins = []
    plugin_dir_path = SERVER_PLUGIN_DIR.resolve() # Ensure path is absolute
    if not plugin_dir_path.is_dir():
        logger.info(f"Server plugin directory {plugin_dir_path} not found. No plugins loaded.")
        return

    logger.info(f"Loading server plugins from: {plugin_dir_path}")
    # Ensure plugin directory structure is importable
    # Add the 'src' directory to sys.path if not already present
    src_dir_path = plugin_dir_path.parent.parent.parent
    if str(src_dir_path) not in sys.path:
         sys.path.insert(0, str(src_dir_path))
         logger.debug(f"Added {src_dir_path} to sys.path for plugin loading")


    for filename in plugin_dir_path.glob("*.py"):
        if filename.name == "__init__.py":
            continue
        # Construct module path relative to 'src' like 'akita_reticulum_web_services.plugins.hexagon.my_plugin'
        relative_module_path = filename.relative_to(src_dir_path)
        module_name_parts = list(relative_module_path.parts[:-1]) + [filename.stem]
        module_name = ".".join(module_name_parts)

        logger.debug(f"Attempting to import server plugin module: {module_name}")
        try:
            module = importlib.import_module(module_name)
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if isinstance(attribute, type) and issubclass(attribute, HexagonPluginBase) and attribute is not HexagonPluginBase:
                    try:
                        plugin_instance = attribute()
                        loaded_server_plugins.append(plugin_instance)
                        logger.info(f"Successfully loaded server plugin: {attribute_name} from {filename.name}")
                    except Exception as e:
                        logger.error(f"Failed to instantiate server plugin {attribute_name} from {filename.name}: {e}", exc_info=True)
        except ImportError as e:
            logger.error(f"Failed to import server plugin module {module_name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error loading server plugin from {filename.name}: {e}", exc_info=True)

    logger.info(f"Loaded {len(loaded_server_plugins)} server plugin(s).")

# --- Configuration Loading ---
def load_config(config_file=DEFAULT_CONFIG_FILE):
    """Loads configuration from a JSON file."""
    # Resolve paths relative to the config file's directory if they are relative
    config_file_abs = config_file.resolve()
    config_dir_abs = config_file_abs.parent

    defaults = {
        "serve_directory": str(DEFAULT_SERVE_DIR), # Default relative to CWD initially
        "interface": None, # Let RNS auto-detect by default
        "log_level": "INFO",
        "server_identity_path": str(CONFIG_DIR / "identity") # Default in standard config location
    }
    config = defaults.copy() # Start with defaults

    try:
        if config_file_abs.exists():
            with open(config_file_abs, 'r') as f:
                loaded_config = json.load(f)
            logger.info(f"Loaded configuration from {config_file_abs}")
            # Merge loaded config, potentially overriding defaults
            config.update(loaded_config)
        else:
            logger.info(f"Config file {config_file_abs} not found. Using default settings.")
            # Keep the defaults loaded initially

    except (json.JSONDecodeError, IOError, TypeError) as e:
        logger.error(f"Error loading config file {config_file_abs}: {e}. Using default settings.")
        config = defaults.copy() # Reset to defaults if file is corrupt

    # Resolve paths *after* loading/merging config
    # Resolve serve_directory relative to CWD if it's relative
    config['serve_directory'] = str(Path(config['serve_directory']).resolve())
    # Resolve identity_path relative to config file dir if relative, else keep absolute
    id_path = Path(config['server_identity_path'])
    if not id_path.is_absolute():
         config['server_identity_path'] = str((config_dir_abs / id_path).resolve())
    else:
         config['server_identity_path'] = str(id_path.resolve()) # Ensure absolute paths are resolved too


    return config

# --- Request Handling ---
def send_response(link, status_code, status_text, headers, body_bytes):
    """Constructs and sends an HTTP response."""
    # Ensure body_bytes is bytes
    if body_bytes is None:
        body_bytes = b""
    elif not isinstance(body_bytes, bytes):
        logger.error(f"Invalid body type passed to send_response: {type(body_bytes)}. Converting to bytes.")
        try:
            body_bytes = str(body_bytes).encode('utf-8')
        except Exception:
            body_bytes = b"Error: Could not encode body"
            status_code = 500
            status_text = "Internal Server Error"

    # Ensure headers are strings
    final_headers = {}
    for k, v in headers.items():
        final_headers[str(k)] = str(v)

    try:
        response_line = f"HTTP/1.0 {status_code} {status_text}\r\n"
        header_lines = "".join([f"{k}: {v}\r\n" for k, v in final_headers.items()])
        response = response_line.encode('utf-8') + header_lines.encode('utf-8') + b"\r\n" + body_bytes

        # Log before sending potentially large data
        logger.info(f"Sending response to {link.destination.hash[:10]}: {status_code} {status_text} ({len(body_bytes)} bytes)")
        link.send(response)

    except RNS.LinkTimeout:
         logger.warning(f"Timeout sending response to {link.destination.hash[:10]}.")
    except RNS.LinkError as e:
         logger.error(f"Link error sending response to {link.destination.hash[:10]}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending response to {link.destination.hash[:10]}: {e}", exc_info=True)


def handle_client_request(link, serve_directory_path):
    """Handles an incoming client connection and request."""
    global loaded_server_plugins
    request_data = b""
    client_info = link.destination.hash[:10]
    request_line = ""
    req_headers = {}
    status_code = 500 # Default internal error until success
    resp_headers = {"Server": "Akita-Hexagon", "Connection": "close"}
    resp_body = b"" # Default empty body

    try:
        logger.info(f"Connection established with {client_info}")
        link.set_link_timeout(15) # Slightly longer timeout for link activity

        # Receive the request header data
        while b"\r\n\r\n" not in request_data and len(request_data) < MAX_REQUEST_SIZE:
            incoming_message = link.receive(timeout=10) # Timeout for receiving parts
            if not incoming_message:
                if not request_data: # Timeout before receiving anything
                     logger.warning(f"Timeout waiting for request from {client_info}")
                     # Do not send response on initial timeout, just close.
                     return
                else: # Timeout after receiving partial data
                     logger.warning(f"Timeout waiting for complete request header from {client_info}")
                     status_code, resp_headers, resp_body = 408, resp_headers, b"408 Request Timeout"
                     break # Go to send response

            request_data += incoming_message.content
            # Check size *after* appending
            if len(request_data) >= MAX_REQUEST_SIZE:
                 logger.warning(f"Request from {client_info} exceeded max size ({len(request_data)} >= {MAX_REQUEST_SIZE}).")
                 status_code, resp_headers, resp_body = 413, resp_headers, b"413 Payload Too Large"
                 break # Go to send response

        if status_code not in [408, 413]: # If we didn't timeout or exceed size above
            if b"\r\n\r\n" not in request_data:
                 logger.warning(f"Received partial request (no CRLFCRLF) from {client_info} within size limit.")
                 status_code, resp_headers, resp_body = 400, resp_headers, b"400 Bad Request (incomplete headers)"
            else:
                # Process valid header format
                header_part, _ = request_data.split(b"\r\n\r\n", 1)
                try:
                    header_str = header_part.decode("utf-8")
                except UnicodeDecodeError:
                     logger.warning(f"Failed to decode request header from {client_info} (non-UTF8?).")
                     status_code, resp_headers, resp_body = 400, resp_headers, b"400 Bad Request (header encoding error)"
                     # Skip further processing, go to response sending
                     header_str = "" # Prevent NameError later

                if status_code != 400: # Proceed if header decoded okay
                    header_lines = header_str.splitlines()
                    request_line = header_lines[0] if header_lines else ""
                    logger.info(f"Received request from {client_info}: {request_line}")

                    # Parse request headers
                    for line in header_lines[1:]:
                        if ":" in line:
                            key, value = line.split(":", 1)
                            req_headers[key.strip().lower()] = value.strip()

                    # --- Plugin Request Processing Hook ---
                    request_handled_by_plugin = False
                    for plugin in loaded_server_plugins:
                        try:
                            if plugin.process_request(link, request_line, req_headers, serve_directory_path):
                                logger.info(f"Request handled by plugin: {type(plugin).__name__}")
                                request_handled_by_plugin = True
                                # If plugin handles it, we assume it sends its own response or sets state appropriately
                                # For simplicity here, we just break and skip default handling.
                                # A more complex system might allow plugins to set status/body here.
                                break
                        except Exception as e:
                            logger.error(f"Error in plugin {type(plugin).__name__}.process_request: {e}", exc_info=True)
                            # Let subsequent plugins/default handler run

                    # --- Default File Serving (if not handled by plugin) ---
                    if not request_handled_by_plugin:
                        if request_line.startswith("GET ") and request_line.endswith(" HTTP/1.0"):
                            parts = request_line.split(" ")
                            if len(parts) == 3:
                                path_requested = parts[1]
                                # Basic path normalization and default file
                                if path_requested == "/" or not path_requested : path_requested = "/index.html"

                                # Security: Decode URL-encoded parts (%20 etc) AFTER checking for traversal
                                from urllib.parse import unquote
                                path_decoded = unquote(path_requested)

                                # Security: Prevent directory traversal using normalized paths
                                # Construct path relative to serve dir, then resolve
                                target_file = serve_directory_path.joinpath(path_decoded.lstrip('/')).resolve()

                                # Check if the resolved path is still within the serve directory
                                if not str(target_file).startswith(str(serve_directory_path.resolve())):
                                    logger.warning(f"Forbidden path request from {client_info}: {path_decoded} (resolved outside serve dir)")
                                    status_code, resp_headers, resp_body = 403, resp_headers, b"403 Forbidden"
                                elif target_file.is_file():
                                    try:
                                        content = target_file.read_bytes()
                                        mime_type, _ = mimetypes.guess_type(target_file)
                                        resp_headers['Content-Type'] = mime_type or 'application/octet-stream'
                                        # Content-Length set later before sending
                                        status_code, resp_body = 200, content
                                        logger.debug(f"Serving {path_decoded} ({mime_type}, {len(content)} bytes) to {client_info}")
                                    except IOError as e:
                                        logger.error(f"Error reading file {target_file}: {e}")
                                        status_code, resp_headers, resp_body = 500, resp_headers, b"500 Internal Server Error (read error)"
                                    except Exception as e:
                                         logger.error(f"Unexpected error serving file {target_file}: {e}", exc_info=True)
                                         status_code, resp_headers, resp_body = 500, resp_headers, b"500 Internal Server Error"
                                else:
                                    logger.info(f"File not found for {client_info}: {path_decoded} (resolved: {target_file})")
                                    status_code, resp_headers, resp_body = 404, resp_headers, b"404 Not Found"
                            else:
                                 logger.warning(f"Malformed GET request from {client_info}: {request_line}")
                                 status_code, resp_headers, resp_body = 400, resp_headers, b"400 Bad Request (malformed GET)"
                        else:
                            # Handle non-GET requests or other protocols if needed, otherwise 400
                            logger.warning(f"Unsupported method or protocol from {client_info}: {request_line}")
                            status_code, resp_headers, resp_body = 400, resp_headers, b"400 Bad Request (unsupported method/protocol)"

        # --- Plugin Response Modification Hook ---
        # This runs regardless of whether a plugin handled the request or default serving occurred
        final_status, final_headers, final_body = status_code, resp_headers, resp_body
        # Only proceed if the request wasn't fully handled by a plugin earlier (which would imply plugin sent response)
        if not request_handled_by_plugin:
            for plugin in loaded_server_plugins:
                 try:
                     # Pass the *current* state of status/headers/body
                     final_status, final_headers, final_body = plugin.modify_response(
                         link, request_line, req_headers, final_status, final_headers, final_body
                     )
                 except Exception as e:
                      logger.error(f"Error in plugin {type(plugin).__name__}.modify_response: {e}", exc_info=True)
                      # Continue with state before the failing plugin

        # --- Send Final Response ---
        # Only send if not handled (and presumably sent) by a plugin in process_request hook
        if not request_handled_by_plugin:
            status_map = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                          408: "Request Timeout", 413: "Payload Too Large", 500: "Internal Server Error"}
            status_text = status_map.get(final_status, "Unknown Status")

            # Ensure Content-Length is set correctly
            body_len = len(final_body) if final_body else 0
            final_headers['Content-Length'] = str(body_len)

            send_response(link, final_status, status_text, final_headers, final_body)

    except RNS.LinkTimeout:
         logger.warning(f"Link timeout with {client_info} during request processing.")
    except RNS.LinkError as e:
         # Log errors that occur after initial connection if link fails
         logger.error(f"Link error with {client_info} during processing: {e}")
    except Exception as e:
        logger.error(f"Unexpected error handling client {client_info}: {e}", exc_info=True)
        # Try sending a 500 error if possible and not already sent by logic above
        if link and link.status == RNS.Link.ACTIVE and status_code != 500 and not request_handled_by_plugin:
            try:
                # Use basic headers for error response
                error_headers = {"Server": "Akita-Hexagon", "Connection": "close", "Content-Length": "27"}
                send_response(link, 500, "Internal Server Error", error_headers, b"500 Internal Server Error")
            except Exception as send_err:
                 logger.error(f"Failed to send 500 error to {client_info}: {send_err}")
    finally:
        # Final check to ensure link is closed
        if link and link.status != RNS.Link.CLOSED:
            logger.info(f"Closing connection with {client_info} in finally block.")
            link.teardown()


def server_listener(destination, serve_dir_path):
    """Listens for incoming connections and spawns handler threads."""
    logger.info(f"Server listening on {destination.hash}")
    logger.info(f"Serving files from: {serve_dir_path.resolve()}")
    if not serve_dir_path.is_dir():
        logger.critical(f"Serve directory '{serve_dir_path}' is not a valid directory. Server cannot start.")
        print(f"Error: Serve directory '{serve_dir_path}' not found or is not a directory.")
        return # Exit if serve directory is invalid

    active = True
    while active:
        try:
            logger.debug("Waiting for incoming link...")
            # Wait indefinitely for a connection attempt
            link = RNS.Link.accept(destination, timeout=None)

            if link:
                logger.debug(f"Incoming link request from {link.destination.hash[:10]}")
                # Start a new thread for each client
                client_thread = threading.Thread(
                    target=handle_client_request,
                    args=(link, serve_dir_path),
                    daemon=True # Allows main thread to exit even if client threads are running
                )
                client_thread.start()
            else:
                 # Link.accept returns None if destination is torn down
                 logger.warning("Link.accept returned None (destination closed?). Stopping listener.")
                 active = False # Exit loop if destination closed

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received. Shutting down server listener.")
            active = False # Exit loop
            break # Break immediately
        except RNS.TransportNotReadyError:
            logger.critical("RNS Transport became unready. Stopping listener.")
            print("\nCritical Error: Reticulum Transport stopped or became unavailable.")
            active = False # Exit loop
            break
        except Exception as e:
            logger.error(f"Error in server listener loop: {e}", exc_info=True)
            # Avoid crashing the whole server on listener errors if possible
            time.sleep(1) # Pause briefly before retrying accept

    logger.info("Server listener loop finished.")


def run_server(config):
    """Initializes Reticulum and starts the Hexagon web server based on config."""
    reticulum_instance = None
    destination = None
    # Resolve serve directory path from config immediately
    serve_dir = Path(config['serve_directory']).resolve()

    try:
        # --- Configure Logging ---
        log_level_str = config.get('log_level', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        # Set level for this module's logger
        logger.setLevel(log_level)
        # Optionally set root logger level if you want RNS logs affected too
        # logging.getLogger().setLevel(log_level)
        logger.info(f"Log level set to {log_level_str}")

        # --- Load Server Plugins ---
        load_server_plugins()

        # --- Reticulum Setup ---
        logger.info("Initializing Reticulum...")
        # Use a unique instance name if running multiple RNS apps
        reticulum_instance = RNS.Reticulum(loglevel=logging.WARNING) # Keep RNS logs quieter by default
        logger.info("Reticulum instance initialized.")

        # Check transport status *after* initializing Reticulum instance
        if not RNS.Transport.is_active():
             logger.critical("Reticulum Transport is not active. Server cannot start.")
             print("\nError: Reticulum Transport is not running or configured.")
             print("Please start Reticulum (e.g., using 'rnstatus --config ...').")
             if reticulum_instance: reticulum_instance.shutdown() # Clean up instance
             return

        # Configure interface if specified in config
        interface_name = config.get('interface')
        if interface_name:
            # RNS Transport usually handles interface management automatically if the
            # interface is configured correctly in Reticulum's main config.
            # We just log the intent here.
            logger.info(f"Config requests interface: {interface_name} (RNS will attempt to use if available)")


        # --- Server Identity and Destination ---
        identity_path = Path(config['server_identity_path']).resolve()
        identity = None
        try:
             identity_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
             if identity_path.exists():
                 identity = RNS.Identity.from_file(identity_path)
                 if identity:
                      logger.info(f"Loaded server identity from {identity_path}")
                 else:
                      # File exists but is invalid
                      logger.warning(f"Could not load identity from {identity_path}, creating new one.")
                      try: identity_path.unlink() # Attempt to remove invalid file
                      except OSError as e: logger.error(f"Could not remove invalid identity file: {e}")

             if not identity:
                 logger.info("Creating new server identity.")
                 identity = RNS.Identity()
                 identity.to_file(identity_path)
                 logger.info(f"Saved new server identity to {identity_path}")

        except Exception as e:
             logger.critical(f"Failed to load or create server identity at {identity_path}: {e}", exc_info=True)
             print(f"\nCritical Error: Could not load/create server identity file: {e}")
             if reticulum_instance: reticulum_instance.shutdown()
             return

        if not identity:
             logger.critical("Server identity is missing. Cannot start.")
             if reticulum_instance: reticulum_instance.shutdown()
             return

        # Create the server destination
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.TYPE_SINGLE,
            SERVER_APP_NAME, SERVER_ASPECT
        )
        # Set proof strategy - PROVE_ALL requires clients to prove paths, enhancing security slightly
        destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        logger.info(f"Destination proof strategy set to PROVE_ALL.")

        # Announce the destination
        destination.announce()
        # Add small delay to allow announce to propagate before printing ready message
        time.sleep(0.1)
        logger.info(f"Announcing destination {destination.hash} for {SERVER_APP_NAME}/{SERVER_ASPECT}")

        print("\n" + "="*60)
        print(" Akita Hexagon - Reticulum Web Server")
        print("="*60)
        print(f" Server Announce Hash: {destination.hash}")
        print(f" Serving files from:   {serve_dir}")
        print(f" Log Level:            {log_level_str}")
        print(f" Identity File:        {identity_path}")
        print(f" Config File Used:     {config.get('config_file_path', 'Defaults/Args')}") # Show where config came from
        print("="*60)
        print(" Server is running. Press Ctrl+C to stop.")
        print("="*60)

        # Start the main listener loop - this will block until interrupted or error
        server_listener(destination, serve_dir)

    except RNS.TransportNotReadyError:
         # Should be caught earlier, but handle here just in case
         logger.critical("RNS Transport not ready at server startup.")
         print("\nCritical Error: Reticulum Transport not ready.")
    except KeyboardInterrupt:
         logger.info("Shutdown requested via KeyboardInterrupt (main execution).")
    except Exception as e:
        # Catch unexpected errors during setup before listener starts
        logger.critical(f"Server failed to start or crashed during setup: {e}", exc_info=True)
        print(f"\nAn critical error occurred during server setup: {e}")
    finally:
        # --- Shutdown Sequence ---
        print("\nShutting down server...")
        # 1. Close the destination first to stop accepting new links
        if destination and destination.status != RNS.Destination.STATUS_CLOSED:
             logger.info("Closing server destination...")
             destination.teardown()
             print("Server destination closed.")
        # 2. Shutdown Reticulum instance
        if reticulum_instance:
            logger.info("Shutting down Reticulum instance...")
            reticulum_instance.shutdown()
            print("Reticulum shut down.")
        else:
             # If instance creation failed but we reached finally
             logger.info("Reticulum instance was not initialized.")

        logger.info("Akita Hexagon server stopped.")
        print("Server stopped.")

# Note: Argument parsing and config merging now handled in scripts/run_hexagon_server.py

