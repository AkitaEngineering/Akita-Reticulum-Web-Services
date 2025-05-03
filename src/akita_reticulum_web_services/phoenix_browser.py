# src/akita_reticulum_web_services/phoenix_browser.py

import RNS
import time
import logging
import os
import threading
import json
import importlib
import sys
from pathlib import Path # Use pathlib for easier path manipulation
from .html_parser import TextHTMLParser # Import parser from the same package

# --- Constants ---
BROWSER_APP_NAME = "akita_web"
SERVER_ASPECT = "hexagon"
REQUEST_TIMEOUT = 25           # Increased timeout slightly
LINK_ACTIVITY_TIMEOUT = 15     # Increased timeout slightly
MAX_RESPONSE_SIZE = 2 * 1024 * 1024 # Increased max size (e.g., 2MB)
DISCOVERY_TIMEOUT = 10
CONFIG_DIR = Path(os.path.expanduser("~/.config/akita-phoenix"))
BOOKMARK_FILE = CONFIG_DIR / "bookmarks.json"
PLUGIN_DIR = Path(__file__).parent / "plugins" / "phoenix" # Plugin directory relative to this file

# --- Logging Setup ---
# Configure logging (can be overridden by script later)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__) # Use module-specific logger
logger.addHandler(log_handler)
logger.setLevel(logging.INFO) # Default level

# --- Global State ---
discovered_servers = {}
discovery_lock = threading.Lock()
bookmarks = {} # Dictionary to hold bookmarks {name: {"hash": hash, "path": path}}
loaded_plugins = [] # List to hold loaded plugin instances

# --- Plugin Base Class ---
class PhoenixPluginBase:
    """Base class for Akita Phoenix plugins."""
    def process_content(self, destination_hash, path, status_code, headers, raw_content_bytes):
        """
        Hook to process raw content before default parsing.
        Plugins can potentially handle the content entirely or modify it.

        Args:
            destination_hash (str): The hash of the server.
            path (str): The requested path.
            status_code (int): The HTTP status code received.
            headers (dict): A dictionary of response headers (lowercase keys).
            raw_content_bytes (bytes): The raw byte content of the response body.

        Returns:
            bytes or None: Modified content bytes to be parsed by the default parser,
                           or None if the plugin fully handled the content (prevents default parsing).
                           Return the original raw_content_bytes to pass through unmodified.
        """
        # Default implementation does nothing
        return raw_content_bytes

# --- Plugin Loading ---
def load_plugins():
    """Loads plugins from the plugin directory."""
    global loaded_plugins
    loaded_plugins = []
    plugin_dir_path = PLUGIN_DIR.resolve() # Ensure path is absolute
    if not plugin_dir_path.is_dir():
        logger.info(f"Plugin directory {plugin_dir_path} not found. No plugins loaded.")
        return

    logger.info(f"Loading browser plugins from: {plugin_dir_path}")
    # Ensure plugin directory structure is importable
    # Add the 'src' directory to sys.path if not already present
    src_dir_path = plugin_dir_path.parent.parent.parent
    if str(src_dir_path) not in sys.path:
         sys.path.insert(0, str(src_dir_path))
         logger.debug(f"Added {src_dir_path} to sys.path for plugin loading")


    for filename in plugin_dir_path.glob("*.py"):
        if filename.name == "__init__.py":
            continue
        # Construct module path relative to 'src' like 'akita_reticulum_web_services.plugins.phoenix.my_plugin'
        relative_module_path = filename.relative_to(src_dir_path)
        module_name_parts = list(relative_module_path.parts[:-1]) + [filename.stem]
        module_name = ".".join(module_name_parts)

        logger.debug(f"Attempting to import browser plugin module: {module_name}")
        try:
            module = importlib.import_module(module_name)
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if isinstance(attribute, type) and issubclass(attribute, PhoenixPluginBase) and attribute is not PhoenixPluginBase:
                    try:
                        plugin_instance = attribute() # Instantiate the plugin
                        loaded_plugins.append(plugin_instance)
                        logger.info(f"Successfully loaded browser plugin: {attribute_name} from {filename.name}")
                    except Exception as e:
                        logger.error(f"Failed to instantiate browser plugin {attribute_name} from {filename.name}: {e}", exc_info=True)

        except ImportError as e:
            logger.error(f"Failed to import browser plugin module {module_name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error loading browser plugin from {filename.name}: {e}", exc_info=True)

    logger.info(f"Loaded {len(loaded_plugins)} browser plugin(s).")


# --- Bookmark Management ---
def load_bookmarks():
    """Loads bookmarks from the JSON file."""
    global bookmarks
    bookmarks = {} # Reset before loading
    try:
        if BOOKMARK_FILE.exists():
            with open(BOOKMARK_FILE, 'r') as f:
                # Basic validation: ensure it's a dict and entries have hash/path
                loaded_data = json.load(f)
                if isinstance(loaded_data, dict):
                    valid_bookmarks = {}
                    for name, data in loaded_data.items():
                        if isinstance(data, dict) and 'hash' in data and 'path' in data:
                             valid_bookmarks[name] = data
                        else:
                             logger.warning(f"Skipping invalid bookmark entry: '{name}'")
                    bookmarks = valid_bookmarks
                    logger.info(f"Loaded {len(bookmarks)} valid bookmark(s) from {BOOKMARK_FILE}")
                else:
                     logger.error(f"Bookmark file {BOOKMARK_FILE} does not contain a valid dictionary.")
                     # Optionally backup the corrupt file here
        else:
            logger.info(f"Bookmark file {BOOKMARK_FILE} not found. Starting with empty bookmarks.")
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading bookmarks from {BOOKMARK_FILE}: {e}")
        print(f"Warning: Could not load bookmarks file ({e}). Starting fresh.")
        bookmarks = {} # Ensure bookmarks is an empty dict on error

def save_bookmarks():
    """Saves bookmarks to the JSON file."""
    global bookmarks
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True) # Ensure config dir exists
        with open(BOOKMARK_FILE, 'w') as f:
            json.dump(bookmarks, f, indent=4, sort_keys=True) # Add sort_keys for consistent output
        logger.info(f"Saved {len(bookmarks)} bookmark(s) to {BOOKMARK_FILE}")
    except IOError as e:
        logger.error(f"Error saving bookmarks to {BOOKMARK_FILE}: {e}")
        print(f"Warning: Could not save bookmarks ({e}).")

def add_bookmark(name, dest_hash, path):
    """Adds or updates a bookmark."""
    global bookmarks
    if not name:
        print("Error: Bookmark name cannot be empty.")
        return
    # Ensure hash and path are stored
    bookmarks[name] = {"hash": str(dest_hash), "path": str(path)}
    save_bookmarks()
    print(f"Bookmark '{name}' added/updated.")

def list_bookmarks_cmd():
    """Prints the list of bookmarks, sorted by name."""
    global bookmarks
    if not bookmarks:
        print("No bookmarks saved.")
        return [] # Return empty list if none exist

    print("\n--- Bookmarks ---")
    # Sort by name for consistent listing
    sorted_names = sorted(bookmarks.keys())
    for i, name in enumerate(sorted_names):
        bm = bookmarks[name]
        # Display truncated hash for readability
        display_hash = bm.get('hash', 'N/A')[:8] + "..." if bm.get('hash') else 'N/A'
        display_path = bm.get('path', 'N/A')
        print(f"[{i+1}] {name} -> {display_hash}{display_path}")
    print("---------------")
    return sorted_names # Return sorted names for use with 'gobm'

def go_to_bookmark(index_str, sorted_names):
    """Gets the destination details for a selected bookmark index."""
    if not sorted_names:
        print("Error: No bookmarks listed to choose from.")
        return None, None
    try:
        index = int(index_str) - 1
        if 0 <= index < len(sorted_names):
            name = sorted_names[index]
            bm = bookmarks.get(name) # Use .get for safety
            if bm and 'hash' in bm and 'path' in bm:
                 print(f"Going to bookmark '{name}'...")
                 return bm["hash"], bm["path"]
            else:
                 print(f"Error: Bookmark data for '{name}' is invalid.")
                 return None, None
        else:
            print("Invalid bookmark number.")
            return None, None
    except ValueError:
        print("Invalid input. Please enter the bookmark number.")
        return None, None

# --- Network and Discovery ---
def announce_handler(destination_hash, announced_app_name, aspects):
    """Callback function for received Reticulum announcements."""
    global discovered_servers, discovery_lock
    # Decode app name bytes to string for comparison
    try:
        app_name_str = announced_app_name.decode('utf-8') if isinstance(announced_app_name, bytes) else str(announced_app_name)
        # Decode aspect bytes to strings
        aspects_str = [a.decode('utf-8') if isinstance(a, bytes) else str(a) for a in aspects]
    except Exception as e:
        logger.warning(f"Could not decode announce data: {e}")
        return # Ignore undecodable announces

    if app_name_str == BROWSER_APP_NAME and SERVER_ASPECT in aspects_str:
        hash_str = RNS.hexrep(destination_hash, delimit=False)
        with discovery_lock:
            now = time.time()
            # Add or update server entry with timestamp
            if hash_str not in discovered_servers:
                 logger.info(f"Discovered server: {hash_str}")
                 print(f"Discovered server: {hash_str}") # Also print to console during discovery
            discovered_servers[hash_str] = now # Store last seen time

def discover_servers(timeout=DISCOVERY_TIMEOUT):
    """Listens for server announcements."""
    global discovered_servers, discovery_lock
    with discovery_lock:
        discovered_servers.clear() # Clear previous discoveries for this run

    logger.info(f"Starting server discovery for {timeout} seconds...")
    print(f"Listening for Akita Hexagon servers ({BROWSER_APP_NAME}/{SERVER_ASPECT}) for {timeout} seconds...")
    print("Press Ctrl+C to stop discovery early.")

    if not RNS.Transport.is_active():
        logger.error("Discovery requires Reticulum Transport to be active.")
        print("\nError: Reticulum Transport is not running. Cannot perform discovery.")
        print("Ensure Reticulum (e.g., rnstatus) is running and configured.")
        return []

    RNS.Transport.register_announce_handler(announce_handler)
    # Use a loop with sleep for better interrupt handling than single sleep
    end_time = time.time() + timeout
    interrupted = False
    try:
        while time.time() < end_time:
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.warning("Discovery interrupted by user.")
        print("\nDiscovery cancelled.")
        interrupted = True
    finally:
        # Always unregister the handler
        RNS.Transport.unregister_announce_handler(announce_handler)

    logger.info(f"Discovery finished. Found {len(discovered_servers)} server(s).")
    if not interrupted: print("Discovery finished.")

    with discovery_lock:
        # Return sorted list for consistent ordering
        return sorted(list(discovered_servers.keys()))


def select_server_from_discovery():
    """Handles the server discovery and selection process."""
    discovered = discover_servers(timeout=DISCOVERY_TIMEOUT)
    if not discovered:
        print("\nNo Akita Hexagon servers found during discovery.")
        print("You can try again or specify a server hash directly.")
        return None # Indicate no server selected

    print("\n--- Discovered Servers ---")
    for i, server_hash in enumerate(discovered):
        print(f"[{i+1}] {server_hash}")
    print("--------------------------")

    while True:
        try:
            choice = input("Select server number to connect to (or Q to quit): ").strip().lower()
            if choice == 'q':
                return None # Indicate user quit selection
            server_index = int(choice) - 1
            if 0 <= server_index < len(discovered):
                return discovered[server_index] # Return selected hash
            else:
                print("Invalid server number.")
        except ValueError:
            print("Invalid input. Please enter a number or Q.")
        except (KeyboardInterrupt, EOFError):
             print("\nExiting selection.")
             return None # Indicate user quit selection

def fetch_page_content(destination_hash, path="/"):
    """Fetches content from a Reticulum Hexagon server."""
    link = None
    start_time = time.time()
    received_data = b""
    status_code = 0 # Default error
    headers = {} # Store headers (lowercase keys)
    html_content_bytes = None # Store raw body bytes

    # Validate hash format before proceeding
    if not isinstance(destination_hash, str) or len(destination_hash) != 56:
         logger.error(f"Invalid destination hash format provided: {destination_hash}")
         print(f"Error: Invalid destination hash format.")
         return 0, {}, None # status, headers, body

    try:
        dest_hash_bytes = RNS.unhexrep(destination_hash)
    except ValueError:
        logger.error(f"Invalid destination hash hex representation: {destination_hash}")
        print(f"Error: Invalid destination hash hex value.")
        return 0, {}, None # status, headers, body

    try:
        logger.info(f"Attempting to connect to {destination_hash} for path: {path}")
        server_identity = RNS.Identity.recall(dest_hash_bytes)

        # Path Discovery Logic
        if not server_identity:
            print("Server info not cached, requesting path...", end="", flush=True)
            RNS.Transport.request_path(dest_hash_bytes)
            identity_wait_start = time.time()
            max_wait = 15
            resolved = False
            try:
                while time.time() - identity_wait_start < max_wait:
                     if RNS.Identity.recall(dest_hash_bytes):
                         resolved = True
                         break
                     time.sleep(0.5)
                     print(".", end="", flush=True)
            except KeyboardInterrupt:
                print("\nPath request cancelled.")
                return 0, {}, None # Treat interrupt as failure
            print() # Newline after progress dots or cancellation

            server_identity = RNS.Identity.recall(dest_hash_bytes)
            if not server_identity:
                logger.error(f"Could not resolve destination hash after request: {destination_hash}")
                print(f"Error: Could not find or resolve destination {destination_hash}.")
                print("Ensure the server is running and reachable on the Reticulum network.")
                return 0, {}, None

        # Destination Setup
        destination = RNS.Destination(
            server_identity, RNS.Destination.OUT, RNS.Destination.TYPE_SINGLE,
            BROWSER_APP_NAME, SERVER_ASPECT
        )

        # Link Establishment
        print(f"Establishing link to {destination_hash}...")
        link = RNS.Link(destination)
        link.set_link_timeout(LINK_ACTIVITY_TIMEOUT) # Set inactivity timeout

        if not link.wait_established(timeout=10): # Wait up to 10s for link
             logger.error(f"Link establishment timed out for {destination_hash}")
             print("Error: Could not establish link with the server (timed out).")
             link.teardown()
             return 0, {}, None

        # Send Request
        logger.info(f"Link established. Sending request for {path}...")
        print(f"Requesting path: {path}")
        # Include User-Agent
        request = f"GET {path} HTTP/1.0\r\nHost: {destination_hash}\r\nConnection: close\r\nUser-Agent: Akita-Phoenix/0.2\r\n\r\n".encode("utf-8")
        link.send(request)

        # Receive Response Loop
        headers_received = False
        content_length = None
        response_start_time = time.time() # Track time spent receiving

        while time.time() - response_start_time < REQUEST_TIMEOUT:
            if link.status == RNS.Link.CLOSED:
                 logger.info("Link closed by remote peer during receive.")
                 break
            if link.status != RNS.Link.ACTIVE:
                 logger.warning(f"Link no longer active (status: {link.status}). Stopping receive.")
                 break

            # Receive with a shorter timeout for subsequent parts
            incoming_message = link.receive(timeout=5)
            if incoming_message:
                received_data += incoming_message.content
                logger.debug(f"Received {len(incoming_message.content)} bytes. Total body: {len(received_data)}")

                # Parse headers if not already done
                if not headers_received and b"\r\n\r\n" in received_data:
                    try:
                        header_part, body_part = received_data.split(b"\r\n\r\n", 1)
                        header_str = header_part.decode("utf-8") # Assume UTF-8 for headers
                        header_lines = header_str.splitlines()
                        status_line = header_lines[0] if header_lines else ""
                        logger.debug(f"Received Status: {status_line}")
                        logger.debug(f"Received Headers:\n{header_str}")

                        # Parse status code
                        try:
                            status_code = int(status_line.split(" ")[1])
                        except (IndexError, ValueError):
                            logger.error(f"Could not parse status code from line: {status_line}")
                            status_code = 0 # Error
                            break # Cannot proceed without status

                        # Parse headers into dict (lowercase keys)
                        headers = {}
                        for line in header_lines[1:]:
                            if ":" in line:
                                key, value = line.split(":", 1)
                                headers[key.strip().lower()] = value.strip()

                        content_length_str = headers.get('content-length')
                        if content_length_str:
                            try:
                                content_length = int(content_length_str)
                                logger.debug(f"Expected Content-Length: {content_length}")
                                # Basic sanity check for content length
                                if content_length < 0:
                                     logger.warning("Invalid negative Content-Length received.")
                                     content_length = None
                                elif content_length > MAX_RESPONSE_SIZE:
                                     logger.error(f"Advertised Content-Length ({content_length}) exceeds max size ({MAX_RESPONSE_SIZE}).")
                                     status_code = 0 # Treat as error
                                     break
                            except ValueError:
                                logger.warning("Invalid Content-Length header value.")
                                content_length = None # Treat as invalid

                        headers_received = True
                        received_data = body_part # Keep only the body part in received_data now

                    except UnicodeDecodeError:
                         logger.error("Failed to decode HTTP headers (non-UTF8?).")
                         status_code = 0 # Error
                         break # Cannot proceed
                    except Exception as e:
                         logger.error(f"Error parsing headers: {e}", exc_info=True)
                         status_code = 0 # Error
                         break

                # Check if response body size limit is exceeded
                if len(received_data) > MAX_RESPONSE_SIZE:
                    logger.error(f"Response body exceeded maximum size of {MAX_RESPONSE_SIZE} bytes.")
                    print("Error: Response too large.")
                    status_code = 0 # Error
                    break

                # Check if we have the full body based on Content-Length
                if headers_received and content_length is not None:
                    if len(received_data) >= content_length:
                        html_content_bytes = received_data[:content_length]
                        logger.info(f"Received full response body based on Content-Length ({len(html_content_bytes)} bytes).")
                        break # Got the complete body

            # If no data received in this interval, check conditions to break
            elif headers_received:
                 # If headers are received and no more data came, assume complete
                 # (especially if no content-length was provided)
                 logger.info("No more data received, assuming response body complete.")
                 html_content_bytes = received_data # Take whatever body we got
                 break

        # --- Post-Loop Processing ---
        if link.status == RNS.Link.ACTIVE:
             logger.warning("Response loop finished (timeout?), but link still active. Tearing down.")
             link.teardown()

        # Check for timeout condition *after* the loop
        if time.time() - response_start_time >= REQUEST_TIMEOUT and status_code == 0 and not html_content_bytes:
             logger.error("Timeout waiting for full response.")
             print("Error: Timeout receiving data from server.")
             return 0, {}, None

        # Final check if loop ended without error but content wasn't assigned
        if status_code != 0 and html_content_bytes is None:
            html_content_bytes = received_data

        # Log final status and size
        final_body_size = len(html_content_bytes) if html_content_bytes is not None else 0
        logger.info(f"Request finished with status {status_code}. Body size: {final_body_size} bytes.")
        return status_code, headers, html_content_bytes

    except RNS.LinkTimeout:
        logger.error(f"Link timeout during connection or request to {destination_hash}.")
        print("Error: Connection timed out.")
        return 0, {}, None
    except RNS.LinkEstablishmentError:
         logger.error(f"Link establishment failed for {destination_hash}.")
         print("Error: Could not establish link with the server (connection refused or other issue).")
         return 0, {}, None
    except RNS.TransportNotReadyError:
         logger.critical("Reticulum Transport is not ready or active.", exc_info=True)
         print("\nCritical Error: Reticulum Transport is not ready. Cannot make connections.")
         # Re-raise to signal fatal error to the main loop
         raise
    except Exception as e:
        logger.error(f"Unexpected error fetching page from {destination_hash}{path}: {e}", exc_info=True)
        print(f"An unexpected error occurred: {e}")
        return 0, {}, None
    finally:
        # Ensure link teardown if it exists and isn't already closed
        if link and link.status != RNS.Link.CLOSED:
            logger.debug(f"Tearing down link to {destination_hash} in finally block.")
            link.teardown()


def display_page(destination_hash, path, status_code, headers, content_bytes):
    """Parses and displays the page content, or handles errors."""
    links = []
    page_text = ""
    processed_content = content_bytes if content_bytes is not None else b"" # Ensure bytes

    # --- Plugin Hook ---
    global loaded_plugins
    plugin_handled_display = False
    for plugin in loaded_plugins:
        try:
            # Pass content to plugin. It might modify or consume it.
            plugin_result = plugin.process_content(destination_hash, path, status_code, headers, processed_content)
            if plugin_result is None:
                # Plugin handled the content entirely
                logger.info(f"Content handled by plugin: {type(plugin).__name__}")
                plugin_handled_display = True
                # We assume the plugin did its own printing/display
                return [] # No links to return from default parser
            else:
                # Plugin potentially modified the content
                processed_content = plugin_result
        except Exception as e:
            logger.error(f"Error executing process_content for plugin {type(plugin).__name__}: {e}", exc_info=True)
            # Continue with potentially modified content

    # --- Default Processing/Rendering (if not handled by plugin) ---
    if not plugin_handled_display:
        if status_code == 200:
            # Try decoding using charset from headers, fallback to utf-8, then latin-1
            encoding = 'utf-8' # Default
            content_type = headers.get('content-type', '').lower()
            if 'charset=' in content_type:
                try:
                    encoding = content_type.split('charset=')[-1].split(';')[0].strip()
                    # Validate encoding name briefly
                    import codecs
                    codecs.lookup(encoding)
                except (LookupError, IndexError):
                     logger.warning(f"Invalid or unsupported charset '{encoding}' found in header. Falling back to utf-8.")
                     encoding = 'utf-8'
            logger.debug(f"Attempting to decode using encoding: {encoding}")

            try:
                html_content_str = processed_content.decode(encoding)
            except (UnicodeDecodeError, LookupError) as e1:
                logger.warning(f"Failed decoding with specified encoding '{encoding}': {e1}. Trying utf-8.")
                try:
                    html_content_str = processed_content.decode('utf-8', errors='ignore') # Ignore errors on fallback
                    encoding = 'utf-8 (fallback)'
                except UnicodeDecodeError as e2:
                    logger.warning(f"Failed decoding with utf-8: {e2}. Trying latin-1.")
                    try:
                        html_content_str = processed_content.decode('latin-1') # Latin-1 rarely fails
                        encoding = 'latin-1 (fallback)'
                    except Exception as e3: # Catch broader errors just in case
                        logger.error(f"Failed to decode content with any known encoding: {e3}")
                        print("\n--- Error ---")
                        print("Could not decode page content.")
                        print("-------------")
                        return [] # Cannot parse

            # Parse HTML for text and links
            parser = TextHTMLParser(base_destination_hash=destination_hash)
            try:
                parser.feed(html_content_str)
                page_text = parser.get_text()
                links = parser.get_links()

                print("\n--- Page Content ---")
                # Display encoding used if it wasn't the default utf-8
                if 'fallback' in encoding or encoding not in ['utf-8', 'utf8']:
                     print(f"[Decoded using: {encoding}]")
                print(page_text if page_text else "[Page is empty or contains no displayable text]")
                print("--------------------")

            except Exception as e:
                print(f"\nError parsing HTML content: {e}")
                logger.error(f"HTML parsing error for {path}: {e}", exc_info=True)

        elif status_code > 0:
             # Display server error status and message if available
             print(f"\n--- Server Response (Status: {status_code}) ---")
             error_body = ""
             if processed_content: # Use potentially plugin-modified content
                 try: # Try decoding error body as utf-8
                     error_body = processed_content.decode('utf-8', errors='ignore')
                 except Exception: pass # Ignore if can't decode
             if error_body:
                 print(error_body)
             else:
                 # Provide generic messages for known codes if no body
                 status_messages = {
                     404: "Resource not found.", 403: "Access forbidden.",
                     400: "Bad request.", 500: "Internal server error.",
                     408: "Request timeout.", 413: "Payload too large.",
                     0: "Network or connection error." # Map internal error code
                 }
                 print(status_messages.get(status_code, f"Received status code {status_code}"))
             print("---------------------------------------")
        else:
            # Error occurred during fetch (status_code == 0 reported by fetch_page_content)
            # Error message should have been printed by fetch_page_content
            pass # Avoid printing duplicate error messages

    return links # Return extracted links for navigation


def process_user_input(current_hash, current_path, history, links):
    """Handles user commands for navigation, bookmarks, etc."""
    global bookmarks # Allow modification
    next_hash, next_path = current_hash, current_path # Default to stay/refresh
    should_exit = False
    refresh = False
    # Get currently listed bookmarks if needed (persists between inputs in same session)
    # This relies on list_bookmarks_cmd being called before gobm if needed
    # A more robust way might involve passing state, but this is simpler for now.
    # We'll rely on the user running 'l' before 'g' if the list isn't fresh.
    sorted_bookmark_names = getattr(process_user_input, "last_listed_bookmarks", [])


    # --- Display Links ---
    if links:
        print("\n--- Links ---")
        for i, link_path in enumerate(links):
            print(f"[{i+1}] {link_path}")
        print("-------------")

    print("\nOptions: [Num]Link | [B]ack | [R]efresh | [H]ome | [A]ddBM [name] | [L]istBM | [G]oBM <num> | [Q]uit")

    try:
        # Read input robustly
        raw_input = input("Enter choice: ").strip()
        if not raw_input: # Handle empty input
             refresh = True # Treat empty input as refresh/stay
             command, args = '', ''
        else:
            choice_parts = raw_input.split(" ", 1)
            command = choice_parts[0].lower()
            args = choice_parts[1] if len(choice_parts) > 1 else ""

        # Process command
        if command.isdigit():
            link_index = int(command) - 1
            if 0 <= link_index < len(links):
                next_path = links[link_index] # Navigate to link
                logger.info(f"User chose link {command}: {next_path}")
            else:
                print("Invalid link number.")
                refresh = True # Stay on same page
        elif command == 'q':
            should_exit = True
        elif command == 'b':
            if len(history) > 1:
                history.pop() # Remove current page from history
                prev_dest, prev_path = history[-1] # Peek at the new last item
                next_hash, next_path = prev_dest, prev_path
                logger.info("User chose Back.")
            else:
                print("No previous page in history.")
                refresh = True # Stay on same page
        elif command == 'r':
             refresh = True
             logger.info("User chose Refresh.")
        elif command == 'h':
             # Go back to the initial path ('/') on the current server
             if current_path != "/":
                 next_path = "/"
                 logger.info("User chose Home.")
             else:
                 refresh = True # Already home, just refresh
        elif command == 'a' or command == 'addbm':
             bookmark_name = args.strip()
             if not bookmark_name:
                 # Default name: use path or hash+path
                 bookmark_name = current_path if current_path != "/" else current_hash[:8] + current_path
                 # Sanitize default name slightly (replace slashes)
                 bookmark_name = bookmark_name.replace('/', '_').strip('_')
                 print(f"Using default bookmark name: '{bookmark_name}'")
             add_bookmark(bookmark_name, current_hash, current_path)
             refresh = True # Stay on same page after adding
        elif command == 'l' or command == 'listbm':
             sorted_bookmark_names = list_bookmarks_cmd() # Store sorted names
             # Store the listed bookmarks for potential 'gobm' use immediately after
             process_user_input.last_listed_bookmarks = sorted_bookmark_names
             refresh = True # Stay on same page after listing
        elif command == 'g' or command == 'gobm':
             # Use the stored list from the last 'l' command
             if not hasattr(process_user_input, "last_listed_bookmarks") or not process_user_input.last_listed_bookmarks:
                 print("Please list bookmarks with 'l' before using 'g'.")
                 refresh = True
             else:
                 bm_hash, bm_path = go_to_bookmark(args, process_user_input.last_listed_bookmarks)
                 if bm_hash and bm_path is not None: # Check both hash and path exist
                     next_hash, next_path = bm_hash, bm_path
                     logger.info(f"User chose Go Bookmark {args}: {next_hash}{next_path}")
                     # Clear the stored list after successful use to force 'l' again
                     process_user_input.last_listed_bookmarks = []
                 else:
                     refresh = True # Invalid GoBM input or bookmark data
        elif command == '': # Handle empty input case (already set refresh=True)
             pass
        else:
            print(f"Invalid command: '{command}'")
            refresh = True # Stay on same page

    except (KeyboardInterrupt, EOFError):
        print("\nExiting...")
        should_exit = True
    except Exception as e:
        print(f"An error occurred processing input: {e}")
        logger.error(f"Input loop error: {e}", exc_info=True)
        refresh = True # Stay on same page on error

    # If refreshing, ensure next path/hash are the current ones
    if refresh:
        next_hash, next_path = current_hash, current_path

    return next_hash, next_path, refresh, should_exit


def run_browser(initial_destination_hash=None, initial_path="/"):
    """
    Main function to initialize and run the Akita Phoenix browser.
    """
    reticulum_instance = None
    exit_code = 0 # Default success exit code
    try:
        # --- Initialization ---
        print("--- Akita Phoenix Reticulum Browser ---")
        CONFIG_DIR.mkdir(parents=True, exist_ok=True) # Ensure config dir exists
        logger.info(f"Using configuration directory: {CONFIG_DIR}")

        # Load bookmarks early
        load_bookmarks()

        # Load plugins
        load_plugins()

        # Initialize Reticulum
        logger.info("Initializing Reticulum...")
        # Create instance *before* checking transport status
        reticulum_instance = RNS.Reticulum(loglevel=logging.WARNING) # Keep RNS logs quieter by default
        logger.info("Reticiculum instance initialized.")
        # Check transport status *after* instance creation
        if not RNS.Transport.is_active():
             print("\nError: Reticulum Transport is not active or could not start.")
             print("Please ensure Reticulum is running and configured correctly.")
             logger.critical("Reticulum Transport is not active. Browser cannot function.")
             # Clean up instance before returning
             if reticulum_instance: reticulum_instance.shutdown()
             return 1 # Indicate error exit

        # --- Server Selection ---
        selected_server_hash = initial_destination_hash
        if not selected_server_hash:
            selected_server_hash = select_server_from_discovery()
            if not selected_server_hash:
                logger.info("No server selected or discovered. Exiting.")
                if reticulum_instance: reticulum_instance.shutdown()
                return 0 # Normal exit if user quit selection

        logger.info(f"Selected server: {selected_server_hash}")

        # --- Browser State ---
        history = [] # List of (destination_hash, path) tuples
        current_destination_hash = selected_server_hash
        current_path = initial_path
        links = []
        # Clear any potentially stored bookmark list from previous runs
        if hasattr(process_user_input, "last_listed_bookmarks"):
            del process_user_input.last_listed_bookmarks

        # --- Main Navigation Loop ---
        should_exit = False
        while not should_exit:
            print("\n" + "="*60)
            print(f"Current Location: {current_destination_hash}{current_path}")
            print("="*60)

            # Manage History: Add if new location
            current_location = (current_destination_hash, current_path)
            # Add only if history is empty or location differs from last entry
            if not history or history[-1] != current_location:
                 history.append(current_location)
                 # Limit history size (optional)
                 # MAX_HISTORY = 50
                 # if len(history) > MAX_HISTORY: history.pop(0)

            # Fetch and Display Page
            try:
                print("Loading page...")
                status_code, headers, content_bytes = fetch_page_content(current_destination_hash, current_path)
                # Pass fetched data to display function
                links = display_page(current_destination_hash, path, status_code, headers, content_bytes)
            except RNS.TransportNotReadyError:
                 # Handle case where transport dies mid-session
                 logger.critical("Reticulum Transport became unavailable during operation.")
                 print("\nCritical Error: Reticulum connection lost.")
                 should_exit = True
                 exit_code = 1 # Indicate error exit
                 continue # Skip input processing, go straight to shutdown
            except Exception as e:
                 # Catch unexpected errors during fetch/display phase
                 logger.error(f"Error during page load/display: {e}", exc_info=True)
                 print(f"\nAn error occurred: {e}")
                 # Allow user to try navigating away or quitting
                 links = [] # Clear links as page load failed


            # Process User Input
            next_hash, next_path, refresh, exit_cmd = process_user_input(
                current_destination_hash, current_path, history, links
            )
            should_exit = exit_cmd

            # Update state for next iteration
            if not refresh:
                 # Only update if navigation occurred (not refresh)
                 current_destination_hash = next_hash
                 current_path = next_path
            # else: # Refresh case
                 # If refreshing, remove current entry from history so it's re-added cleanly on next loop iteration
                 # if history and history[-1] == current_location:
                 #      history.pop()
                 # Note: Refresh logic simplified - history is added only if location changes.
                 # Refreshing keeps the same location, so history isn't duplicated.


    except KeyboardInterrupt:
        print("\nInterrupt received. Shutting down...")
        logger.info("Keyboard interrupt received by main loop.")
        exit_code = 0 # Normal exit on Ctrl+C
    except Exception as e:
         # Catch unexpected errors in the main loop/initialization
         logger.critical(f"Unhandled exception in run_browser: {e}", exc_info=True)
         print(f"\nA critical error occurred: {e}")
         exit_code = 1 # Indicate error exit
    finally:
        # --- Shutdown ---
        print("Shutting down...")
        save_bookmarks() # Ensure bookmarks are saved on exit
        if reticulum_instance:
            logger.info("Shutting down Reticulum instance...")
            reticulum_instance.shutdown()
            print("Reticulum shut down.")
        else:
            logger.info("Reticulum instance was not initialized or already shut down.")

        print("Akita Phoenix browser closed.")
        # Exit with appropriate code if needed (e.g., for scripting)
        # sys.exit(exit_code) # Consider adding this if script usage is expected

# Note: Argument parsing and direct execution are handled in scripts/run_phoenix_browser.py
