# src/akita_reticulum_web_services/phoenix_browser.py

import RNS
import time
import logging
import os
import threading
import json
import importlib
import sys
import hashlib
from pathlib import Path
from urllib.parse import urlencode, parse_qs
from .html_parser import TextHTMLParser

# --- Constants ---
BROWSER_APP_NAME = "akita_web"
SERVER_ASPECT = "hexagon"
REQUEST_TIMEOUT = 25
LINK_ACTIVITY_TIMEOUT = 15
MAX_RESPONSE_SIZE = 2 * 1024 * 1024
DISCOVERY_TIMEOUT = 10
RNS_RESOLVE_TIMEOUT = 10
CONFIG_DIR = Path(os.path.expanduser("~/.config/akita-phoenix"))
DEFAULT_BROWSER_CONFIG_FILE = CONFIG_DIR / "config.json" # Browser config file
BOOKMARK_FILE = CONFIG_DIR / "bookmarks.json"
CACHE_DIR = CONFIG_DIR / "cache"
DEFAULT_CACHE_TTL_SECONDS = 300 # Default cache validity (5 minutes)
PLUGIN_DIR = Path(__file__).parent / "plugins" / "phoenix"
USER_AGENT = "Akita-Phoenix/0.8" # Updated version

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler(); log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__); logger.addHandler(log_handler); logger.setLevel(logging.INFO)

# --- Global State ---
discovered_servers = {}; discovery_lock = threading.Lock()
bookmarks = {}; loaded_plugins = []
browser_config = {} # Store loaded browser config globally

# --- Plugin Base Class ---
class PhoenixPluginBase:
    """Base class for Akita Phoenix plugins."""
    def modify_request(self, destination_hash, method, path, headers, body_bytes): return method, path, headers, body_bytes
    def process_content(self, destination_hash, path, status_code, headers, raw_content_bytes): return raw_content_bytes
    def post_parse_content(self, destination_hash, path, status_code, headers, parsed_text, parsed_links): return parsed_text, parsed_links
    def modify_links(self, destination_hash, path, status_code, headers, parsed_links): return parsed_links

# --- Plugin Loading ---
def load_plugins():
    """Loads plugins from the plugin directory."""
    global loaded_plugins; loaded_plugins = []
    plugin_dir_path = PLUGIN_DIR.resolve()
    if not plugin_dir_path.is_dir(): logger.info(f"Plugin dir {plugin_dir_path} not found."); return
    logger.info(f"Loading browser plugins from: {plugin_dir_path}")
    src_dir_path = plugin_dir_path.parent.parent.parent
    if str(src_dir_path) not in sys.path: sys.path.insert(0, str(src_dir_path))
    for filename in plugin_dir_path.glob("*.py"):
        if filename.name == "__init__.py": continue
        relative_module_path = filename.relative_to(src_dir_path)
        module_name = ".".join(list(relative_module_path.parts[:-1]) + [filename.stem])
        logger.debug(f"Attempting import: {module_name}")
        try:
            module = importlib.import_module(module_name)
            for name, attr in module.__dict__.items():
                if isinstance(attr, type) and issubclass(attr, PhoenixPluginBase) and attr is not PhoenixPluginBase:
                    try: plugin_instance = attr(); loaded_plugins.append(plugin_instance); logger.info(f"Loaded plugin: {name}")
                    except Exception as e: logger.error(f"Failed instantiating plugin {name}: {e}", exc_info=True)
        except Exception as e: logger.error(f"Error loading plugin module {module_name}: {e}", exc_info=True)
    logger.info(f"Loaded {len(loaded_plugins)} browser plugin(s).")

# --- Configuration Loading ---
def load_browser_config(config_file=DEFAULT_BROWSER_CONFIG_FILE):
    """Loads browser configuration from a JSON file."""
    global browser_config # Store loaded config globally
    config_file_abs = config_file.resolve()
    defaults = {
        "cache_ttl_seconds": DEFAULT_CACHE_TTL_SECONDS, "request_timeout_seconds": REQUEST_TIMEOUT,
        "link_timeout_seconds": LINK_ACTIVITY_TIMEOUT, "rns_resolve_timeout_seconds": RNS_RESOLVE_TIMEOUT,
        "max_response_size_bytes": MAX_RESPONSE_SIZE, # Add max response size config
    }
    config = defaults.copy()
    try:
        if config_file_abs.exists():
            with open(config_file_abs, 'r') as f: loaded_config = json.load(f)
            logger.info(f"Loaded browser configuration from {config_file_abs}"); config.update(loaded_config)
        else: logger.info(f"Browser config file {config_file_abs} not found. Using defaults.")
    except Exception as e: logger.error(f"Error loading browser config {config_file_abs}: {e}. Using defaults."); config = defaults.copy()
    for key, default_val in defaults.items(): # Validate numeric types
        if isinstance(default_val, (int, float)):
            try: config[key] = type(default_val)(config[key])
            except (ValueError, TypeError): logger.warning(f"Invalid value for '{key}' in browser config ('{config[key]}'). Using default: {default_val}"); config[key] = default_val
    browser_config = config; logger.info(f"Browser cache TTL set to {browser_config.get('cache_ttl_seconds')} seconds.")
    return config

# --- Bookmark Management ---
def load_bookmarks():
    global bookmarks; bookmarks = {}
    try:
        if BOOKMARK_FILE.exists():
            with open(BOOKMARK_FILE, 'r') as f: loaded_data = json.load(f)
            if isinstance(loaded_data, dict):
                valid_bookmarks = {name: data for name, data in loaded_data.items() if isinstance(data, dict) and ('hash' in data or 'name' in data) and 'path' in data}
                bookmarks = valid_bookmarks; logger.info(f"Loaded {len(bookmarks)} bookmark(s)")
            else: logger.error(f"Bookmark file invalid format.")
        else: logger.info(f"Bookmark file not found.")
    except Exception as e: logger.error(f"Error loading bookmarks: {e}"); print(f"Warning: Could not load bookmarks ({e})."); bookmarks = {}
def save_bookmarks():
    global bookmarks
    try: CONFIG_DIR.mkdir(parents=True, exist_ok=True);
    with open(BOOKMARK_FILE, 'w') as f: json.dump(bookmarks, f, indent=4, sort_keys=True); logger.info(f"Saved {len(bookmarks)} bookmark(s)")
    except Exception as e: logger.error(f"Error saving bookmarks: {e}"); print(f"Warning: Could not save bookmarks ({e}).")
def add_bookmark(name, dest_hash, rns_name, path):
    global bookmarks;
    if not name: print("Error: Bookmark name empty."); return
    bm_data = {"path": str(path)};
    if rns_name: bm_data["name"] = str(rns_name)
    elif dest_hash: bm_data["hash"] = str(dest_hash)
    else: print("Error: Cannot add bookmark without destination."); return
    bookmarks[name] = bm_data; save_bookmarks(); print(f"Bookmark '{name}' added/updated.")
def list_bookmarks_cmd():
    global bookmarks;
    if not bookmarks: print("No bookmarks saved."); return []
    print("\n--- Bookmarks ---"); sorted_names = sorted(bookmarks.keys())
    for i, name in enumerate(sorted_names):
        bm = bookmarks[name]; target = bm.get('name') or bm.get('hash', 'N/A')
        display_target = target[:20] + "..." if len(target) > 20 else target; display_path = bm.get('path', 'N/A')
        print(f"[{i+1}] {name} -> {display_target}{display_path}")
    print("---------------"); return sorted_names
def get_bookmark_target(index_str, sorted_names):
    if not sorted_names: print("Error: No bookmarks listed."); return None, None
    try:
        index = int(index_str) - 1
        if 0 <= index < len(sorted_names):
            name = sorted_names[index]; bm = bookmarks.get(name)
            if bm and ('hash' in bm or 'name' in bm) and 'path' in bm:
                 target = bm.get('name') or bm.get('hash'); path = bm.get('path'); print(f"Selected bookmark '{name}' -> {target}{path}"); return target, path
            else: print(f"Error: Invalid bookmark data for '{name}'."); return None, None
        else: print("Invalid bookmark number."); return None, None
    except ValueError: print("Invalid input. Enter number."); return None, None

# --- Network and Discovery ---
def announce_handler(destination_hash, announced_app_name, aspects):
    global discovered_servers, discovery_lock
    try: app_name_str = announced_app_name.decode('utf-8') if isinstance(announced_app_name, bytes) else str(announced_app_name); aspects_str = [a.decode('utf-8') if isinstance(a, bytes) else str(a) for a in aspects]
    except Exception as e: logger.warning(f"Could not decode announce: {e}"); return
    if app_name_str == BROWSER_APP_NAME and SERVER_ASPECT in aspects_str:
        hash_str = RNS.hexrep(destination_hash, delimit=False)
        with discovery_lock: now = time.time();
        if hash_str not in discovered_servers: logger.info(f"Discovered server: {hash_str}"); print(f"Discovered server: {hash_str}")
        discovered_servers[hash_str] = now
def discover_servers(timeout=DISCOVERY_TIMEOUT):
    global discovered_servers, discovery_lock; with discovery_lock: discovered_servers.clear()
    logger.info(f"Starting discovery ({timeout}s)..."); print(f"Listening for servers ({timeout}s)... Ctrl+C to stop.");
    if not RNS.Transport.is_active(): logger.error("Discovery needs active RNS Transport."); print("\nError: RNS Transport not running."); return []
    RNS.Transport.register_announce_handler(announce_handler); end_time = time.time() + timeout; interrupted = False
    try:
        while time.time() < end_time: time.sleep(0.1)
    except KeyboardInterrupt: logger.warning("Discovery interrupted."); print("\nDiscovery cancelled."); interrupted = True
    finally: RNS.Transport.unregister_announce_handler(announce_handler)
    logger.info(f"Discovery finished. Found {len(discovered_servers)} server(s).")
    if not interrupted: print("Discovery finished.")
    with discovery_lock: return sorted(list(discovered_servers.keys()))
def select_server_from_discovery():
    discovered = discover_servers(timeout=DISCOVERY_TIMEOUT)
    if not discovered: print("\nNo servers found."); return None
    print("\n--- Discovered Servers ---"); [print(f"[{i+1}] {h}") for i, h in enumerate(discovered)]; print("--------------------------")
    while True:
        try: choice = input("Select server number (or Q to quit): ").strip().lower();
        if choice == 'q': return None
        idx = int(choice) - 1;
        if 0 <= idx < len(discovered): return discovered[idx]
        else: print("Invalid number.")
        except ValueError: print("Invalid input.")
        except (KeyboardInterrupt, EOFError): print("\nExiting selection."); return None

# --- RNS Name Resolution ---
def resolve_rns_path(rns_path_str):
    global browser_config
    resolve_timeout = browser_config.get('rns_resolve_timeout_seconds', RNS_RESOLVE_TIMEOUT)
    if not RNS.Transport.is_active(): logger.error("RNS needs active Transport."); print("Error: RNS Transport not running."); return None
    logger.info(f"Resolving RNS: {rns_path_str}"); print(f"Resolving RNS: {rns_path_str} ...", end="", flush=True)
    try:
        RNS.Transport.request_path(rns_path_str); start = time.time()
        while time.time() - start < resolve_timeout: # Use configured timeout
            dest = RNS.Destination.find_path(rns_path_str)
            if dest: hash_hex = RNS.hexrep(dest.hash, delimit=False); print(" OK."); logger.info(f"Resolved {rns_path_str} -> {hash_hex}"); return hash_hex
            time.sleep(0.5); print(".", end="", flush=True)
        print(" Timeout."); logger.warning(f"Timeout resolving RNS: {rns_path_str}"); print(f"Error: Resolve timeout ({resolve_timeout}s) for '{rns_path_str}'."); return None
    except Exception as e: print(f" Error."); logger.error(f"Error resolving RNS {rns_path_str}: {e}", exc_info=True); print(f"Error: {e}"); return None
def get_target_hash(target_str):
    if not target_str: return None
    if len(target_str) == 56 and all(c in '0123456789abcdef' for c in target_str.lower()):
        logger.debug(f"Input '{target_str}' looks like hash.")
        try: RNS.unhexrep(target_str); return target_str
        except ValueError: logger.warning(f"Invalid hash hex: {target_str}"); print("Error: Invalid hash hex."); return None
    else: logger.debug(f"Input '{target_str}' assumed RNS name."); return resolve_rns_path(target_str)

# --- Caching ---
def _get_cache_key(destination_hash, path): return f"{destination_hash}:{path}"
def _get_cache_filepath(cache_key): key_hash = hashlib.sha256(cache_key.encode('utf-8')).hexdigest(); return CACHE_DIR / f"{key_hash}.cache"
def _read_cache(filepath):
    """Reads cache data using configured TTL."""
    global browser_config
    max_age_seconds = browser_config.get('cache_ttl_seconds', DEFAULT_CACHE_TTL_SECONDS)
    try:
        if not filepath.exists(): logger.debug(f"Cache miss (no file): {filepath}"); return None
        file_mod_time = filepath.stat().st_mtime
        if time.time() - file_mod_time > max_age_seconds: logger.info(f"Cache expired (file age > {max_age_seconds}s): {filepath}"); return None
        with open(filepath, 'rb') as f: meta_line = f.readline(); body = f.read()
        meta = json.loads(meta_line.decode('utf-8'));
        if not all(k in meta for k in ['status', 'headers', 'fetch_time']): logger.warning(f"Invalid cache meta: {filepath}"); return None
        fetch_time = meta.get('fetch_time', 0);
        if time.time() - fetch_time > max_age_seconds: logger.info(f"Cache expired (metadata age > {max_age_seconds}s): {filepath}"); return None
        logger.info(f"Cache hit: {filepath}"); return meta['status'], meta['headers'], body
    except Exception as e: logger.warning(f"Error reading cache {filepath}: {e}"); try: filepath.unlink() ; except OSError: pass; return None
def _write_cache(filepath, status, headers, body_bytes):
    """Writes data and metadata to a cache file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        meta = {"status": status, "headers": headers, "fetch_time": time.time()}; meta_line = json.dumps(meta).encode('utf-8') + b'\n'
        tmp_path = filepath.with_suffix(f"{filepath.suffix}.tmp")
        with open(tmp_path, 'wb') as f: f.write(meta_line); if body_bytes: f.write(body_bytes)
        os.replace(tmp_path, filepath); logger.info(f"Cache written: {filepath} ({len(body_bytes) if body_bytes else 0}b)")
    except Exception as e: logger.error(f"Error writing cache {filepath}: {e}"); if tmp_path.exists(): try: tmp_path.unlink(); except OSError: pass

# --- Page Fetching / Request Sending ---
def fetch_page_content(destination_hash, path="/", force_refresh=False):
    """Fetches GET content, checking cache first unless force_refresh is True."""
    cache_key = _get_cache_key(destination_hash, path); cache_filepath = _get_cache_filepath(cache_key)
    if not force_refresh:
        cached_data = _read_cache(cache_filepath) # Uses configured TTL internally now
        if cached_data: print("(Serving from cache)"); return cached_data
    logger.info(f"Cache miss or refresh for GET {cache_key}. Fetching network...")
    status_code, headers, body_bytes = _send_request(destination_hash, "GET", path)
    if status_code == 200: _write_cache(cache_filepath, status_code, headers, body_bytes)
    return status_code, headers, body_bytes
def send_post_request(destination_hash, path, post_data_dict):
    """Sends a POST request with URL-encoded form data."""
    logger.info(f"Sending POST request to {destination_hash}{path}")
    try: post_body_encoded = urlencode(post_data_dict).encode('utf-8')
    except Exception as e: logger.error(f"Failed POST data encode: {e}"); print(f"Error: Could not encode POST data: {e}"); return 0, {}, None
    post_headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(post_body_encoded))}
    return _send_request(destination_hash, "POST", path, extra_headers=post_headers, request_body=post_body_encoded)

def _send_request(destination_hash, method, path, extra_headers=None, request_body=None):
    """Internal function to send a request, including modify_request hook."""
    global loaded_plugins, browser_config
    link = None; received_data = b""; status_code = 0; headers = {}; response_body_bytes = None; method = method.upper()
    req_timeout = browser_config.get('request_timeout_seconds', REQUEST_TIMEOUT)
    link_timeout = browser_config.get('link_timeout_seconds', LINK_ACTIVITY_TIMEOUT)
    max_resp_size = browser_config.get('max_response_size_bytes', MAX_RESPONSE_SIZE)
    try: dest_hash_bytes = RNS.unhexrep(destination_hash)
    except ValueError: logger.error(f"Internal Error: Invalid hash: {destination_hash}"); return 0, {}, None
    try:
        req_method = method; req_path = path
        req_headers = {"host": destination_hash, "connection": "close", "user-agent": USER_AGENT}
        if extra_headers: req_headers.update({k.lower(): v for k, v in extra_headers.items()})
        req_body_bytes = request_body
        # Plugin Hook: Modify Request
        for plugin in loaded_plugins:
            try:
                if hasattr(plugin, 'modify_request'):
                    logger.debug(f"Calling modify_request for {type(plugin).__name__}")
                    mod_method, mod_path, mod_headers, mod_body = plugin.modify_request(destination_hash, req_method, req_path, req_headers.copy(), req_body_bytes)
                    req_method = mod_method if mod_method is not None else req_method; req_path = mod_path if mod_path is not None else req_path
                    req_headers = mod_headers if mod_headers is not None else req_headers; req_body_bytes = mod_body if mod_body is not None else req_body_bytes
                    if req_method == "POST" and 'content-length' in req_headers: # Recalculate CL if body modified
                         new_len = len(req_body_bytes) if req_body_bytes else 0
                         if int(req_headers['content-length']) != new_len: logger.info(f"Plugin updated POST body, updating CL to {new_len}"); req_headers['content-length'] = str(new_len)
            except Exception as e: logger.error(f"Plugin modify_request error: {e}", exc_info=True)

        logger.debug(f"Network {req_method} conn to {destination_hash} for {req_path}")
        server_identity = RNS.Identity.recall(dest_hash_bytes);
        if not server_identity: logger.warning(f"Identity {destination_hash} not cached.")
        destination = RNS.Destination(dest_hash_bytes, RNS.Destination.OUT, RNS.Destination.TYPE_SINGLE, BROWSER_APP_NAME, SERVER_ASPECT)
        logger.debug(f"Establishing link..."); link = RNS.Link(destination); link.set_link_timeout(link_timeout)
        if not link.wait_established(timeout=10): logger.error(f"Link timeout: {destination_hash}"); print("Error: Link timed out."); return 0, {}, None
        request_line = f"{req_method} {req_path} HTTP/1.0\r\n"; header_str = "".join([f"{k}: {v}\r\n" for k, v in req_headers.items()]);
        full_request = request_line.encode('utf-8') + header_str.encode('utf-8') + b"\r\n"
        if req_body_bytes: full_request += req_body_bytes
        logger.debug(f"Link established. Sending {req_method} request..."); link.send(full_request)
        headers_received = False; content_length = None; response_start_time = time.time()
        while time.time() - response_start_time < req_timeout:
            if link.status == RNS.Link.CLOSED: logger.debug("Link closed by peer."); break
            if link.status != RNS.Link.ACTIVE: logger.warning(f"Link not active ({link.status})."); break
            incoming_message = link.receive(timeout=5)
            if incoming_message:
                received_data += incoming_message.content
                if not headers_received and b"\r\n\r\n" in received_data:
                    try:
                        header_part, body_part = received_data.split(b"\r\n\r\n", 1); header_str = header_part.decode("utf-8"); header_lines = header_str.splitlines()
                        status_line = header_lines[0] if header_lines else ""; status_code = int(status_line.split(" ")[1])
                        headers = {k.strip().lower(): v.strip() for k, v in (line.split(":", 1) for line in header_lines[1:] if ":" in line)}
                        content_length_str = headers.get('content-length');
                        if content_length_str: content_length = int(content_length_str)
                        if content_length is not None and (content_length < 0 or content_length > max_resp_size): logger.error(f"CL {content_length} exceeds max {max_resp_size}"); status_code = 0; break
                        headers_received = True; received_data = body_part
                    except Exception as e: logger.error(f"Header parsing error: {e}"); status_code = 0; break
                if len(received_data) > max_resp_size: logger.error(f"Response body exceeded max size {max_resp_size}"); status_code = 0; break
                if headers_received and content_length is not None and len(received_data) >= content_length: response_body_bytes = received_data[:content_length]; break
            elif headers_received: response_body_bytes = received_data; break
        if link.status == RNS.Link.ACTIVE: link.teardown()
        if time.time() - response_start_time >= req_timeout and status_code == 0 and not response_body_bytes: logger.error("Timeout receiving."); print("Error: Timeout receiving."); return 0, {}, None
        if status_code != 0 and response_body_bytes is None: response_body_bytes = received_data
        final_body_size = len(response_body_bytes) if response_body_bytes is not None else 0
        logger.info(f"{req_method} request status {status_code}. Body size: {final_body_size} bytes.")
        return status_code, headers, response_body_bytes
    except RNS.LinkTimeout: logger.error(f"Link timeout: {destination_hash}."); print("Error: Connection timed out."); return 0, {}, None
    except RNS.LinkEstablishmentError: logger.error(f"Link establishment failed: {destination_hash}."); print("Error: Could not establish link."); return 0, {}, None
    except RNS.TransportNotReadyError: logger.critical("RNS Transport not ready."); print("Critical Error: RNS Transport not ready."); raise
    except Exception as e: logger.error(f"Request error {destination_hash}{path}: {e}", exc_info=True); print(f"Error: {e}"); return 0, {}, None
    finally:
        if link and link.status != RNS.Link.CLOSED: link.teardown()

# --- Page Display and Parsing ---
# (display_page function remains the same)
def display_page(destination_hash, path, status_code, headers, content_bytes):
    """Parses and displays the page content, handles errors, checks content type."""
    links = []; page_text = ""; processed_content = content_bytes if content_bytes is not None else b""; plugin_handled_display = False; final_links = []
    for plugin in loaded_plugins: # Pre-parse hook
        try: plugin_result = plugin.process_content(destination_hash, path, status_code, headers, processed_content)
        if plugin_result is None: logger.info(f"Content handled pre-parse: {type(plugin).__name__}"); plugin_handled_display = True; return []
        else: processed_content = plugin_result
        except Exception as e: logger.error(f"Plugin pre-parse error: {e}", exc_info=True)
    if not plugin_handled_display: # Default processing
        content_type = headers.get('content-type', 'application/octet-stream').lower()
        displayable_text_types = ['text/plain', 'text/css', 'text/javascript', 'application/json', 'application/xml', 'text/xml']
        if status_code == 200:
            if 'text/html' in content_type:
                encoding = 'utf-8';
                if 'charset=' in content_type: try: encoding = content_type.split('charset=')[-1].split(';')[0].strip(); import codecs; codecs.lookup(encoding); except Exception: encoding = 'utf-8'
                logger.debug(f"HTML decode using: {encoding}")
                try: html_content_str = processed_content.decode(encoding)
                except Exception: logger.warning(f"Decode fail '{encoding}', trying fallbacks."); try: html_content_str = processed_content.decode('utf-8', errors='ignore'); encoding += " (fb utf-8)"; except Exception: html_content_str = processed_content.decode('latin-1'); encoding += " (fb latin-1)"
                parser = TextHTMLParser(base_destination_hash=destination_hash)
                try:
                    parser.feed(html_content_str); page_text = parser.get_text(); links = parser.get_links()
                    for plugin in loaded_plugins: # Post-parse hook
                         try:
                              if hasattr(plugin, 'post_parse_content'): page_text, links = plugin.post_parse_content(destination_hash, path, status_code, headers, page_text, links)
                         except Exception as e: logger.error(f"Plugin post-parse error: {e}", exc_info=True)
                    print("\n--- Page Content (text/html) ---");
                    if 'fb' in encoding: print(f"[Decoded: {encoding}]")
                    print(page_text or "[Page empty/no text]"); print("---------------------------------")
                    final_links = links
                except Exception as e: print(f"\nError parsing HTML: {e}"); logger.error(f"HTML parsing error: {e}", exc_info=True)
            elif any(text_type in content_type for text_type in displayable_text_types):
                 try:
                     encoding = 'utf-8';
                     if 'charset=' in content_type: try: encoding = content_type.split('charset=')[-1].split(';')[0].strip(); import codecs; codecs.lookup(encoding); except Exception: encoding = 'utf-8'
                     logger.debug(f"Displaying {content_type} using encoding: {encoding}")
                     plain_text = processed_content.decode(encoding, errors='replace')
                     links = []
                     for plugin in loaded_plugins: # Post-parse hook for text
                          try:
                              if hasattr(plugin, 'post_parse_content'): plain_text, links = plugin.post_parse_content(destination_hash, path, status_code, headers, plain_text, links)
                          except Exception as e: logger.error(f"Plugin post-parse error ({content_type}): {e}", exc_info=True)
                     print(f"\n--- Page Content ({content_type}) ---"); print(plain_text); print("---------------------------------")
                     final_links = links
                 except Exception as e: print(f"\nError decoding {content_type}: {e}"); logger.error(f"Text decode error: {e}", exc_info=True)
            else: print("\n--- Non-Displayable Content ---"); print(f"Type: {content_type}, Len: {len(processed_content)}b"); print("-------------------------------"); final_links = []
        elif status_code > 0:
             print(f"\n--- Server Response ({status_code}) ---"); error_body = ""; status_msg = {404:"Not Found", 403:"Forbidden", 400:"Bad Request", 500:"Server Error", 408:"Timeout", 411:"Length Required", 413:"Too Large", 501:"Not Implemented"}
             if processed_content: try: error_body = processed_content.decode('utf-8', errors='ignore'); except Exception: pass
             print(error_body or status_msg.get(status_code, f"Status {status_code}")); print("---------------------------------"); final_links = []
    modified_links = final_links # Modify Links Hook
    for plugin in loaded_plugins:
        try:
            if hasattr(plugin, 'modify_links'): modified_links = plugin.modify_links(destination_hash, path, status_code, headers, modified_links)
        except Exception as e: logger.error(f"Plugin modify_links error ({type(plugin).__name__}): {e}", exc_info=True)
    return modified_links


# --- User Input Processing ---
# (process_user_input function remains the same)
def process_user_input(current_hash, current_rns_name, current_path, history, links):
    """Handles user commands, including POST."""
    global bookmarks
    next_target = current_rns_name or current_hash; next_path = current_path
    should_exit = False; force_refresh = False; post_data_dict = None
    sorted_bookmark_names = getattr(process_user_input, "last_listed_bookmarks", [])
    if links: print("\n--- Links ---"); [print(f"[{i+1}] {link_path}") for i, link_path in enumerate(links)]; print("-------------")
    print("\nOptions: [Num]Link | [B]ack | [R]efresh | [H]ome | [P]ost <path> <k=v&k=v...> ")
    print("         [A]ddBM [name] | [L]istBM | [G]oBM <num> | [Q]uit")
    try:
        raw_input = input("Enter choice: ").strip();
        if not raw_input: command, args = '', ''
        else: choice_parts = raw_input.split(" ", 1); command = choice_parts[0].lower(); args = choice_parts[1] if len(choice_parts) > 1 else ""
        if command.isdigit():
            idx = int(command) - 1;
            if 0 <= idx < len(links): next_path = links[idx]; logger.info(f"Link {command}: {next_path}")
            else: print("Invalid link number."); force_refresh = True
        elif command == 'q': should_exit = True
        elif command == 'b':
            if len(history) > 1: history.pop(); prev_hash, prev_rns_name, prev_path = history[-1]; next_target = prev_rns_name or prev_hash; next_path = prev_path; logger.info("Back.")
            else: print("No history."); force_refresh = True
        elif command == 'r': force_refresh = True; logger.info("Refresh.")
        elif command == 'h':
             if current_path != "/": next_path = "/"; logger.info("Home.")
             else: force_refresh = True
        elif command == 'p' or command == 'post':
             post_parts = args.split(" ", 1)
             if len(post_parts) == 2:
                 post_path_raw, post_data_str = post_parts; next_path = post_path_raw if post_path_raw.startswith('/') else '/' + post_path_raw
                 try: parsed_qs_data = parse_qs(post_data_str, keep_blank_values=True); post_data_dict = {k: v[0] if v else '' for k, v in parsed_qs_data.items()}; logger.info(f"POST to {next_path} data: {post_data_dict}"); next_target = current_rns_name or current_hash
                 except Exception as e: print(f"Error parsing POST data: {e}"); logger.warning(f"POST data parse error: {e}"); force_refresh = True
             else: print("Invalid POST format."); force_refresh = True
        elif command == 'a' or command == 'addbm':
             name = args.strip();
             if not name: default_target = current_rns_name or current_hash[:8]; name = (default_target + current_path).replace('/', '_').strip('_'); print(f"Default name: '{name}'")
             add_bookmark(name, current_hash, current_rns_name, current_path); force_refresh = True
        elif command == 'l' or command == 'listbm': sorted_bookmark_names = list_bookmarks_cmd(); process_user_input.last_listed_bookmarks = sorted_bookmark_names; force_refresh = True
        elif command == 'g' or command == 'gobm':
             if not hasattr(process_user_input, "last_listed_bookmarks") or not process_user_input.last_listed_bookmarks: print("List bookmarks ('l') first."); force_refresh = True
             else:
                 bm_target, bm_path = get_bookmark_target(args, process_user_input.last_listed_bookmarks)
                 if bm_target and bm_path is not None: next_target = bm_target; next_path = bm_path; logger.info(f"Go Bookmark {args}"); process_user_input.last_listed_bookmarks = []
                 else: force_refresh = True
        elif command == '': force_refresh = True
        else: print(f"Invalid command: '{command}'"); force_refresh = True
    except (KeyboardInterrupt, EOFError): print("\nExiting..."); should_exit = True
    except Exception as e: print(f"Input error: {e}"); logger.error(f"Input error: {e}", exc_info=True); force_refresh = True
    if force_refresh: next_target, next_path = (current_rns_name or current_hash), current_path
    return next_target, next_path, force_refresh, should_exit, post_data_dict


# --- Main Browser Function ---
def run_browser(initial_target=None, initial_path="/"):
    """Main function to initialize and run the Akita Phoenix browser."""
    global browser_config # Access global config
    reticulum_instance = None; exit_code = 0
    try:
        print(f"--- Akita Phoenix Reticulum Browser ({USER_AGENT}) ---")
        CONFIG_DIR.mkdir(parents=True, exist_ok=True); CACHE_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Config dir: {CONFIG_DIR}"); logger.info(f"Cache dir: {CACHE_DIR}")
        # Load browser config first
        load_browser_config() # Loads into global browser_config
        load_bookmarks(); load_plugins()
        logger.info("Initializing Reticulum..."); reticulum_instance = RNS.Reticiculum(loglevel=logging.WARNING); logger.info("RNS initialized.")
        if not RNS.Transport.is_active(): print("\nError: RNS Transport not active."); logger.critical("RNS Transport not active."); return 1

        target_hash = None; target_rns_name = None; selected_target = initial_target
        if not selected_target: selected_hash = select_server_from_discovery();
        if not selected_hash: logger.info("No server selected/discovered. Exiting."); return 0
        selected_target = selected_hash
        target_hash = get_target_hash(selected_target);
        if not target_hash: return 1
        if target_hash != selected_target: target_rns_name = selected_target
        logger.info(f"Starting browser for target: {selected_target} (hash: {target_hash})")

        history = []; current_destination_hash = target_hash; current_rns_name = target_rns_name; current_path = initial_path; links = []
        if hasattr(process_user_input, "last_listed_bookmarks"): del process_user_input.last_listed_bookmarks

        should_exit = False
        while not should_exit:
            current_destination_hash = get_target_hash(current_rns_name or current_destination_hash)
            if not current_destination_hash:
                 print(f"Error: Could not resolve current target '{current_rns_name or 'hash'}'.")
                 if len(history) > 1: history.pop(); current_destination_hash, current_rns_name, current_path = history[-1]; print("Attempting back..."); continue
                 else: should_exit = True; exit_code = 1; continue

            print("\n" + "="*60); display_location = current_rns_name or current_destination_hash; print(f"Location: {display_location}{current_path}"); print("="*60)
            current_location_tuple = (current_destination_hash, current_rns_name, current_path)
            if not history or history[-1] != current_location_tuple: history.append(current_location_tuple)

            # Get input *before* fetch/post
            next_target, next_path, force_refresh, exit_cmd, post_data = process_user_input(current_destination_hash, current_rns_name, current_path, history, links)
            should_exit = exit_cmd
            if should_exit: continue

            # Perform Fetch (GET) or POST
            try:
                if post_data is not None: # POST command
                    print(f"Sending POST to {next_path}...")
                    status_code, headers, content_bytes = send_post_request(current_destination_hash, next_path, post_data)
                    links = display_page(current_destination_hash, next_path, status_code, headers, content_bytes) # Display POST response
                    next_target = current_rns_name or current_destination_hash; next_path = current_path; force_refresh = True # Force refresh after POST
                    print("\n(Displayed POST response. Refreshing current page...)"); time.sleep(1)
                else: # GET command (or refresh)
                    status_code, headers, content_bytes = fetch_page_content(current_destination_hash, current_path, force_refresh=force_refresh)
                    links = display_page(current_destination_hash, current_path, status_code, headers, content_bytes)
            except RNS.TransportNotReadyError: logger.critical("RNS Transport unavailable."); print("Critical Error: RNS connection lost."); should_exit=True; exit_code=1; continue
            except Exception as e: logger.error(f"Request/Display error: {e}", exc_info=True); print(f"Error: {e}"); links = []

            # Update state for next loop
            if not should_exit:
                if len(next_target) == 56 and all(c in '0123456789abcdef' for c in next_target.lower()): current_destination_hash = next_target; current_rns_name = None
                else: current_rns_name = next_target; current_destination_hash = None
                current_path = next_path

    except KeyboardInterrupt: print("\nInterrupt received..."); logger.info("Keyboard interrupt."); exit_code = 0
    except Exception as e: logger.critical(f"Unhandled exception: {e}", exc_info=True); print(f"Critical error: {e}"); exit_code = 1
    finally:
        print("Shutting down..."); save_bookmarks()
        if reticulum_instance: logger.info("Shutting down RNS..."); reticulum_instance.shutdown(); print("RNS shut down.")
        else: logger.info("RNS instance not initialized.")
        print("Akita Phoenix browser closed.")
        # sys.exit(exit_code)

