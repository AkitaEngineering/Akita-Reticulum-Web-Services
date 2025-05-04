# src/akita_reticulum_web_services/hexagon_server.py

import RNS
import os
import threading
import time
import logging
import json
import mimetypes
import importlib
import sys
import html # For escaping error details
from pathlib import Path
from urllib.parse import unquote, parse_qs

# --- Constants ---
SERVER_APP_NAME = "akita_web"
SERVER_ASPECT = "hexagon"
DEFAULT_SERVE_DIR = Path("./examples")
DEFAULT_REQUEST_TIMEOUT = 10 # Timeout for reading request parts
DEFAULT_LINK_TIMEOUT = 15    # Inactivity timeout for established link
DEFAULT_MAX_REQUEST_HEADER_SIZE = 8192
DEFAULT_MAX_POST_BODY_SIZE = 1 * 1024 * 1024 # 1MB Default POST limit
CONFIG_DIR = Path(os.path.expanduser("~/.config/akita-hexagon"))
DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.json"
SERVER_PLUGIN_DIR = Path(__file__).parent / "plugins" / "hexagon"
TEMPLATE_DIR = Path(__file__).parent / "templates" # Directory for error templates
SERVER_VERSION = "Akita-Hexagon/0.6" # Updated version

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler(); log_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__); logger.addHandler(log_handler); logger.setLevel(logging.INFO)

# --- Global State ---
loaded_server_plugins = []
plugin_path_handlers = {}
server_config = {} # Store loaded config globally for access in handlers if needed

# --- Server Plugin Base Class ---
class HexagonPluginBase:
    """Base class for Akita Hexagon server plugins."""
    def load(self): pass
    def server_startup(self, config, destination): pass
    def server_shutdown(self): pass
    def register_path_handler(self, path, handler_instance):
        global plugin_path_handlers
        if not path.startswith('/'): logger.error(f"Plugin {type(handler_instance).__name__} invalid path: {path}"); return
        if path in plugin_path_handlers: logger.warning(f"Path '{path}' overwritten by {type(handler_instance).__name__}.")
        plugin_path_handlers[path] = handler_instance; logger.info(f"Plugin {type(handler_instance).__name__} registered for path: {path}")
    def handle_registered_path(self, link, request_line, method, path, headers, body_bytes, serve_directory):
        logger.warning(f"Plugin {type(self).__name__} registered path '{path}' but did not implement handle_registered_path.")
        return False
    def process_request(self, link, request_line, headers, serve_directory): return False # Deprecated
    def handle_post_request(self, link, request_line, headers, post_body_bytes, serve_directory): return None # Deprecated
    def modify_response(self, link, request_line, req_headers, status_code, resp_headers, resp_body_bytes): return status_code, resp_headers, resp_body_bytes

# --- Plugin Loading ---
def load_server_plugins():
    """Loads server plugins and calls their load() method."""
    global loaded_server_plugins, plugin_path_handlers
    loaded_server_plugins = []; plugin_path_handlers = {}
    plugin_dir_path = SERVER_PLUGIN_DIR.resolve()
    if not plugin_dir_path.is_dir(): logger.info(f"Server plugin dir {plugin_dir_path} not found."); return
    logger.info(f"Loading server plugins from: {plugin_dir_path}")
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
                if isinstance(attr, type) and issubclass(attr, HexagonPluginBase) and attr is not HexagonPluginBase:
                    try:
                        plugin_instance = attr()
                        if hasattr(plugin_instance, 'load'): logger.debug(f"Calling load() for {name}"); plugin_instance.load()
                        loaded_server_plugins.append(plugin_instance); logger.info(f"Loaded server plugin: {name}")
                    except Exception as e: logger.error(f"Failed loading plugin {name}: {e}", exc_info=True)
        except Exception as e: logger.error(f"Error loading plugin module {module_name}: {e}", exc_info=True)
    logger.info(f"Loaded {len(loaded_server_plugins)} server plugin(s). {len(plugin_path_handlers)} path handler(s) registered.")


# --- Configuration Loading ---
def load_config(config_file=DEFAULT_CONFIG_FILE):
    """Loads configuration from a JSON file, applying defaults."""
    global server_config # Store loaded config globally
    config_file_abs = config_file.resolve(); config_dir_abs = config_file_abs.parent
    defaults = {
        "serve_directory": str(DEFAULT_SERVE_DIR), "interface": None, "log_level": "INFO",
        "server_identity_path": str(CONFIG_DIR / "identity"), "request_timeout_seconds": DEFAULT_REQUEST_TIMEOUT,
        "link_timeout_seconds": DEFAULT_LINK_TIMEOUT, "max_request_header_size": DEFAULT_MAX_REQUEST_HEADER_SIZE,
        "max_post_body_size": DEFAULT_MAX_POST_BODY_SIZE,
    }
    config = defaults.copy()
    try:
        if config_file_abs.exists():
            with open(config_file_abs, 'r') as f: loaded_config = json.load(f)
            logger.info(f"Loaded configuration from {config_file_abs}"); config.update(loaded_config)
        else: logger.info(f"Config file {config_file_abs} not found. Using defaults.")
    except Exception as e: logger.error(f"Error loading config {config_file_abs}: {e}. Using defaults."); config = defaults.copy()
    config['serve_directory'] = str(Path(config['serve_directory']).resolve())
    id_path = Path(config['server_identity_path'])
    if not id_path.is_absolute(): config['server_identity_path'] = str((config_dir_abs / id_path).resolve())
    else: config['server_identity_path'] = str(id_path.resolve())
    for key, default_val in defaults.items(): # Validate numeric types
        if isinstance(default_val, int):
            try: config[key] = int(config[key])
            except (ValueError, TypeError): logger.warning(f"Invalid value for '{key}' ('{config[key]}'). Using default: {default_val}"); config[key] = default_val
    server_config = config; return config


# --- Request Handling ---
def send_response(link, status_code, status_text, headers, body_bytes):
    """Constructs and sends an HTTP response."""
    if body_bytes is None: body_bytes = b""
    elif not isinstance(body_bytes, bytes): logger.error(f"Invalid body type: {type(body_bytes)}."); try: body_bytes = str(body_bytes).encode('utf-8'); except Exception: body_bytes = b"Err"; status_code = 500; status_text = "Internal Server Error"
    final_headers = {str(k): str(v) for k, v in headers.items()}
    try:
        response_line = f"HTTP/1.0 {status_code} {status_text}\r\n"; header_lines = "".join([f"{k}: {v}\r\n" for k, v in final_headers.items()])
        response = response_line.encode('utf-8') + header_lines.encode('utf-8') + b"\r\n" + body_bytes
        logger.info(f"Sending response to {link.destination.hash[:10]}: {status_code} {status_text} ({len(body_bytes)} bytes)")
        link.send(response)
    except RNS.LinkTimeout: logger.warning(f"Timeout sending response to {link.destination.hash[:10]}.")
    except RNS.LinkError as e: logger.error(f"Link error sending response to {link.destination.hash[:10]}: {e}")
    except Exception as e: logger.error(f"Unexpected error sending response: {e}", exc_info=True)

def send_error_response(link, status_code, status_text, details="", path_context="", method_context=""):
    """Loads an HTML template for an error and sends it."""
    global server_config
    resp_headers = {"Server": SERVER_VERSION, "Connection": "close", "Content-Type": "text/html; charset=utf-8"}
    template_path = TEMPLATE_DIR / f"error_{status_code}.html"; body_bytes = b""
    if template_path.is_file():
        try:
            template_content = template_path.read_text(encoding='utf-8')
            escaped_details = html.escape(str(details)); escaped_path = html.escape(str(path_context)); escaped_method = html.escape(str(method_context))
            formatted_content = template_content.replace("{details}", escaped_details).replace("{path}", escaped_path).replace("{method}", escaped_method)
            if status_code == 413: limit = server_config.get('max_post_body_size', DEFAULT_MAX_POST_BODY_SIZE); formatted_content = formatted_content.replace("{limit}", str(limit))
            body_bytes = formatted_content.encode('utf-8'); resp_headers['Content-Length'] = str(len(body_bytes))
            logger.info(f"Sending HTML error page for status {status_code}")
        except Exception as e: logger.error(f"Failed formatting error template {template_path}: {e}"); body_bytes = f"{status_code} {status_text}\r\n{details}".encode('utf-8'); resp_headers['Content-Type'] = 'text/plain; charset=utf-8'; resp_headers['Content-Length'] = str(len(body_bytes))
    else: logger.warning(f"Error template not found: {template_path}."); body_bytes = f"{status_code} {status_text}\r\n{details}".encode('utf-8'); resp_headers['Content-Type'] = 'text/plain; charset=utf-8'; resp_headers['Content-Length'] = str(len(body_bytes))
    send_response(link, status_code, status_text, resp_headers, body_bytes)

def handle_client_request(link, serve_directory_path):
    """Handles an incoming client connection and request."""
    global loaded_server_plugins, plugin_path_handlers, server_config
    request_header_data = b""; request_body_bytes = b""; client_info = link.destination.hash[:10]; request_line = ""; method = ""; path = ""; req_headers = {}; status_code = 500
    resp_headers = {"Server": SERVER_VERSION, "Connection": "close"}; resp_body = b""; request_handled = False
    max_header_size = server_config.get('max_request_header_size', DEFAULT_MAX_REQUEST_HEADER_SIZE); max_body_size = server_config.get('max_post_body_size', DEFAULT_MAX_POST_BODY_SIZE)
    req_timeout = server_config.get('request_timeout_seconds', DEFAULT_REQUEST_TIMEOUT); link_timeout = server_config.get('link_timeout_seconds', DEFAULT_LINK_TIMEOUT)
    try:
        logger.info(f"Connection from {client_info}"); link.set_link_timeout(link_timeout)
        # 1. Receive Headers
        while b"\r\n\r\n" not in request_header_data and len(request_header_data) < max_header_size:
            incoming = link.receive(timeout=req_timeout)
            if not incoming:
                if not request_header_data: logger.warning(f"Timeout waiting for req from {client_info}"); return
                else: logger.warning(f"Timeout waiting header from {client_info}"); status_code = 408; resp_body = b"Timeout waiting for header"; break
            request_header_data += incoming.content
            if len(request_header_data) >= max_header_size: logger.warning(f"Header too large from {client_info}"); status_code = 413; resp_body = b"Request header too large"; break
        else: # Header loop OK
            if b"\r\n\r\n" not in request_header_data: logger.warning(f"Incomplete header from {client_info}"); status_code = 400; resp_body = b"Incomplete headers"
            else:
                header_part, initial_body_part = request_header_data.split(b"\r\n\r\n", 1); request_body_bytes = initial_body_part
                try:
                    header_str = header_part.decode("utf-8"); header_lines = header_str.splitlines(); request_line = header_lines[0] if header_lines else ""
                    logger.info(f"Request from {client_info}: {request_line}")
                    req_headers = {k.strip().lower(): v.strip() for k, v in (line.split(":", 1) for line in header_lines[1:] if ":" in line)}
                    parts = request_line.split(" ");
                    if len(parts) >= 2: method = parts[0].upper(); path = parts[1]
                    else: raise ValueError("Malformed request line")
                    status_code = 200 # Assume OK
                except UnicodeDecodeError: logger.warning(f"Header decode error from {client_info}"); status_code = 400; resp_body = b"Header encoding error"
                except Exception as e: logger.error(f"Header parsing error: {e}"); status_code = 500; resp_body = b"Header parsing error"
        # 2. Receive Body
        if status_code == 200 and method in ["POST", "PUT"]:
            cl_str = req_headers.get('content-length')
            if cl_str:
                try:
                    cl = int(cl_str);
                    if cl < 0: raise ValueError("Negative CL")
                    if cl > max_body_size: logger.warning(f"{method} body too large"); status_code = 413; resp_body = f"Payload exceeds limit ({max_body_size} bytes)".encode()
                    else:
                        while len(request_body_bytes) < cl:
                             incoming = link.receive(timeout=req_timeout)
                             if not incoming: logger.warning(f"Timeout receiving {method} body"); status_code = 408; resp_body = b"Timeout waiting for body"; break
                             request_body_bytes += incoming.content
                             if len(request_body_bytes) > max_body_size: logger.warning(f"{method} body exceeded limit"); status_code = 413; resp_body = f"Payload exceeds limit ({max_body_size} bytes)".encode(); break
                        if status_code == 200 and len(request_body_bytes) < cl: logger.warning(f"Incomplete {method} body"); status_code = 400; resp_body = b"Incomplete body"
                        elif status_code == 200: request_body_bytes = request_body_bytes[:cl]; logger.info(f"Received {method} body: {len(request_body_bytes)} bytes")
                except ValueError: logger.warning(f"Invalid CL header: {cl_str}"); status_code = 400; resp_body = b"Invalid Content-Length"
            else: logger.warning(f"{method} request without CL"); status_code = 411; resp_body = b"Length Required"
        # 3. Process Request
        if status_code == 200: # Only process if no errors so far
            path_decoded = unquote(path); matched_plugin = None; longest_match_len = -1
            for plugin_path, handler_instance in plugin_path_handlers.items(): # Check Plugin Paths
                 if path_decoded.startswith(plugin_path) and len(plugin_path) > longest_match_len: longest_match_len = len(plugin_path); matched_plugin = handler_instance
            if matched_plugin:
                 logger.info(f"Path '{path_decoded}' matches handler {type(matched_plugin).__name__}")
                 try:
                     request_handled = matched_plugin.handle_registered_path(link, request_line, method, path_decoded, req_headers, request_body_bytes, serve_directory_path)
                     if not request_handled: logger.warning(f"Plugin declined handling {path_decoded}."); status_code = 404; resp_body = b"Not Found (handler declined)"; request_handled = True
                 except Exception as e: logger.error(f"Plugin path handler error: {e}", exc_info=True); status_code = 500; resp_body = b"Plugin error"; request_handled = True
            elif method == "GET": # Default GET
                if path_decoded == "/" or not path_decoded : path_decoded = "/index.html"
                target_file = serve_directory_path.joinpath(path_decoded.lstrip('/')).resolve()
                if not str(target_file).startswith(str(serve_directory_path.resolve())): logger.warning(f"Forbidden GET path: {path_decoded}"); status_code = 403; resp_body = b"Forbidden"
                elif target_file.is_file():
                    try: content = target_file.read_bytes(); mime_type, encoding = mimetypes.guess_type(target_file); resp_headers['Content-Type'] = mime_type or 'application/octet-stream';
                    if encoding: resp_headers['Content-Encoding'] = encoding
                    status_code, resp_body = 200, content; logger.debug(f"Serving GET {path_decoded} ({resp_headers['Content-Type']})")
                    except Exception as e: logger.error(f"Error reading file {target_file}: {e}"); status_code = 500; resp_body = b"Read error"
                else: logger.info(f"GET file not found: {path_decoded}"); status_code = 404; resp_body = b"Not Found"
                request_handled = True
            elif method in ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]: logger.info(f"Unhandled {method} (no plugin path): {path_decoded}"); status_code = 501; resp_body = f"{method} not implemented for this path".encode(); request_handled = True
            else: logger.warning(f"Unsupported method: {method}"); status_code = 501; resp_body = f"Method {method} not implemented".encode(); request_handled = True
        # 4. Modify Response Hook
        final_status, final_headers, final_body = status_code, resp_headers, resp_body
        if not request_handled or status_code >= 400:
             for plugin in loaded_server_plugins:
                 try:
                     if hasattr(plugin, 'modify_response'): final_status, final_headers, final_body = plugin.modify_response(link, request_line, req_headers, final_status, final_headers, final_body)
                 except Exception as e: logger.error(f"Plugin modify_response error: {e}", exc_info=True)
        # 5. Send Final Response
        if not request_handled or status_code >= 400:
            status_map = {200:"OK", 400:"Bad Request", 403:"Forbidden", 404:"Not Found", 405:"Method Not Allowed", 408:"Timeout", 411:"Length Required", 413:"Payload Too Large", 500:"Internal Server Error", 501:"Not Implemented"}
            status_text = status_map.get(final_status, "Unknown Status")
            if final_status >= 400: send_error_response(link, final_status, status_text, details=final_body.decode('utf-8', errors='ignore'), path_context=path, method_context=method)
            else: body_len = len(final_body) if final_body else 0; final_headers['Content-Length'] = str(body_len); send_response(link, final_status, status_text, final_headers, final_body)
    except RNS.LinkTimeout: logger.warning(f"Link timeout with {client_info}.")
    except RNS.LinkError as e: logger.error(f"Link error with {client_info}: {e}")
    except UnicodeDecodeError: logger.warning(f"Header decode error from {client_info}."); send_error_response(link, 400, "Bad Request", details="Header encoding error")
    except Exception as e:
        logger.error(f"Unexpected error handling client {client_info}: {e}", exc_info=True)
        if link and link.status == RNS.Link.ACTIVE and not request_handled:
            try: send_error_response(link, 500, "Internal Server Error", details=str(e))
            except Exception as send_err: logger.error(f"Failed sending 500 error: {send_err}")
    finally:
        if link and link.status != RNS.Link.CLOSED: logger.info(f"Closing connection with {client_info}."); link.teardown()


# --- Server Listener and Main Runner ---
def server_listener(destination, serve_dir_path):
    """Listens for incoming connections and spawns handler threads."""
    logger.info(f"Server listening on {destination.hash}")
    logger.info(f"Serving files from: {serve_dir_path.resolve()}")
    if not serve_dir_path.is_dir(): logger.critical(f"Serve directory '{serve_dir_path}' invalid."); print(f"Error: Serve directory invalid."); return
    active = True
    while active:
        try:
            logger.debug("Waiting for incoming link...")
            link = RNS.Link.accept(destination, timeout=None)
            if link:
                logger.debug(f"Incoming link from {link.destination.hash[:10]}")
                client_thread = threading.Thread(target=handle_client_request, args=(link, serve_dir_path), daemon=True)
                client_thread.start()
            else: logger.warning("Link.accept returned None (destination closed?)."); active = False
        except KeyboardInterrupt: logger.info("Keyboard interrupt. Shutting down."); active = False; break
        except RNS.TransportNotReadyError: logger.critical("RNS Transport unready."); print("\nCritical Error: RNS Transport stopped."); active = False; break
        except Exception as e: logger.error(f"Listener loop error: {e}", exc_info=True); time.sleep(1)
    logger.info("Server listener loop finished.")

def run_server(config):
    """Initializes Reticulum and starts the Hexagon web server based on config."""
    global loaded_server_plugins, server_config
    reticulum_instance = None; destination = None
    server_config = config
    serve_dir = Path(config['serve_directory']).resolve()
    try:
        log_level_str = config.get('log_level', 'INFO').upper(); log_level = getattr(logging, log_level_str, logging.INFO)
        logger.setLevel(log_level); logging.getLogger().setLevel(log_level); logger.info(f"Log level set to {log_level_str}")
        load_server_plugins()
        logger.info("Initializing Reticulum..."); reticulum_instance = RNS.Reticulum(loglevel=logging.WARNING); logger.info("RNS initialized.")
        if not RNS.Transport.is_active(): logger.critical("RNS Transport not active."); print("\nError: RNS Transport not running."); if reticulum_instance: reticulum_instance.shutdown(); return
        interface_name = config.get('interface');
        if interface_name: logger.info(f"Config requests interface: {interface_name}")
        identity_path = Path(config['server_identity_path']).resolve(); identity = None
        try: # Identity loading/creation
             identity_path.parent.mkdir(parents=True, exist_ok=True)
             if identity_path.exists():
                 identity = RNS.Identity.from_file(identity_path)
                 if identity: logger.info(f"Loaded identity from {identity_path}")
                 else: logger.warning(f"Invalid identity file {identity_path}. Creating new."); try: identity_path.unlink(); except OSError as e: logger.error(f"Could not remove invalid identity: {e}")
             if not identity: logger.info("Creating new identity."); identity = RNS.Identity(); identity.to_file(identity_path); logger.info(f"Saved new identity to {identity_path}")
        except Exception as e: logger.critical(f"Failed identity load/create: {e}", exc_info=True); print(f"\nCritical Error: Identity file issue: {e}"); if reticulum_instance: reticulum_instance.shutdown(); return
        if not identity: logger.critical("Server identity missing."); if reticulum_instance: reticulum_instance.shutdown(); return
        destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.TYPE_SINGLE, SERVER_APP_NAME, SERVER_ASPECT)
        destination.set_proof_strategy(RNS.Destination.PROVE_ALL); logger.info(f"Proof strategy: PROVE_ALL.")
        logger.info("Calling server_startup hooks..."); # Startup Hook
        for plugin in loaded_server_plugins:
             try:
                 if hasattr(plugin, 'server_startup'): plugin.server_startup(config, destination)
             except Exception as e: logger.error(f"Error in plugin {type(plugin).__name__}.server_startup: {e}", exc_info=True)
        destination.announce(); time.sleep(0.1); logger.info(f"Announcing {destination.hash} for {SERVER_APP_NAME}/{SERVER_ASPECT}")
        print("\n" + "="*60); print(f" {SERVER_VERSION} - Reticulum Web Server"); print("="*60)
        print(f" Server Announce Hash: {destination.hash}"); print(f" Serving files from:   {serve_dir}"); print(f" Log Level:            {log_level_str}")
        print(f" Identity File:        {identity_path}"); print(f" Config File Used:     {config.get('config_file_path', 'Defaults/Args')}")
        print(f" Request Timeout:      {config.get('request_timeout_seconds')}s"); print(f" Link Timeout:         {config.get('link_timeout_seconds')}s")
        print(f" Max Header Size:      {config.get('max_request_header_size')}b"); print(f" Max POST Body Size:   {config.get('max_post_body_size')}b")
        print("="*60); print(" Server running. Press Ctrl+C to stop."); print("="*60)
        server_listener(destination, serve_dir) # Blocks until exit
    except RNS.TransportNotReadyError: logger.critical("RNS Transport not ready at startup."); print("\nCritical Error: RNS Transport not ready.")
    except KeyboardInterrupt: logger.info("Shutdown requested via KeyboardInterrupt.")
    except Exception as e: logger.critical(f"Server setup/crash error: {e}", exc_info=True); print(f"\nCritical error: {e}")
    finally:
        print("\nShutting down server...")
        logger.info("Calling server_shutdown hooks..."); # Shutdown Hook
        for plugin in loaded_server_plugins:
             try:
                 if hasattr(plugin, 'server_shutdown'): plugin.server_shutdown()
             except Exception as e: logger.error(f"Error in plugin {type(plugin).__name__}.server_shutdown: {e}", exc_info=True)
        if destination and destination.status != RNS.Destination.STATUS_CLOSED: logger.info("Closing destination..."); destination.teardown(); print("Destination closed.")
        if reticulum_instance: logger.info("Shutting down RNS..."); reticulum_instance.shutdown(); print("RNS shut down.")
        else: logger.info("RNS instance not initialized.")
        logger.info("Akita Hexagon server stopped."); print("Server stopped.")


