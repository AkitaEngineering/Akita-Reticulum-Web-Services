#!/usr/bin/env python3
# scripts/run_phoenix_browser.py

import argparse
import os
import sys
import logging
from pathlib import Path

# Add the src directory to the Python path
script_dir = Path(__file__).parent.resolve()
src_dir = script_dir.parent / 'src'
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Import browser function
try:
    # Ensure RNS is available before importing our modules which depend on it
    import RNS
except ImportError:
    print("Error: Reticulum (RNS) library not found.")
    print("Please install it: pip install rns")
    sys.exit(1)

try:
    # Import the updated run_browser function
    from akita_reticulum_web_services.phoenix_browser import run_browser
except ImportError as e:
    print(f"Error: Could not import the browser module from '{src_dir}'.")
    print(f"ImportError: {e}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Akita Phoenix - Reticulum Text Browser with optional server discovery.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Make destination_hash optional
    parser.add_argument(
        "destination_hash",
        nargs='?', # Makes the argument optional
        default=None, # Default value if not provided
        help="Optional: Destination hash of the Reticulum web server (Akita Hexagon). If omitted, discovery will be attempted."
    )
    parser.add_argument(
        "-p", "--path",
        default="/",
        help="Initial path to request from the server."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for browser and RNS operations."
    )
    parser.add_argument(
        "--log-level", # Allow explicit log level setting
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO', # Default log level if --debug is not used
        help="Set the logging level."
    )


    args = parser.parse_args()

    # --- Configure Logging ---
    log_level_str = args.log_level.upper()
    if args.debug:
        log_level_str = 'DEBUG' # Debug flag overrides log-level setting

    log_level = getattr(logging, log_level_str, logging.INFO)
    # Basic config, applies to root logger, affecting RNS and our modules
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Optionally make RNS less verbose unless debugging
    if log_level > logging.DEBUG:
        logging.getLogger("RNS").setLevel(logging.WARNING)

    logging.getLogger("main_script").info(f"Log level set to {log_level_str}")


    # Validate destination hash format if provided
    if args.destination_hash and len(args.destination_hash) != 56:
         # Use logger instead of print for warnings
         logging.warning(f"Provided destination hash '{args.destination_hash}' does not look like a valid Reticulum hash (expected 56 hex characters).")
         # Allow proceeding, Reticulum/run_browser will handle the actual validation/error

    # Ensure path starts with a slash
    request_path = args.path
    if not request_path.startswith('/'):
        logging.info(f"Path '{request_path}' adjusted to start with '/': '/{request_path}'")
        request_path = '/' + request_path


    # Run the browser function from the library
    # Pass None for hash if it wasn't provided to trigger discovery
    try:
        run_browser(initial_destination_hash=args.destination_hash, initial_path=request_path)
    except Exception as e:
        # Catch potential crashes in run_browser itself
        logging.critical(f"Browser failed unexpectedly: {e}", exc_info=True)
        print(f"\nAn critical error occurred: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
         print("\nExiting browser.")
         sys.exit(0)


if __name__ == "__main__":
    main()
