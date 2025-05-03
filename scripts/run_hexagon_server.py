#!/usr/bin/env python3
# scripts/run_hexagon_server.py

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

# Import server functions and constants
try:
    # Ensure RNS is available before importing our modules which depend on it
    import RNS
except ImportError:
    print("Error: Reticulum (RNS) library not found.")
    print("Please install it: pip install rns")
    sys.exit(1)

try:
    from akita_reticulum_web_services.hexagon_server import (
        run_server, load_config, DEFAULT_CONFIG_FILE, DEFAULT_SERVE_DIR, CONFIG_DIR
    )
except ImportError as e:
    print(f"Error: Could not import the server module from '{src_dir}'.")
    print(f"ImportError: {e}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Akita Hexagon - Reticulum Web Server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG_FILE),
        help="Path to the configuration file."
    )
    parser.add_argument(
        "-i", "--interface",
        default=argparse.SUPPRESS, # Use SUPPRESS to easily check if arg was given
        help="Override Reticulum interface specified in config file."
    )
    parser.add_argument(
        "--serve-dir",
        default=argparse.SUPPRESS, # Use SUPPRESS
        help="Override directory with HTML files specified in config file."
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=argparse.SUPPRESS, # Use SUPPRESS
        help="Override log level specified in config file."
    )

    args = parser.parse_args()

    # --- Load Configuration ---
    config_file_path = Path(args.config).resolve()
    config = load_config(config_file_path)
    # Store actual config file path used for display later
    config['config_file_path'] = str(config_file_path) if config_file_path.exists() else 'Defaults/Args'


    # --- Override Config with Command-Line Arguments ---
    # Use hasattr check because we used argparse.SUPPRESS
    if hasattr(args, 'interface'):
        config['interface'] = args.interface
        print(f"Overriding interface with command-line argument: {args.interface}")
    if hasattr(args, 'serve_dir'):
        config['serve_directory'] = args.serve_dir
        print(f"Overriding serve directory with command-line argument: {args.serve_dir}")
    if hasattr(args, 'log_level'):
        config['log_level'] = args.log_level
        print(f"Overriding log level with command-line argument: {args.log_level}")

    # --- Basic Validation ---
    serve_path = Path(config['serve_directory']).resolve()
    if not serve_path.is_dir():
        # Try creating default examples dir if default is used and missing
        # Assume DEFAULT_SERVE_DIR is relative to project root, not script dir
        project_root = script_dir.parent
        default_examples_path = project_root / str(DEFAULT_SERVE_DIR)

        if serve_path == default_examples_path.resolve() and not default_examples_path.exists():
             print(f"Warning: Default examples directory '{default_examples_path}' not found. Creating it.")
             try:
                 default_examples_path.mkdir(parents=True, exist_ok=True)
                 # Create placeholder index.html if it doesn't exist after creating dir
                 placeholder_index = default_examples_path / "index.html"
                 if not placeholder_index.exists():
                      placeholder_index.write_text("<html><body><h1>Default Page</h1><p>Akita Hexagon server is running.</p></body></html>")
                      print(f"Created placeholder index.html in {default_examples_path}")

             except Exception as e:
                 print(f"Error: Could not create default examples directory: {e}")
                 sys.exit(1)
        else:
            # If it's not the default or creation failed/wasn't attempted
            print(f"Error: Serve directory '{serve_path}' not found or is not a valid directory.")
            sys.exit(1)

    # Ensure config dir exists for identity file placement
    try:
        identity_path = Path(config.get('server_identity_path', CONFIG_DIR / "identity")).resolve()
        identity_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create config directory '{identity_path.parent}': {e}")


    # --- Run the Server ---
    # The run_server function will now handle setting the log level internally
    try:
        run_server(config=config)
    except Exception as e:
        # Catch potential crashes during server startup/runtime
        # Use basic logging config in case server's logger setup failed
        logging.basicConfig(level=logging.INFO)
        logging.critical(f"Server failed unexpectedly: {e}", exc_info=True)
        print(f"\nA critical error occurred: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        # Already handled gracefully inside run_server, but catch here too for clean exit
        print("\nServer shutdown requested.")
        sys.exit(0)

if __name__ == "__main__":
    main()
