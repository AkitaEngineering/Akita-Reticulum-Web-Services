# Akita Phoenix and Akita Hexagon for Reticulum

**Organization:** Akita Engineering ([www.akitaengineering.com](https://www.akitaengineering.com))
**License:** GPLv3

This repository contains two Python applications providing web-like services over the [Reticulum Network Stack](https://reticulum.network/):

* **Akita Phoenix:** A text-based web browser with server discovery, bookmarks, and plugin support.
* **Akita Hexagon:** A lightweight web server with service announcement, configuration, and plugin support.

Ideal for low-bandwidth, terminal-based, or specialized network environments.

## Features

### Akita Phoenix (Browser)

* **Server Discovery:** Automatically discovers running Akita Hexagon servers on the local Reticulum network segment at startup.
* **Bookmarks:** Save and quickly navigate to favorite Reticulum server paths (`addbm`, `listbm`, `gobm`). Stored in `~/.config/akita-phoenix/bookmarks.json`.
* **Text-based HTML Rendering:** Extracts and displays the core textual content of HTML pages.
* **Basic Link Navigation:** Follows relative links within displayed pages.
* **Navigation Controls:** Supports Back (`b`), Refresh (`r`), and Home (`h`).
* **Plugin System:** Loads simple plugins from `src/akita_reticulum_web_services/plugins/phoenix/` to extend functionality (e.g., logging page titles).
* **Robustness:** Improved timeout handling, error reporting, and content decoding.
* **Command-line Interface:** Connect directly via hash or use discovery.

### Akita Hexagon (Server)

* **Service Announcement:** Announces its presence (`akita_web/hexagon`) over Reticulum for discovery.
* **Configurable:** Settings managed via `~/.config/akita-hexagon/config.json` and command-line overrides (serve directory, interface, log level, identity path).
* **Plugin System:** Loads plugins from `src/akita_reticulum_web_services/plugins/hexagon/` to modify request handling or responses.
* **Serves Local Files:** Serves files from a configured directory. Guesses MIME types.
* **Basic HTTP/1.0 Support:** Handles GET requests.
* **Error Handling:** Provides basic 4xx and 5xx error responses with logging.
* **Multi-threaded Request Handling:** Uses threading for concurrent connections.

## Project Structure

Akita-Reticulum-Web-Services/├── .gitignore├── LICENSE├── README.md├── requirements.txt├── examples/             # Sample HTML files│   ├── index.html│   └── about.html├── scripts/              # Executable scripts│   ├── run_hexagon_server.py│   └── run_phoenix_browser.py└── src/                  # Source code library└── akita_reticulum_web_services/├── init.py├── hexagon_server.py     # Server logic├── html_parser.py        # Browser HTML parser├── phoenix_browser.py    # Browser logic└── plugins/              # Plugin directory├── init.py├── phoenix/          # Browser plugins│   ├── init.py│   └── title_logger.py (Example)└── hexagon/          # Server plugins└── init.py
## Installation

1.  **Prerequisites:**
    * Python 3.7+
    * A running and configured Reticulum instance (`rnstatus`, `rnsd`, or integrated). Transport must be active.

2.  **Clone the repository:**
    ```bash
    git clone [https://github.com/AkitaEngineering/Akita-Reticulum-Web-Services.git](https://github.com/AkitaEngineering/Akita-Reticulum-Web-Services.git)
    cd Akita-Reticulum-Web-Services
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Running the Akita Hexagon Server

The server uses a configuration file (`~/.config/akita-hexagon/config.json`) and allows overrides via command-line arguments.

* **Default Configuration (`config.json`):** If the file doesn't exist, defaults will be used. You can create it with content like:
    ```json
    {
        "serve_directory": "./examples",
        "interface": null, // null lets Reticulum auto-detect
        "log_level": "INFO",
        "server_identity_path": "~/.config/akita-hexagon/identity"
    }
    ```
    *(Paths can be relative or absolute; `~` is expanded)*

* **Start the server (using config/defaults):**
    ```bash
    python3 scripts/run_hexagon_server.py
    ```

* **Override configuration via command-line:**
    ```bash
    # Use a specific interface and serve from /var/www/reticulum
    python3 scripts/run_hexagon_server.py -i wlan0 --serve-dir /var/www/reticulum

    # Increase log verbosity
    python3 scripts/run_hexagon_server.py --log-level DEBUG

    # Use a different config file
    python3 scripts/run_hexagon_server.py --config /etc/akita-hexagon.json
    ```

The server will print its configuration and announce hash upon starting.

### 2. Running the Akita Phoenix Browser

* **Using Server Discovery (Recommended):**
    ```bash
    python3 scripts/run_phoenix_browser.py
    ```
    It will listen for servers and let you choose.

* **Connecting Directly:**
    ```bash
    python3 scripts/run_phoenix_browser.py <server_destination_hash>
    ```

* **Connecting to a Specific Path:**
    ```bash
    # With discovery
    python3 scripts/run_phoenix_browser.py -p /about.html
    # Directly
    python3 scripts/run_phoenix_browser.py <server_destination_hash> -p /about.html
    ```

* **Inside the browser:**
    * Navigate by entering the number next to a link.
    * **Commands:**
        * `b`: Go back in history.
        * `r`: Refresh the current page.
        * `h`: Go to the root path (`/`) of the current server.
        * `a [name]` or `addbm [name]`: Add current page as a bookmark. If `name` is omitted, a default name is generated.
        * `l` or `listbm`: List saved bookmarks.
        * `g <num>` or `gobm <num>`: Go to the bookmark number shown by `listbm`. (Run `listbm` first if needed).
        * `q`: Quit the browser.

## Plugins

Both the browser and server support simple plugins.

* **Browser Plugins:**
    * Place Python files in `src/akita_reticulum_web_services/plugins/phoenix/`.
    * Plugins must define a class inheriting from `PhoenixPluginBase`.
    * Implement the `process_content` method to inspect or modify raw page content before parsing.
    * See `title_logger.py` for an example.
* **Server Plugins:**
    * Place Python files in `src/akita_reticulum_web_services/plugins/hexagon/`.
    * Plugins must define a class inheriting from `HexagonPluginBase`.
    * Implement `process_request` to handle requests before file serving (return `True` if handled).
    * Implement `modify_response` to change status, headers, or body before sending.

## Notes

* **Reticulum Setup:** A functional Reticulum transport layer is essential. Ensure `rnstatus` or `rnsd` is running and configured for your network interfaces.
* **Platform:** Tested on Linux. Should work on macOS/Windows where Python and Reticulum are supported.
* **Security:** Basic implementation. No encryption beyond Reticulum's link layer. Be cautious with served content and network exposure.
* **Link Scope:** Browser currently only follows relative links within the same server destination.

## Future Improvements

* RNS integration for human-readable names.
* More advanced plugin hooks (e.g., post-parsing hooks for browser).
* Support for more HTTP methods (POST?) and headers.
* Asynchronous operations (`asyncio`) for potentially better performance under load.
* Browser-side caching.
* Handling different content types more explicitly.

## Contributing

Contributions are welcome! Please submit pull requests or open issues.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

