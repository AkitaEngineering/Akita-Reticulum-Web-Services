# Akita Phoenix and Akita Hexagon for Reticulum
## Akita Reticulum Web Services

**Organization:** Akita Engineering ([www.akitaengineering.com](https://www.akitaengineering.com))
**License:** GPLv3

This repository contains two Python applications providing web-like services over the [Reticulum Network Stack](https://reticulum.network/):

* **Akita Phoenix:** A text-based web browser with discovery, RNS names, bookmarks, configurable caching, POST support, and enhanced plugin hooks.
* **Akita Hexagon:** A lightweight web server with discovery announcement, enhanced configuration (timeouts, sizes), plugin-based path handling (GET/POST), lifecycle hooks, HTML error pages, and plugin support.

Ideal for low-bandwidth, terminal-based, or specialized network environments.

## Features

### Akita Phoenix (Browser)

* **Server Discovery & RNS:** Connect via discovery, RNS name (e.g., `myweb.serv`), or destination hash.
* **Bookmarks:** Save (`addbm`), list (`listbm`), navigate (`gobm`) favorite sites. Stored in `~/.config/akita-phoenix/bookmarks.json`.
* **Configurable Caching:** Time-based response caching in `~/.config/akita-phoenix/cache/`. TTL configurable via `~/.config/akita-phoenix/config.json`. Use `r` to refresh.
* **Text Rendering:** Displays `text/html`, `text/plain`, and other common text types (`application/json`, `text/css`, etc.). Informs about binary types.
* **Navigation:** Follow relative links (`[Num]`), Back (`b`), Refresh (`r`), Home (`h`).
* **POST Requests:** Send simple URL-encoded form data using the `post <path> <key=value&...>` command.
* **Plugin System:**
    * `modify_request`: Alter outgoing request (method, path, headers, body).
    * `process_content`: Modify raw response bytes before parsing.
    * `post_parse_content`: Modify extracted text/links after parsing.
    * `modify_links`: Filter or change the list of links before display.
    * Plugins loaded from `src/akita_reticulum_web_services/plugins/phoenix/`.

### Akita Hexagon (Server)

* **Service Announcement:** Announces `akita_web/hexagon` for discovery.
* **Configurable:** Settings via `~/.config/akita-hexagon/config.json` (timeouts, sizes, paths, log level) and command-line overrides.
* **Plugin System:**
    * **Path Handling:** Plugins register URL paths (`/myplugin/api`) via `register_path_handler` in `load()`. Requests are routed to `handle_registered_path` (supports GET/POST/etc.).
    * **Lifecycle Hooks:** `server_startup(config, destination)` and `server_shutdown()` for setup/cleanup (see `startup_logger.py` example).
    * **Response Hook:** `modify_response` allows altering default responses/errors.
    * Plugins loaded from `src/akita_reticulum_web_services/plugins/hexagon/`. Includes `echo_post.py` and `startup_logger.py` examples.
* **File Serving:** Serves local files for GET requests if no plugin handles the path. Uses `mimetypes`.
* **Basic HTTP/1.0:** Handles GET by default. Handles POST/other methods *only if* a plugin registers a path handler. Requires `Content-Length` for POST/PUT.
* **Error Handling:** Serves basic HTML error pages (from `src/.../templates/`) for common 4xx/5xx errors. Logs errors.
* **Multi-threaded Request Handling:** Uses threading for concurrency.

## Project Structure
```
Akita-Reticulum-Web-Services/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── examples/             # Sample HTML files
├── scripts/              # Executable scripts
│   ├── run_hexagon_server.py
│   └── run_phoenix_browser.py
└── src/                  # Source code library
└── akita_reticulum_web_services/
├── init.py
├── hexagon_server.py     # Server logic
├── html_parser.py        # Browser HTML parser
├── phoenix_browser.py    # Browser logic
├── templates/            # HTML error page templates
│   └── error_*.html
└── plugins/              # Plugin directory
├── init.py
├── phoenix/          # Browser plugins
│   ├── init.py
│   └── title_logger.py (Example)
└── hexagon/          # Server plugins
├── init.py
├── echo_post.py  (Example)
└── startup_logger.py (Example)
```
## Installation

1.  **Prerequisites:** Python 3.7+, running/configured Reticulum instance.
2.  **Clone:** `git clone <repo_url> && cd Akita-Reticulum-Web-Services`
3.  **Install deps:** `pip install -r requirements.txt`

## Configuration

* **Server (`~/.config/akita-hexagon/config.json`):** Controls serve directory, interface, identity path, log level, timeouts (request/link), size limits (header/POST body). See `load_config` in `hexagon_server.py` for keys and defaults.
* **Browser (`~/.config/akita-phoenix/config.json`):** Controls cache TTL (`cache_ttl_seconds`), timeouts (request/link/RNS resolve). See `load_browser_config` in `phoenix_browser.py` for keys and defaults.

*(Create these JSON files if you want to override defaults)*

## Usage

### 1. Running the Akita Hexagon Server

* **Start:** `python3 scripts/run_hexagon_server.py`
* **Overrides:** `python3 scripts/run_hexagon_server.py -c /path/to/config.json -i <iface>`

### 2. Running the Akita Phoenix Browser

* **Discover:** `python3 scripts/run_phoenix_browser.py`
* **Connect (Name/Hash):** `python3 scripts/run_phoenix_browser.py <target>`
* **Specify Path:** Add `-p /path/page.html`

* **Browser Commands:**
    * `[Num]`: Follow link.
    * `b`: Back.
    * `r`: Refresh.
    * `h`: Home (`/`).
    * `p <path> <data>`: Send POST (e.g., `p /echo name=test&val=123`).
    * `a [name]`: Add bookmark.
    * `l`: List bookmarks.
    * `g <num>`: Go to bookmark.
    * `q`: Quit.

## Plugins

* **Browser:** Place in `src/.../plugins/phoenix/`. Inherit `PhoenixPluginBase`. See base class docstrings for hooks.
* **Server:** Place in `src/.../plugins/hexagon/`. Inherit `HexagonPluginBase`. Use `load()` to register paths via `self.register_path_handler(...)`. Implement `handle_registered_path(...)` (return `True` if handled). Use lifecycle hooks `server_startup`/`server_shutdown`.

## Notes

* **Reticulum Setup:** Essential.
* **POST:** Browser sends URL-encoded. Server relies on plugins registering paths.
* **Security:** Basic. Use cautiously.

## Future Improvements

* Asynchronous operations (`asyncio`).
* More robust error pages/handling.
* More configuration options.
* More sophisticated plugin management.
* Support for other HTTP methods via plugins (PUT, DELETE).

## Contributing

Contributions welcome!

## License

GPLv3 - see [LICENSE](LICENSE) file.
