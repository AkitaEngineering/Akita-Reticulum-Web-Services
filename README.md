# Akita Phoenix and Akita Hexagon for Reticulum

This repository contains two Python scripts that provide a basic text-based web browser and web server for the Reticulum network.

## Akita Phoenix (Text-based Reticulum Browser)

`akita_phoenix_reticulum.py` is a text-based web browser designed to navigate and display HTML content served over the Reticulum network. It focuses on displaying the textual content of web pages, making it suitable for low-bandwidth environments.

### Features

* **Text-based HTML rendering:** Extracts and displays the textual content of HTML pages.
* **Basic link navigation:** Allows users to follow links within displayed pages.
* **Browsing history:** Supports basic "back" navigation.
* **Timeout handling:** Prevents indefinite waiting for server responses.
* **Robust link extraction:** Uses regular expressions to find links.
* **Command-line interface:** Easy to use with Reticulum destination hashes.

### Usage

1.  **Run the Reticulum web server (Akita Hexagon).**
2.  **Copy the destination hash of the server.**
3.  **Run the browser:**

    ```bash
    python3 akita_phoenix_reticulum.py <destination_hash>
    ```

    * Replace `<destination_hash>` with the server's destination hash.

    * You can also add a path to the url using the `-p` flag. Example: `python3 akita_phoenix_reticulum.py <destination_hash> -p /about.html`

4.  **Follow links by entering the corresponding number.**
5.  **Type `b` to go back in history or `q` to quit.**

## Akita Hexagon (Reticulum Web Server)

`akita_hexagon_webserver_reticulum.py` is a simple web server designed to serve HTML content over the Reticulum network.

### Features

* **Serves HTML files:** Serves files from the current directory.
* **Basic HTTP/1.0 support:** Handles GET requests.
* **404 and 500 error handling:** Provides appropriate error responses.
* **Content-Length header:** Includes content length information in responses.
* **Multi-threaded request handling:** Allows multiple simultaneous connections.
* **Interface selection:** Allows the user to specify the Reticulum interface.

### Usage

1.  **Place your HTML files in the same directory as the server script.**
2.  **Run the server:**

    ```bash
    python3 akita_hexagon_webserver_reticulum.py
    ```

    * You can specify the Reticulum interface using the `-i` or `--interface` argument. Example: `python3 akita_hexagon_webserver_reticulum.py -i wlan0`.

3.  **The server will print its destination hash.**

### Requirements

* Python 3.x
* Reticulum library (`pip install reticulum`)

### Notes

* This is a basic implementation and is suitable for simple text-based web pages.
* Security considerations should be taken into account when serving content over the Reticulum network.
* For more complex web applications, consider using a more robust web server and browser.
* The server will serve files from the current directory. So create your index.html file in the same directory as the server.
* The browser only follows links that resolve to the same destination hash as the initial server.

### Future Improvements

* LXMF plugin integration for service discovery.
* Reticulum naming service integration.
* Enhanced security features.
* Asynchronous server operations.
* Cache implementation for the browser.
* More robust error handling.
* More user friendly URL handling.

### Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
