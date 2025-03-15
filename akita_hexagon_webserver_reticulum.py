# akita_hexagon_webserver_reticulum.py (Enhanced Reticulum Web Server)

import reticulum.identity
import reticulum.transport
import reticulum.interfaces
import reticulum.destination
import reticulum.lamport
import reticulum.link
import reticulum.message
import reticulum
import argparse
import os
import threading
import time

def handle_request(link, request):
    try:
        if "GET " in request and " HTTP/1.0" in request:
            path = request.split(" ")[1]
            if path == "/":
                path = "/index.html"
            filepath = os.path.join(".", path[1:]) #remove leading slash.

            if os.path.isfile(filepath):
                with open(filepath, "rb") as f:
                    content = f.read()

                response = f"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(content)}\r\n\r\n".encode("utf-8") + content
                message = reticulum.message.Message(link, response)
                link.send(message)
            else:
                response = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found".encode("utf-8")
                message = reticulum.message.Message(link, response)
                link.send(message)
        else:
            response = "HTTP/1.0 400 Bad Request\r\n\r\n400 Bad Request".encode("utf-8")
            message = reticulum.message.Message(link, response)
            link.send(message)

    except FileNotFoundError:
        response = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found".encode("utf-8")
        message = reticulum.message.Message(link, response)
        link.send(message)

    except Exception as e:
        response = f"HTTP/1.0 500 Internal Server Error\r\n\r\n500 Internal Server Error: {e}".encode("utf-8")
        message = reticulum.message.Message(link, response)
        link.send(message)

def server_loop(destination):
    while True:
        try:
            link = reticulum.link.Link.wait_for_incoming(destination)
            if link:
                incoming_message = link.receive()
                if incoming_message:
                    request = incoming_message.content.decode("utf-8")
                    threading.Thread(target=handle_request, args=(link, request)).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="Akita Hexagon - Reticulum Web Server")
    parser.add_argument("-i", "--interface", default="lo", help="Reticulum interface to use.")
    args = parser.parse_args()

    identity = reticulum.identity.Identity()
    destination = reticulum.destination.Destination(reticulum.destination.Destination.TYPE_SERVER, "akita_hexagon")
    interface = reticulum.interfaces.Interfaces.find_interface(args.interface)
    reticulum.transport.Transport.add_interface(interface)
    destination.announce()

    print(f"Akita Hexagon Server running on {destination.hash}")

    server_loop(destination)

if __name__ == "__main__":
    main()
