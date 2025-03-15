# akita_phoenix_reticulum.py (Enhanced Reticulum Text Browser)

import reticulum.destination
import reticulum.link
import reticulum.message
import reticulum
import argparse
import html.parser
import urllib.parse
import time
import threading
import os
import re

class TextHTMLParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = ""
        self.ignore = False

    def handle_starttag(self, tag, attrs):
        if tag in ["script", "style"]:
            self.ignore = True

    def handle_endtag(self, tag):
        if tag in ["script", "style"]:
            self.ignore = False

    def handle_data(self, data):
        if not self.ignore:
            self.text += data

    def get_text(self):
        return self.text

def fetch_html(destination_hash, path="/", timeout=10):
    try:
        dest = reticulum.destination.Destination(destination_hash)
        link = reticulum.link.Link(dest)
        request = f"GET {path} HTTP/1.0\r\n\r\n".encode("utf-8")
        message = reticulum.message.Message(link, request)
        link.send(message)

        start_time = time.time()
        received_data = b""
        while True:
            incoming_message = link.receive(timeout=5)
            if incoming_message:
                received_data += incoming_message.content
                try:
                    payload = received_data.decode("utf-8")
                    if "\r\n\r\n" in payload:
                        if "HTTP/1.0 200 OK" in payload:
                            content_start = payload.find("\r\n\r\n") + 4
                            html_content = payload[content_start:]
                            return html_content
                        else:
                            print("Server returned:", payload.split("\r\n")[0])
                            return None
                except UnicodeDecodeError:
                    pass #wait for more data.

            if time.time() - start_time > timeout:
                print("Timeout waiting for response.")
                return None

    except Exception as e:
        print(f"Error fetching HTML: {e}")
        return None

def extract_links(html_content, base_url):
    links = []
    parser = TextHTMLParser()
    parser.feed(html_content)
    text = parser.get_text()
    for word in re.findall(r'(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)', text):
        try:
            parsed_url = urllib.parse.urlparse(word)
            if parsed_url.netloc == base_url:
                links.append(parsed_url.path)
        except:
            pass

    return links

def display_text(html_content):
    if html_content:
        parser = TextHTMLParser()
        parser.feed(html_content)
        print(parser.get_text())
    else:
        print("No content to display.")

def main(destination, path="/", history=None):
    if history is None:
        history = []
    history.append((destination, path))

    html_content = fetch_html(destination, path)
    if html_content:
        display_text(html_content)
        links = extract_links(html_content, destination)
        if links:
            print("\nAvailable links:")
            for i, link in enumerate(links):
                print(f"{i+1}. {link}")
            try:
                choice = input("Enter link number to follow (b for back, q to quit): ")
                if choice.lower() == "b" and len(history) > 1:
                    prev_destination, prev_path = history[-2]
                    main(prev_destination, prev_path, history[:-2])
                elif choice.lower() == "q":
                    return
                else:
                    choice = int(choice)
                    if 1 <= choice <= len(links):
                        main(destination, links[choice-1], history)
            except ValueError:
                print("Invalid input.")
                main(destination, path, history)
        else:
            main(destination, path, history)
    else:
        print("No content to display.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Akita Phoenix - Reticulum Text Browser")
    parser.add_argument("destination", help="Destination hash of the Reticulum web server.")
    parser.add_argument("-p", "--path", default="/", help="path to fetch")
    args = parser.parse_args()

    main(args.destination, args.path)
