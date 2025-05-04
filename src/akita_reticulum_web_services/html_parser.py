# src/akita_reticulum_web_services/html_parser.py

import html.parser
import re
import urllib.parse
import os # For os.path.normpath
import logging

# Get logger for this module
logger = logging.getLogger(__name__)

class TextHTMLParser(html.parser.HTMLParser):
    """
    A simple HTML parser that extracts plain text content and relative links
    from HTML data, suitable for a text-based browser.
    It ignores content within <script> and <style> tags.
    """
    def __init__(self, base_destination_hash):
        """
        Initializes the parser.

        Args:
            base_destination_hash (str): The Reticulum destination hash of the
                                         server being browsed. Currently unused
                                         but kept for potential future use in link filtering.
        """
        super().__init__()
        self.text_content = []  # Store text chunks as a list
        self.links = []         # Store valid relative links found (paths)
        self.ignore_content = False # Flag to ignore content inside certain tags
        self.current_href = None # Temporarily store href of current <a> tag
        self.is_in_link_tag = False # Flag to know if we are processing text inside <a>
        self.base_destination_hash = base_destination_hash # Store for potential future use

        # Regex to find common block elements for adding newlines
        self.BLOCK_ELEMENTS = re.compile(r'^(p|br|h[1-6]|div|li|ul|ol|table|tr|td|th|blockquote|hr|pre)$', re.IGNORECASE)
        # Regex to find inline elements where spaces might be needed
        self.INLINE_ELEMENTS = re.compile(r'^(a|b|i|em|strong|span|code|q)$', re.IGNORECASE)


    def handle_starttag(self, tag, attrs):
        """Processes start tags."""
        tag_lower = tag.lower()
        if tag_lower in ["script", "style", "head", "meta", "link"]: # Ignore content of more tags
            self.ignore_content = True
        elif tag_lower == "a":
            # Look for 'href' attribute in <a> tags
            attrs_dict = dict(attrs)
            href = attrs_dict.get('href')
            if href:
                self.current_href = href
                self.is_in_link_tag = True # Mark that we are inside a link tag
                self.try_add_link(href) # Attempt to add the link immediately
        elif self.BLOCK_ELEMENTS.match(tag_lower):
             # Add newline before starting a block element if needed
             if self.text_content and not self.text_content[-1].endswith('\n'):
                  self.text_content.append("\n")


    def handle_endtag(self, tag):
        """Processes end tags."""
        tag_lower = tag.lower()
        if tag_lower in ["script", "style", "head", "meta", "link"]:
            self.ignore_content = False
        elif tag_lower == "a":
            # Reset link state when </a> is encountered
            self.current_href = None
            self.is_in_link_tag = False
            # Add a space after link text if needed
            if self.text_content and not self.text_content[-1].endswith((' ','\n')):
                 self.text_content.append(" ")
        elif self.BLOCK_ELEMENTS.match(tag_lower):
             # Add newline after closing a block element if needed
             if self.text_content and not self.text_content[-1].endswith('\n'):
                 self.text_content.append("\n")


    def handle_data(self, data):
        """Processes text data within tags."""
        if not self.ignore_content:
            # Collapse whitespace within the data chunk itself
            clean_data = ' '.join(data.split())
            if clean_data: # Avoid adding empty strings
                # Add a space before data if the previous chunk didn't end with space/newline
                if self.text_content and not self.text_content[-1].endswith((' ','\n')):
                     self.text_content.append(" ")
                self.text_content.append(clean_data)

    def handle_entityref(self, name):
        """Handle named character entities like &nbsp;"""
        if not self.ignore_content:
            # Basic handling for common entities
            if name == 'nbsp': self.text_content.append(' ')
            elif name == 'lt': self.text_content.append('<')
            elif name == 'gt': self.text_content.append('>')
            elif name == 'amp': self.text_content.append('&')
            elif name == 'quot': self.text_content.append('"')
            elif name == 'apos': self.text_content.append("'")
            # Add more if needed, or consider using html.unescape if complexity increases
            else: self.text_content.append(f'&{name};') # Append the raw entity if unknown

    def handle_charref(self, name):
        """Handle numeric character entities like &#160;"""
        if not self.ignore_content:
            try:
                # Convert numeric entity (decimal or hex) to character
                if name.startswith(('x', 'X')): char_code = int(name[1:], 16)
                else: char_code = int(name)
                self.text_content.append(chr(char_code))
            except ValueError: self.text_content.append(f'&#{name};') # Append raw if conversion fails


    def try_add_link(self, href):
        """
        Attempts to parse a URL and add it to the links list if it's
        a relative path or an absolute path without a scheme/domain.
        Filters out external URLs and javascript links.
        """
        href = href.strip()
        if not href or href.lower().startswith(('javascript:', 'mailto:', '#')):
            logger.debug(f"Ignoring non-navigable link: {href}")
            return # Ignore javascript, mailto, or fragment links

        try:
            parsed_url = urllib.parse.urlparse(href)

            # Allow relative paths (no scheme, no netloc) or absolute paths (no scheme, no netloc, starts with /)
            if not parsed_url.scheme and not parsed_url.netloc:
                # Normalize path: join with '/' to handle relative paths correctly, then normalize
                normalized_path = urllib.parse.urljoin('/', parsed_url.path)
                # Further normalize to remove redundant slashes or dots
                # os.path.normpath might produce backslashes on Windows, replace them
                normalized_path = os.path.normpath(normalized_path).replace('\\', '/')

                # Ensure path starts with / after normalization
                if not normalized_path.startswith('/'): normalized_path = '/' + normalized_path

                # Re-attach query string if present
                if parsed_url.query: normalized_path += "?" + parsed_url.query
                # Re-attach fragment if present (though we ignore fragment-only links earlier)
                # if parsed_url.fragment: normalized_path += "#" + parsed_url.fragment

                if normalized_path not in self.links:
                    self.links.append(normalized_path)
                    logger.debug(f"Added link: {normalized_path} (from href: {href})")
            else: logger.debug(f"Ignoring external or non-relative link: {href}")

        except Exception as e: logger.warning(f"Error parsing link href '{href}': {e}")


    def get_text(self):
        """Returns the extracted plain text content, cleaned up."""
        full_text = "".join(self.text_content).strip()
        full_text = re.sub(r'[ \t]+', ' ', full_text) # Replace multiple spaces/tabs with single space
        full_text = re.sub(r'(\n\s*){2,}', '\n\n', full_text) # Consolidate multiple newlines (max 2)
        return full_text.strip()


    def get_links(self):
        """Returns the list of extracted and filtered relative links (paths)."""
        return list(self.links) # Return a copy

