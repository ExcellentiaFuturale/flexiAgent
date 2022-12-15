#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

################################################################################
# This module implements a reverse web proxy
# It's still in a beta phase and missing some functionality TBD:
#
# Add thread to pull requests from local servers, don't block main thread
# Don't block regular APIs because of web proxy traffic - use queues if thread
#    is not sufficient
# Add Multithreading and server multiple requests at the same time
# Support post requests
# Split big files into chunks - check also these options:
#     https://stackoverflow.com/a/60401415
#     https://stackoverflow.com/a/53101953
# Add a key generated in the device and signed by the backend -
#     key generation can also be generated with priveleges and
#     signed in backend to prevent accessing the device
#
# Optional:
# Add compression
# HTTP links should go directly, now they are not proxified well
# Consider moving big files to the internet or the backend
#    without accessing the device. Or at least remove the
#    time so it can be cached locally
#
# NTOP specific:
# Top traffic kbps is not showing in flows dashboard and also host links
# ntopng.css.map is not proxified well
#
################################################################################

import os
import re
import requests
from html.parser import HTMLParser
from urllib.parse import urlparse, quote_plus, unquote
import base64

# Propagate the response headers into the backend response
def _get_resp_headers(resp):
    res_headers = []
    resp_headers = resp.headers
    for key in resp_headers:
        if key not in [
            'Content-Encoding',
            'Transfer-Encoding',
            'Content-Length',
            'X-Frame-Options',
            'X-Content-Type-Options']:
            res_headers.append((key, resp_headers[key]))
    res_headers.append(('Content-Length', len(resp.content)))
    return res_headers

def do_GET(url, server, type, headers, body):
    """Process a GET request from backend

    :param url:      String, the URL to query from local server
    :param type:     String, Request type, GET/POST
    :param headers:  List of tuples, (Header, Value)
    :param body:     String, Body of request if exists, otherwise None

    :returns: JSON, response to send to the backend with:
           response - Base64 encoded
           headers  - List of tuples, (Header, Value)
           status   - Int, status code
    """
    # Convert the quoted URL
    url = unquote(url)
    # TBD: Set headers
    # Get response
    resp = requests.get(url)
    # Proxify result
    proxify = FwWebProxy()
    # TBD: Take application from request
    proxified_response = proxify.on_complete(url, server, 'ntopng', resp)
    # If response proxified, encode it
    if proxified_response:
        response = proxified_response.encode('utf-8')
    # Otherwise, None is returned, just return the resp content
    else:
        response = resp.content
    # Encode the response to Base64
    response = base64.b64encode(response).decode('ascii')
    return ({
        'response':response,
        'headers':_get_resp_headers(resp),
        'status':resp.status_code
    })

def do_POST(url, type, headers, body):
    """Process a POST request from backend

    :param url:      String, the URL to query from local server
    :param type:     String, Request type, GET/POST
    :param headers:  List of tuples, (Header, Value)
    :param body:     String, Body of request if exists, otherwise None

    :returns: JSON, response to send to the backend with:
           response - Base64 encoded
           headers  - List of tuples, (Header, Value)
           status   - Int, status code
    """
    pass

# Class for proxification handling
class FwWebProxy():
    def __init__(self):
        self.base_url = None
        self.server = None

    def full_url(self, rel, base):
        if not base: return rel
        if rel.startswith('//'): return 'http:' + rel
        if rel == "": return ""
        if urlparse(rel).scheme != '': return rel # already full
        # Check for queries and anchors
        if rel[0] == '#' or rel[0] == '?': return base + rel
        base_parse = urlparse(base)
        # If relative path points to root, use base url
        # Otherwise, keep the path
        if (rel[0] == '/'):
            path = ''
        else: 
            path = os.path.dirname(base_parse.path) + '/'
        full = base_parse.netloc + path + rel
        return base_parse.scheme + '://' + full

    def proxify_url(self, url, safe=''):
        parser = HTMLParser()
        url = parser.unescape(url)
        # Convert to a full url
        url = self.full_url(url, self.base_url)
        return self.server + '/' + quote_plus(url, safe)

    def proxify_form_action(self, matches):
        # When the form action is empty, it means to the current page
        url = matches.group(1).strip()
        if not url: url = self.base_url
        # Proxify action url
        result = matches.group(0).replace(url, self.proxify_url(url))
        # Check if the form method is POST
        form_post = re.search('method=["\']post', matches.group(0), flags=re.I) != None
        # Convert form to POST if needed
        if form_post:
            result = result.replace('<form', '<form method="POST"')
        return result

    def proxify_meta_refresh(self, matches):
        url = matches.group(1).strip()
        return matches.group(0).replace(url, self.proxify_url(url))

    # <title>, <base>, <link>, <style>, <meta>, <script>, <noscript>
    def proxify_head(self, str):
        # TBD: do we need to update base_url contained in href - remove <base> tag entirely
        # TBD: do we need to replace link href with proxified

        # meta, replace url refresh
        # <meta http-equiv="refresh" content="5; url=http://example.com/">
        str = re.sub(
            r'content=["\']\d+\s*;\s*url=(.*?)["\']',
            self.proxify_meta_refresh,
            str,
            flags=re.I|re.M|re.S
        )
        return str

    def proxify_css_url(self, matches):
        url = matches.group(1).strip()
        if (
            url.startswith('data:') or
            ',' in url or
            ('/' not in url and '.' not in url)
        ):
            return matches.group(0)
        return matches.group(0).replace(url, self.proxify_url(url))

    def proxify_css_import(self, matches):
        # Examples: https://developer.mozilla.org/en-US/docs/Web/CSS/@import
        # @import url("fineprint.css") print;
        # @import url("bluish.css") print, screen;
        # @import "common.css" screen;
        # @import url("landscape.css") screen and (orientation: landscape);
        # @import url("narrow.css") supports(display: flex) screen and (max-width: 400px);
        url = matches.group(1).strip()
        return matches.group(0).replace(url, self.proxify_url(url))

    def proxify_css(self, str):
        # HTML5 supports also unquotes attributes
        str = re.sub(
            r'[^a-z]{1}url\s*\((?:\'|"|`|)(.*?)(?:\'|"|`|\))',
            self.proxify_css_url,
            str,
            flags=re.I|re.M|re.S
        )

        str = re.sub(
            r'@import ["\'](.*?)["\']',
            self.proxify_css_import,
            str,
            flags=re.I|re.M|re.S
        )
        return str

    def proxify_html_attr_href_src(self, matches):
        url = matches.group(1).strip()
        skip_attr = tuple([
            'data:', 'magnet:', 'about:', 'javascript:',
            'mailto:', 'tel:', 'ios-app:', 'android-app:']
        )
        if not url or url.startswith(skip_attr):
            return matches.group(0)
        return matches.group(0).replace(url, self.proxify_url(url))

    def proxify_html_attr(self, str):
        # proxify src= and href=
        str = re.sub(
            r'(?:src|href)\s*=\s*["\'](.*?)["\']',
            self.proxify_html_attr_href_src,
            str,
            flags=re.I|re.M|re.S
        )
        return str

    def proxify_form(self, str):
        str = re.sub(
            r'<\s*form[^>]*action=["\'](.*?)["\'][^>]*>',
            self.proxify_form_action,
            str,
            flags=re.I|re.M|re.S
        )
        return str

    def proxify_ntopng(self, matches):
        url = matches.group(1).strip()
        url_nobase = url.replace('${base_path}','')
        return matches.group(0).replace(url, self.proxify_url(url_nobase, safe='${}'))

    def proxify_application(self, str, application):
        if (application == 'ntopng'):
            # TBD: Proxify ntop spefic, move to a separate application specific module
            str = re.sub(
                r'["\'`]([^"\'`]*/lua/.*?.lua.*?)[\\"\'`\?]',
                self.proxify_ntopng,
                str,
                flags=re.I|re.M|re.S
            )
        return str

    def on_before_request(self, url, type, header, body):
        pass

    def on_complete(self, url, server, application, resp):
        # Skip proxification for font files .woff2 and .ttf
        no_proxify_ext = ['.woff2', '.ttf']
        if any(c in url for c in no_proxify_ext):
            return None

        # Skip proxification on .js files and text/plain content type
        content_type = resp.headers.get('Content-Type')
        no_proxify_js = [
            'text/javascript', 'application/javascript',
            'application/x-javascript', 'text/plain']
        if any(c in content_type for c in no_proxify_js):
            return None

        # Prepend http in url if needed
        if not url.startswith('http'):
            url = 'http://' + url
        # set the base url to be used for proxifying
        self.base_url = url
        self.server = server
        str = resp.text

        # TBD: Should we protect against extarnal js or iframes?

        str = self.proxify_head(str)
        str = self.proxify_css(str)
        str = self.proxify_html_attr(str)

        str = self.proxify_application(str, application)

        str = self.proxify_form(str)

        return str

