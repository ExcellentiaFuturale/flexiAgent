#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

import enum
import socket
import ssl
import urllib.parse
import websocket

import fwglobals


from fwobject import FwObject

class FwWebSocketClient(FwObject):
    """This class wraps the 3rd party WebSocket object, while enabling to fetch
    local port of the connection. This is needed to configure VPP NAT not to
    block the WebSocket packets due to mismatch of packet to existing NAT session
    once the WebSocket connection is reconnected.
    FlexiEdge device uses WebSocket connection to communicate with flexiManage.
    """

    class FwWebSocketState(enum.Enum):
        IDLE          = 1
        CONNECTING    = 2
        CONNECTED     = 3
        DISCONNECTING = 4


    def __init__(self, on_message, on_open=None, on_close=None):
        """
        :params on_message: the user callback which provides user with received
                            message, when receiving is done by the run_loop_send_recv() method.
        :params on_open:    the user callback which notifies user of established connection.
        :params on_closed:  the user callback which notifies user of connection closure.
        """
        FwObject.__init__(self)

        self.ws           = None
        self.on_open      = on_open
        self.on_message   = on_message
        self.on_close     = on_close
        self.ssl_context  = ssl.create_default_context()
        self.state        = self.FwWebSocketState.IDLE

    def finalize(self):
        self.disconnect()

    def connect(self, url, headers=None, check_certificate=True, timeout=10, local_port=0):
        """Establishes connection to the provided URL.

        :params url:     the address of the server to connect to.
        :params headers: the user HTTP headers to be sent during handshake.
        :params check_certificate: if False, the remote peer will be not
                         requested to provide valid certificate.
        :params timeout: the timeout for read operations during handshake.
        """
        parsed_url  = urllib.parse.urlparse(url)
        remote_host = parsed_url.hostname
        remote_port = parsed_url.port if parsed_url.port else 443

        try:
            self.log.debug(f"connecting to {remote_host}")
            self.state = self.FwWebSocketState.CONNECTING

            # We create socket explicitly to be able to control the local port
            # used by it. Fwagent might use it for NAT.
            # In case of loadsimulator we can't use same port for multiple connections.
            #
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if local_port and not fwglobals.g.loadsimulator:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # Avoid EADDRINUSE on reconnect
                sock.bind(('', local_port))
            sock.settimeout(timeout)

            self.ssl_context.verify_mode    = ssl.CERT_REQUIRED if check_certificate else ssl.CERT_OPTIONAL
            self.ssl_context.check_hostname = True
            ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=remote_host)
            ssl_sock.connect((remote_host, remote_port))

            # Now upgrade TLS connection to WebSocket
            #
            self.ws = websocket.create_connection(
                                    url,
                                    socket = ssl_sock,
                                    enable_multithread = True,
                                    header = headers)

            self.log.debug(f"connected to {remote_host}")
            self.state = self.FwWebSocketState.CONNECTED

            self.remote_host = remote_host
            if self.on_open:
                self.on_open()


        # The try-except is need to exit gracefully , if self.on_open() raises exception
        #
        except Exception as e:
            if self.ws:
                self.ws.close()
                self.ws = None
            # No need to shutdown() and close() socket - websocket.create_connection()
            # closes socket brutally on any error to my sorrow, so we will get exception here!
            # ------------------------------------------------------------------------
            #elif sock:
            #    sock.shutdown(socket.SHUT_RDWR)
            #    sock.close()
            self.log.error(f"failed to connect to {remote_host}: {str(e)}")
            raise e


    def disconnect(self):
        """Disconnects the active connection if exists.
        The connect() can be invoked again to establish new connection.
        """
        if self.state != self.FwWebSocketState.CONNECTED:
            return
        self.state = self.FwWebSocketState.DISCONNECTING
        self.log.debug(f"disconnecting from {self.remote_host}")

        #self.ws.shutdown() # The shutdown() actually calls the close()
        self.ws.close()     # The close() performs shutdown as well, though not graceful :(

    def close(self):
        if self.ws:
            self.ws.close()
            self.ws = None
        if self.on_close:
            self.on_close()
        self.state = self.FwWebSocketState.IDLE

    def run_loop_send_recv(self, timeout=None):
        """Runs infinite loop of recv/recv-n-send operations.
        The loop exits in two cases:
            - on timeout on waiting for incoming data to be read from connection
            - on connection closure by remote peer (OPCODE_CLOSE is received).
        In the first case the WebSocketTimeoutException exception is raised,
        in the second - the function returns normally.

        :params timeout: how much second to wait for the data to be received.
                         If no data was received within 'timeout' seconds,
                         raises the websocket.WebSocketTimeoutException exception.
        """
        while self.state == self.FwWebSocketState.CONNECTED:
            received = self.recv(timeout)
            if received:
                to_send = self.on_message(received)
                if to_send:
                    self.send(to_send)


    def recv(self, timeout=None):
        """Reads data from connection.

        :params timeout: how much second to wait for the data to be received.
                         If no data was received within 'timeout' seconds,
                         raises the websocket.WebSocketTimeoutException exception.

        :returns: the received data or None if connection was closed.
        """
        if not timeout:
            timeout = 0xffffffff
        self.ws.settimeout(timeout)

        try:
            opcode, received = self.ws.recv_data()

            if opcode == 0x1 or opcode == 0x2:   # OPCODE_TEXT / OPCODE_BINARY rfc5234
                return received

            if opcode == 0x8:                    # OPCODE_CLOSE rfc5234
                if self.state == self.FwWebSocketState.CONNECTED:
                    self.disconnect()
                elif self.state == self.FwWebSocketState.DISCONNECTING:
                    self.close()
                else:
                    raise Exception(f"not expected state {str(self.state)}")
                return None

            else:
                raise Exception(f"not suppported opcode {opcode}")

        except Exception as e:
            self.log.error(f"recv_send_loop: exception: {str(e)}")
            self.close()
            raise e

    def send(self, data):
        """Pushes data into connection.
        """
        self.ws.send(data)
