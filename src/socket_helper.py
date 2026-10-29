from src.const import HTTP_MAX_MESSAGE_SIZE, MAX_LINE_SIZE, RECV_MAX_SIZE

FRAME_HEADER_SIZE = 8  # uint64 big-endian payload length for channel frames


class BufferedSocket:
    """Recv wrapper holding leftover bytes so framed messages can be
    split correctly across arbitrary TCP segment boundaries."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self):
        chunk = self.sock.recv(RECV_MAX_SIZE)
        if not chunk:
            raise ConnectionError("peer closed connection")
        self.buf += chunk

    def read_until(self, marker, max_size=HTTP_MAX_MESSAGE_SIZE):
        while True:
            idx = self.buf.find(marker)
            if idx != -1:
                end = idx + len(marker)
                data = bytes(self.buf[:end])
                del self.buf[:end]
                return data
            if len(self.buf) > max_size:
                raise ValueError("message exceeds {} bytes".format(max_size))
            self._fill()

    def read_exactly(self, length, max_size=HTTP_MAX_MESSAGE_SIZE):
        if length > max_size:
            raise ValueError("message exceeds {} bytes".format(max_size))
        while len(self.buf) < length:
            self._fill()
        data = bytes(self.buf[:length])
        del self.buf[:length]
        return data

    def read_to_eof(self, max_size=HTTP_MAX_MESSAGE_SIZE):
        """Read until the peer cleanly closes; used for close-delimited
        HTTP/1.0 response bodies. Timeouts and resets are NOT clean EOF —
        they propagate so a stalled/truncated body fails instead of
        being forwarded as a complete response."""
        while True:
            try:
                chunk = self.sock.recv(RECV_MAX_SIZE)
            except OSError:
                raise
            if not chunk:
                break
            self.buf += chunk
            if len(self.buf) > max_size:
                raise ValueError("message exceeds {} bytes".format(max_size))
        data = bytes(self.buf)
        self.buf.clear()
        return data


def send_frame(sock, data: bytes):
    """Frame one channel message as `<u64 length><payload>`; the channel is
    persistent, so framing cannot rely on peer close."""
    if len(data) > HTTP_MAX_MESSAGE_SIZE:
        raise ValueError("message exceeds {} bytes".format(HTTP_MAX_MESSAGE_SIZE))
    sock.sendall(len(data).to_bytes(FRAME_HEADER_SIZE, "big") + data)


def read_frame(reader: BufferedSocket) -> bytes:
    length = int.from_bytes(reader.read_exactly(FRAME_HEADER_SIZE), "big")
    return reader.read_exactly(length)


def _header_value(head: bytes, name: bytes):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(name + b":"):
            return line.split(b":", 1)[1].strip()
    return None


def _read_chunked_body(reader: BufferedSocket) -> bytes:
    body = bytearray()
    while True:
        line = reader.read_until(b"\r\n", MAX_LINE_SIZE)
        body += line
        size = int(line.strip().split(b";", 1)[0], 16)
        if size == 0:
            # Optional trailer section, terminated by an empty line.
            while True:
                trailer = reader.read_until(b"\r\n", MAX_LINE_SIZE)
                body += trailer
                if trailer == b"\r\n":
                    break
            if len(body) > HTTP_MAX_MESSAGE_SIZE:
                raise ValueError(
                    "message exceeds {} bytes".format(HTTP_MAX_MESSAGE_SIZE)
                )
            return bytes(body)
        body += reader.read_exactly(size + 2)  # chunk data + CRLF
        if len(body) > HTTP_MAX_MESSAGE_SIZE:
            raise ValueError("message exceeds {} bytes".format(HTTP_MAX_MESSAGE_SIZE))


def request_method(request: bytes) -> str:
    """First token of the request line ('GET', 'HEAD', ...)."""
    try:
        return request.split(b"\r\n", 1)[0].split(b" ", 1)[0].decode("latin-1").upper()
    except (IndexError, UnicodeDecodeError):
        return ""


def read_http_request(reader: BufferedSocket) -> bytes:
    """Read one complete HTTP request: headers plus body framed by
    Content-Length or Transfer-Encoding: chunked."""
    head = reader.read_until(b"\r\n\r\n")
    transfer = _header_value(head, b"transfer-encoding")
    if transfer and b"chunked" in transfer.lower():
        return head + _read_chunked_body(reader)
    length = _header_value(head, b"content-length")
    if length is not None:
        return head + reader.read_exactly(int(length))
    return head


def read_http_response(reader: BufferedSocket, method: str = "") -> bytes:
    """Read one complete HTTP response.

    Unlike requests, responses may be close-delimited (HTTP/1.0 or
    'Connection: close' without a length) or carry no body at all
    (HEAD replies, 204, 304), so framing is method/status-aware.
    Interim 1xx responses (e.g. 100 Continue) are skipped until the
    final response head arrives.
    """
    while True:
        head = reader.read_until(b"\r\n\r\n")
        status = None
        try:
            status = int(head.split(b"\r\n", 1)[0].split(b" ", 2)[1])
        except (IndexError, ValueError):
            pass
        if status is not None and status < 200:
            continue  # interim response — read the next head
        break

    if method == "HEAD" or status in (204, 304):
        return head

    transfer = _header_value(head, b"transfer-encoding")
    if transfer and b"chunked" in transfer.lower():
        return head + _read_chunked_body(reader)
    length = _header_value(head, b"content-length")
    if length is not None:
        return head + reader.read_exactly(int(length))
    # No length and no transfer coding: the body runs to connection close.
    return head + reader.read_to_eof()


def simple_http_response(status: int, reason: str, body: bytes = b"") -> bytes:
    head = (
        "HTTP/1.1 {} {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).format(status, reason, len(body))
    return head.encode() + body


def recvall(sock, length=-1):
    """
    Receive data from the socket.

    :param length: Bytes to receive; -1 reads until the peer closes or a
        short chunk arrives.
    :return: Received data.
    """
    received_data = bytearray()
    if length == -1:
        while True:
            received_chunk = sock.recv(RECV_MAX_SIZE)
            if not received_chunk:
                break
            received_data += received_chunk
            if len(received_chunk) < RECV_MAX_SIZE:
                break
    else:
        while len(received_data) < length:
            received_chunk = sock.recv(length - len(received_data))
            if not received_chunk:
                break
            received_data += received_chunk

    return bytes(received_data)
