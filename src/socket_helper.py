from src.const import HTTP_MAX_MESSAGE_SIZE, RECV_MAX_SIZE


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

    def read_exactly(self, length):
        while len(self.buf) < length:
            self._fill()
        data = bytes(self.buf[:length])
        del self.buf[:length]
        return data


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    return 0


def read_http_message(reader: BufferedSocket) -> bytes:
    """Read one complete HTTP request/response (headers + body).

    Note: chunked transfer-encoding is not supported; senders must use
    Content-Length (or no body).
    """
    head = reader.read_until(b"\r\n\r\n")
    length = _content_length(head)
    if length:
        return head + reader.read_exactly(length)
    return head


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
