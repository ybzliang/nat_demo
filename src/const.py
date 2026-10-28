RECV_MAX_SIZE = 64 * 1024  # 64KB per recv call

HTTP_MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16MB cap on a single HTTP request/response
MAX_LINE_SIZE = 8 * 1024  # cap on a single protocol line (register command etc.)
HTTP_IO_TIMEOUT = 60  # seconds, socket read/write timeout
CONNECT_TIMEOUT = 10  # seconds, TCP connect timeout
