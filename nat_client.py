import argparse
import hashlib
import hmac
import os
import socket
import time

from src.const import CONNECT_TIMEOUT, HTTP_IO_TIMEOUT, MAX_LINE_SIZE
from src.socket_helper import (
    BufferedSocket,
    read_frame,
    read_http_response,
    request_method,
    send_frame,
    simple_http_response,
)


def connect_channel(host, port):
    s = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    s.settimeout(None)  # block while idle-waiting for requests
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s


def register(reader, proxy_type, remote_port, token):
    greeting = reader.read_until(b"\r\n", MAX_LINE_SIZE).decode().strip()
    parts = greeting.split(";")
    if len(parts) != 2 or parts[0] != "nonce":
        raise ConnectionError("unexpected server greeting: {}".format(greeting))
    # Answer the challenge: send HMAC(token, nonce), never the token itself.
    digest = hmac.new(
        token.encode("utf-8"), parts[1].encode("utf-8"), hashlib.sha256
    ).hexdigest()
    reader.sock.sendall(
        "register;{};{};{}\r\n".format(proxy_type, remote_port, digest).encode()
    )
    line = reader.read_until(b"\r\n", MAX_LINE_SIZE).decode().strip()
    parts = line.split(";")
    if len(parts) < 2 or parts[0] != "ok":
        raise ConnectionError("register rejected: {}".format(line))


def proxy_to_local(request, local_port, method):
    local = socket.create_connection(
        ("127.0.0.1", local_port), timeout=CONNECT_TIMEOUT
    )
    try:
        local.settimeout(HTTP_IO_TIMEOUT)
        local.sendall(request)
        return read_http_response(BufferedSocket(local), method)
    finally:
        local.close()


def serve(reader, local_port):
    channel = reader.sock
    while True:
        request = read_frame(reader)
        method = request_method(request)
        try:
            response = proxy_to_local(request, local_port, method)
        except (OSError, ConnectionError, ValueError) as err:
            print("Local service unavailable: {}".format(err))
            response = simple_http_response(
                502, "Bad Gateway", b"local service unavailable"
            )
        send_frame(channel, response)


def parse_nat_server(parser):
    nat_server = os.environ.get("NAT_SERVER")
    if not nat_server:
        parser.error(
            "environment variable NAT_SERVER is required, "
            "e.g. NAT_SERVER=10.10.2.2:8080"
        )
    host, sep, port = nat_server.rpartition(":")
    if not sep or not host:
        parser.error(
            "NAT_SERVER must be in 'host:port' form, got {!r}".format(nat_server)
        )
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        parser.error("NAT_SERVER port must be an integer 1-65535")
    return host, port


def main():
    parser = argparse.ArgumentParser(description="NAT Client")
    parser.add_argument(
        "--type", choices=["http"], help="Proxy type (only http supported)", required=True
    )
    parser.add_argument(
        "--local_port", type=int, help="Local service port", required=True
    )
    parser.add_argument(
        "--remote_port", type=int, help="Public port to open on NAT server", required=True
    )
    parser.add_argument(
        "--token",
        help="Shared secret for registration "
        "(default: env NAT_TOKEN; must match the server's --token if set)",
    )
    args = parser.parse_args()
    for name in ("local_port", "remote_port"):
        if not 1 <= getattr(args, name) <= 65535:
            parser.error("--{} must be between 1 and 65535".format(name))
    nat_host, nat_port = parse_nat_server(parser)

    delay = 1
    while True:
        channel = None
        try:
            channel = connect_channel(nat_host, nat_port)
            reader = BufferedSocket(channel)
            token = args.token if args.token is not None else os.environ.get(
                "NAT_TOKEN", ""
            )
            register(reader, args.type, args.remote_port, token)
            delay = 1
            print(
                "Registered remote_port={} on {}:{}, proxying to 127.0.0.1:{}".format(
                    args.remote_port, nat_host, nat_port, args.local_port
                )
            )
            serve(reader, args.local_port)
        except KeyboardInterrupt:
            break
        except (OSError, ConnectionError, ValueError) as err:
            print(
                "Connection lost: {}; reconnecting in {}s...".format(err, delay)
            )
            time.sleep(delay)
            delay = min(delay * 2, 30)
        finally:
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    pass


if __name__ == "__main__":
    main()
