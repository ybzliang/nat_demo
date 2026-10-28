import argparse
import os
import socket
import time

from src.const import CONNECT_TIMEOUT, HTTP_IO_TIMEOUT, MAX_LINE_SIZE
from src.socket_helper import (
    BufferedSocket,
    read_http_message,
    simple_http_response,
)


def connect_channel(host, port):
    s = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    s.settimeout(None)  # block while idle-waiting for requests
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s


def register(reader, proxy_type, remote_port):
    reader.sock.sendall(
        "register;{};{}\r\n".format(proxy_type, remote_port).encode()
    )
    line = reader.read_until(b"\r\n", MAX_LINE_SIZE).decode().strip()
    parts = line.split(";")
    if len(parts) < 2 or parts[0] != "ok":
        raise ConnectionError("register rejected: {}".format(line))


def proxy_to_local(request, local_port):
    local = socket.create_connection(
        ("127.0.0.1", local_port), timeout=CONNECT_TIMEOUT
    )
    try:
        local.settimeout(HTTP_IO_TIMEOUT)
        local.sendall(request)
        return read_http_message(BufferedSocket(local))
    finally:
        local.close()


def serve(reader, local_port):
    channel = reader.sock
    while True:
        request = read_http_message(reader)
        try:
            response = proxy_to_local(request, local_port)
        except OSError as err:
            print("Local service unavailable: {}".format(err))
            response = simple_http_response(
                502, "Bad Gateway", b"local service unavailable"
            )
        channel.sendall(response)


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
    parser.add_argument("--type", help="Proxy type, e.g. http", required=True)
    parser.add_argument(
        "--local_port", type=int, help="Local service port", required=True
    )
    parser.add_argument(
        "--remote_port", type=int, help="Public port to open on NAT server", required=True
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
            register(reader, args.type, args.remote_port)
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
