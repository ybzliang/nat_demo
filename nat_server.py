import argparse
import hmac
import os
import socket
import threading

from src.const import HTTP_IO_TIMEOUT, MAX_LINE_SIZE
from src.socket_helper import (
    BufferedSocket,
    read_frame,
    read_http_request,
    send_frame,
    simple_http_response,
)

# Shared secret required on register when configured via --token/NAT_TOKEN;
# empty means the control port accepts any registration.
SERVER_TOKEN = ""

# remote_port (int) -> {
#     "channel": BufferedSocket,  # persistent conn registered by the nat client
#     "channel_lock": Lock,       # serializes request/response over the channel
#     "listener": socket,         # public listener bound on remote_port
# }
proxy_nat_client_port_map = {}
map_lock = threading.Lock()


def create_listen_socket(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    return s


def close_quietly(sock):
    # shutdown() first: a listener close() alone does not free the port while
    # another thread is blocked in accept() on it (the syscall holds a file
    # reference until it returns; shutdown forces it to error out).
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def unregister(remote_port, entry=None):
    """Drop a registration and release its listener and channel socket.

    If ``entry`` is given, only unregister when the map still holds that
    entry, so a failing in-flight request cannot remove a newer
    registration for the same port.
    """
    with map_lock:
        current = proxy_nat_client_port_map.get(remote_port)
        if current is None or (entry is not None and current is not entry):
            return
        del proxy_nat_client_port_map[remote_port]
    close_quietly(current["listener"])
    close_quietly(current["channel"].sock)
    print("NatClient unregistered, remote_port={}".format(remote_port))


def send_control_reply(conn, message):
    try:
        conn.sendall(message.encode() + b"\r\n")
    except OSError:
        pass


def handle_http_conn(conn, remote_port):
    """Proxy one HTTP request (accepted on a remote listener) to the
    registered nat client and write its response back."""
    conn.settimeout(HTTP_IO_TIMEOUT)
    try:
        request = read_http_request(BufferedSocket(conn))
    except (OSError, ConnectionError, ValueError) as err:
        print("Invalid http request on port {}: {}".format(remote_port, err))
        conn.close()
        return

    with map_lock:
        entry = proxy_nat_client_port_map.get(remote_port)
    if entry is None:
        try:
            conn.sendall(simple_http_response(404, "Not Found", b"port not registered"))
        except OSError:
            pass
        conn.close()
        return

    try:
        with entry["channel_lock"]:
            send_frame(entry["channel"].sock, request)
            response = read_frame(entry["channel"])
        conn.sendall(response)
    except (OSError, ConnectionError, ValueError) as err:
        print("Channel to nat client failed (port {}): {}".format(remote_port, err))
        try:
            conn.sendall(
                simple_http_response(502, "Bad Gateway", b"nat client unavailable")
            )
        except OSError:
            pass
        # Free the port so the client can reconnect and re-register.
        unregister(remote_port, entry=entry)
    finally:
        conn.close()


def remote_accept_loop(remote_port, listener):
    while True:
        try:
            conn, address = listener.accept()
        except OSError:
            # Listener closed by unregister(); exit the loop.
            return
        print("Http request from: {} (remote_port={})".format(address, remote_port))
        threading.Thread(
            target=handle_http_conn, args=(conn, remote_port), daemon=True
        ).start()


def handle_register(conn, reader, proxy_type, remote_port):
    with map_lock:
        stale = proxy_nat_client_port_map.pop(remote_port, None)
        if stale is not None:
            close_quietly(stale["listener"])
            close_quietly(stale["channel"].sock)
            print("Dropped stale registration, remote_port={}".format(remote_port))
        listener = create_listen_socket(remote_port)
        proxy_nat_client_port_map[remote_port] = {
            "channel": reader,
            "channel_lock": threading.Lock(),
            "listener": listener,
        }
    threading.Thread(
        target=remote_accept_loop, args=(remote_port, listener), daemon=True
    ).start()
    send_control_reply(conn, "ok;{}".format(remote_port))
    print(
        "NatClient registered, remote_port={}, proxy_type={}".format(
            remote_port, proxy_type
        )
    )
    # The channel socket stays open, owned by the map entry. This thread ends
    # here; channel traffic is driven by handle_http_conn under channel_lock.


def handle_control_conn(conn, address):
    """Handle one connection on the control port: the only valid command is
    'register;<proxy_type>;<remote_port>' followed by CRLF."""
    conn.settimeout(HTTP_IO_TIMEOUT)
    reader = BufferedSocket(conn)
    try:
        line = reader.read_until(b"\r\n", MAX_LINE_SIZE).decode().strip()
    except (OSError, ConnectionError, ValueError) as err:
        print("Invalid control message from {}: {}".format(address, err))
        conn.close()
        return

    parts = line.split(";")
    if len(parts) in (3, 4) and parts[0] == "register" and parts[1] == "http":
        supplied_token = parts[3] if len(parts) == 4 else ""
        if SERVER_TOKEN and not hmac.compare_digest(supplied_token, SERVER_TOKEN):
            send_control_reply(conn, "error;unauthorized")
            conn.close()
            return
        try:
            remote_port = int(parts[2])
            if not 1 <= remote_port <= 65535:
                raise ValueError("port out of range")
        except ValueError:
            send_control_reply(conn, "error;invalid remote_port")
            conn.close()
            return
        try:
            handle_register(conn, reader, parts[1], remote_port)
        except OSError as err:
            send_control_reply(conn, "error;{}".format(err))
            conn.close()
    else:
        send_control_reply(conn, "error;unknown command")
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="NAT Server")
    parser.add_argument("--port", type=int, help="NAT Server control port", required=True)
    parser.add_argument(
        "--token",
        help="Shared secret clients must present to register "
        "(default: env NAT_TOKEN; unset = no auth)",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    global SERVER_TOKEN
    SERVER_TOKEN = args.token if args.token is not None else os.environ.get("NAT_TOKEN", "")

    control_socket = create_listen_socket(args.port)
    print("NatServer: '0.0.0.0:{}', running...".format(args.port))
    try:
        while True:
            conn, address = control_socket.accept()
            print("Connection from: {}".format(address))
            threading.Thread(
                target=handle_control_conn, args=(conn, address), daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        control_socket.close()


if __name__ == "__main__":
    main()
