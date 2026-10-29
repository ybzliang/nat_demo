# NAT demo

A minimal HTTP reverse tunnel (内网穿透): a client behind NAT registers on a
public server, which opens a public port and forwards HTTP requests to the
client over a persistent channel; the client proxies them to a local service.

```
remote {nat_server_ip:remote_port} <---> client <---> local {127.0.0.1:local_port}
```

## Prepare

Python 3, standard library only — no dependencies to install.

## NAT Server

Run on the public node:

```
python3 nat_server.py --port=8080
```

## NAT Client

Run on the device behind NAT:

```
NAT_SERVER="10.10.2.2:8080" python3 nat_client.py --type=http --local_port=8811 --remote_port=8811
```

- `NAT_SERVER`: `host:port` of the NAT server (required).
- `local_port`: the local service to expose.
- `remote_port`: the public port opened on the NAT server.
- `type`: proxy protocol; only `http` is supported.
- `--token` / env `NAT_TOKEN`: shared secret; required only when the server
  runs with `--token` (otherwise registrations are unauthenticated — anyone
  reaching the control port can claim or hijack ports).

Then `curl http://<nat_server_ip>:<remote_port>/` reaches `127.0.0.1:local_port`.

## Protocol

- Control port (`--port`): the client sends `register;http;<remote_port>[;<token>]`
  + CRLF; the server replies `ok;<remote_port>` or `error;<reason>` + CRLF.
- Channel (the persistent client connection): messages are framed as
  `<8-byte big-endian length><payload>` carrying one complete HTTP request
  or response each.
- Remote port: each accepted connection carries one complete HTTP request;
  one complete HTTP response is written back.
- Edge HTTP framing: `\r\n\r\n` + `Content-Length`; `Transfer-Encoding:
  chunked` and close-delimited (HTTP/1.0) bodies are also read fully.
- Re-registering a port replaces the stale registration; the client
  reconnects and re-registers automatically on channel failure.

## Notes

- One in-flight request per registration (requests on a remote port are
  serialized through the channel lock).
- Single message cap is 16MB (`HTTP_MAX_MESSAGE_SIZE` in `src/const.py`).
