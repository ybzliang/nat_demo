# Test socket (run from repo root or test/ directory).
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$PYTHONPATH:$BASE_DIR"
cd "$BASE_DIR/test"

# In one terminal:
python3 socket_server.py
# In another terminal:
# python3 socket_client.py

# Test NAT Server
# case1: register , then request.
# case2: no register, then request.
