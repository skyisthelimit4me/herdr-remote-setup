#!/usr/bin/env bash
# Start the one-time SSH key enrollment endpoint.
#
# Usage:
#   ./enroll.sh [--bind 127.0.0.1] [--port 8787] [--ttl 600]
#               [--token <code>] [--quiet]
#
# Prints and saves the token. The client posts its public key to
# http://<host>:<port>/enroll with that token.
#
# The endpoint listens on one address only. The loopback default is safe but
# only usable from this computer; pass the Tailscale address for a remote
# client, which is what setup.sh --enroll does.
#
# Exit codes: 0 ok, 2 prerequisite, 6 internal.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || dirname "$0")"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/herdr-setup"
# Standalone helper. For the product flow use `setup.sh --enroll`, which
# picks a free port automatically (port 0) and embeds it in the connection code.
BIND="${HERDR_ENROLL_BIND:-127.0.0.1}"
PORT="${HERDR_ENROLL_PORT:-8787}"
TTL="${HERDR_ENROLL_TTL:-600}"
TOKEN="${HERDR_ENROLL_TOKEN:-}"
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bind)   BIND="${2:-}"; shift 2 ;;
    --bind=*) BIND="${1#--bind=}"; shift ;;
    --port)   PORT="${2:-}"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    --ttl)    TTL="${2:-}"; shift 2 ;;
    --ttl=*)  TTL="${1#--ttl=}"; shift ;;
    --token)  TOKEN="${2:-}"; shift 2 ;;
    --token=*) TOKEN="${1#--token=}"; shift ;;
    --quiet)  QUIET=1; shift ;;
    --help|-h) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

[ -n "$BIND" ] || { echo "--bind needs a value"; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }
[ -f "$SCRIPT_DIR/enroll.py" ] || { echo "enroll.py not found next to enroll.sh"; exit 2; }

if [ -z "$TOKEN" ]; then
  TOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

mkdir -p "$STATE_DIR" 2>/dev/null || true
umask 077
printf 'bind=%s\nport=%s\ntoken=%s\nstarted=%s\nttl=%s\n' "$BIND" "$PORT" "$TOKEN" "$(date +%s)" "$TTL" \
  > "$STATE_DIR/enroll.txt" 2>/dev/null || true
chmod 600 "$STATE_DIR/enroll.txt" 2>/dev/null || true

[ "$QUIET" -eq 1 ] || echo "ENROLL_BIND=$BIND ENROLL_PORT=$PORT ENROLL_TOKEN=$TOKEN TTL=$TTL"

HERDR_ENROLL_TOKEN="$TOKEN" \
HERDR_ENROLL_BIND="$BIND" \
HERDR_ENROLL_PORT="$PORT" \
HERDR_ENROLL_TTL="$TTL" \
HERDR_ENROLL_LOG="$STATE_DIR/enroll.log" \
exec python3 "$SCRIPT_DIR/enroll.py"
