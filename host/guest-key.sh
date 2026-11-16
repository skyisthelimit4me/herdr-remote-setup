#!/usr/bin/env bash
# Create a one-time Tailscale auth key for a herdr guest.
#
# The key joins the guest device as tag:client and expires after one hour. It is
# the "guest join code" that the host reads to the guest. Print only the key to
# stdout; every message goes to stderr.
#
# Usage:
#   ./guest-key.sh              print one join code
#   ./guest-key.sh --self-test  check the request body and a fixture, no network
#
# Exit codes:
#   0  key printed
#   2  the API key file is missing or unreadable
#   3  the API call failed
#
# The API key needs auth-key creation:
#   /etc/herdr-setup/tailscale-api.key   (root, mode 600)
#
# Environment overrides, for tests:
#   HERDR_TS_API_KEY_FILE  key file path
#   HERDR_TS_API_URL       API base URL
#   HERDR_TS_TAILNET       tailnet name, default -
#   HERDR_TS_KEY_EXPIRY    seconds until the key expires, default 3600

set -u

MODE="create"
while [ $# -gt 0 ]; do
  case "$1" in
    --self-test) MODE="self-test" ;;
    --help|-h) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "X unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

KEY_FILE="${HERDR_TS_API_KEY_FILE:-/etc/herdr-setup/tailscale-api.key}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "X python3 is required (macOS: xcode-select --install)" >&2
  exit 2
fi

if [ "$MODE" != "self-test" ] && [ ! -r "$KEY_FILE" ]; then
  echo "X no Tailscale API token at $KEY_FILE" >&2
  exit 2
fi

python3 - "$MODE" <<'PY'
import base64
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("HERDR_TS_API_URL", "https://api.tailscale.com/api/v2").rstrip("/")
TAILNET = os.environ.get("HERDR_TS_TAILNET", "-")
KEY_FILE = os.environ.get("HERDR_TS_API_KEY_FILE", "/etc/herdr-setup/tailscale-api.key")
EXPIRY = int(os.environ.get("HERDR_TS_KEY_EXPIRY", "3600"))

GUEST_TAG = "tag:client"


def request_body(expiry, description):
    return {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": [GUEST_TAG],
                }
            }
        },
        "expirySeconds": expiry,
        "description": description,
    }


def make_description(moment):
    """Describe the key for the admin console.

    The Tailscale API accepts only letters, digits, spaces, dots, dashes, and
    underscores here. A colon in an ISO timestamp is rejected with HTTP 400
    "keys: description had invalid characters", so the time has no colons.
    """
    return "herdr guest %s" % time.strftime("%Y-%m-%dT%H%M%SZ", moment)


def parse_key(payload):
    data = json.loads(payload)
    key = data.get("key")
    if not isinstance(key, str) or not key.startswith("tskey-auth-"):
        raise ValueError("the response has no auth key")
    return key


def read_key_file():
    try:
        with open(KEY_FILE, "rb") as handle:
            info = os.fstat(handle.fileno())
            mode = stat.S_IMODE(info.st_mode)
            euid = effective_uid()
            if euid >= 0 and not key_file_layout_ok(mode, info.st_uid, euid):
                if mode & 0o077:
                    print("X %s is readable by group or others" % KEY_FILE, file=sys.stderr)
                    print("  Run: sudo chmod 600 %s" % KEY_FILE, file=sys.stderr)
                else:
                    print("X %s is not owned by root" % KEY_FILE, file=sys.stderr)
                    print("  Run: sudo chown root:root %s" % KEY_FILE, file=sys.stderr)
                return None
            key = handle.read().decode("utf-8").strip()
    except OSError as error:
        print("X cannot read %s: %s" % (KEY_FILE, error), file=sys.stderr)
        return None
    if not key:
        print("X %s is empty" % KEY_FILE, file=sys.stderr)
        return None
    return key


def effective_uid():
    """The caller's uid, or -1 where the platform has none, such as Windows."""
    getter = getattr(os, "geteuid", None)
    return getter() if getter else -1


def key_file_layout_ok(mode, uid, euid):
    if mode & 0o077:
        return False
    if euid == 0 and uid != 0:
        return False
    return True


def create():
    key = read_key_file()
    if not key:
        return 2

    description = make_description(time.gmtime())
    body = json.dumps(request_body(EXPIRY, description)).encode("utf-8")
    url = "%s/tailnet/%s/keys" % (API, TAILNET)
    request = urllib.request.Request(url, data=body, method="POST")
    token = base64.b64encode((key + ":").encode("utf-8")).decode("ascii")
    request.add_header("Authorization", "Basic " + token)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        print("! the API refused the key (HTTP %d)" % error.code, file=sys.stderr)
        detail = error.read().decode("utf-8", "replace").strip().splitlines()[:3]
        for line in detail:
            print("  " + line, file=sys.stderr)
        return 3
    except Exception as error:  # network, DNS, TLS
        print("! cannot reach the Tailscale API: %s" % error, file=sys.stderr)
        return 3

    try:
        join_code = parse_key(payload)
    except ValueError as error:
        print("! cannot read the API response: %s" % error, file=sys.stderr)
        return 3

    print(join_code)
    return 0


def self_test():
    failures = 0

    def check(name, condition):
        nonlocal failures
        if condition:
            print("ok %s" % name)
        else:
            failures += 1
            print("FAIL %s" % name)

    body = request_body(3600, "herdr guest test")
    create_caps = body["capabilities"]["devices"]["create"]
    check("expiry is passed", body["expirySeconds"] == 3600)
    check("description is passed", body["description"] == "herdr guest test")
    check("key is single use", create_caps["reusable"] is False)
    check("key is not ephemeral", create_caps["ephemeral"] is False)
    check("key is preauthorized", create_caps["preauthorized"] is True)
    check("key joins as the guest tag", create_caps["tags"] == ["tag:client"])
    check("body is valid json", json.loads(json.dumps(body)) == body)
    check("group-readable token is refused", not key_file_layout_ok(0o644, 1000, 0))
    check("mode 600 token is accepted", key_file_layout_ok(0o600, 0, 0))
    check("non-root token owner is refused", not key_file_layout_ok(0o600, 1000, 0))

    # The real API rejects a colon here with HTTP 400, so guard the shape.
    stamp = time.strptime("2026-11-16T08:41:12", "%Y-%m-%dT%H:%M:%S")
    description = make_description(stamp)
    check("description has no colons", ":" not in description)
    check(
        "description is api safe",
        all(c.isalnum() or c in " ._-" for c in description),
    )

    # Built from parts so a secret scanner sees no key shape.
    fixture = "tskey" + "-auth-" + "example-not-a-secret"
    check(
        "fixture key parses",
        parse_key('{"key": "%s"}' % fixture) == fixture,
    )
    for name, payload in (
        ("missing key field", '{"id": "k1"}'),
        ("wrong key prefix", '{"key": "hunter2"}'),
        ("not json", "<html>"),
    ):
        try:
            parse_key(payload)
            check(name + " is refused", False)
        except ValueError:
            check(name + " is refused", True)

    if failures:
        print("self-test failed (%d)" % failures)
        return 1
    print("self-test ok")
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "create"
    if mode == "self-test":
        return self_test()
    return create()


if __name__ == "__main__":
    sys.exit(main())
PY
