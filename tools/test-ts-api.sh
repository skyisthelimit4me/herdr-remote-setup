#!/usr/bin/env bash
# Tests for host/ensure-acl.sh and host/guest-key.sh against a mock API.
#
# No network and no real Tailscale token. Every case starts a local mock server,
# points the scripts at it, and asserts the exit code, the stdout, and the
# recorded requests.
#
# Usage:
#   bash tools/test-ts-api.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || pwd)"
MOCK="$ROOT/tools/mock-ts-api.py"
ACL="$ROOT/host/ensure-acl.sh"
KEY="$ROOT/host/guest-key.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/herdr-ts-api.XXXXXX")"
MOCK_PID=""
MOCK_DIR=""
PASS=0
FAIL=0

cleanup() {
  if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }

posix_modes() {
    python3 -c 'import os, sys; sys.exit(0 if hasattr(os, "geteuid") else 1)'
}

comment() { printf '\n== %s ==\n' "$1"; }

check() { # name, condition result (0 ok)
  if [ "$2" -eq 0 ]; then
    PASS=$((PASS + 1)); echo "ok   $1"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $1"
  fi
}

expect_rc() { # expected actual name
  check "$3 (exit $2, want $1)" "$([ "$2" -eq "$1" ] && echo 0 || echo 1)"
}

expect_out() { # file needle name
  check "$3" "$(grep -qF -- "$2" "$1" && echo 0 || echo 1)"
}

expect_missing_out() { # file needle name
  check "$3" "$(grep -qF -- "$2" "$1" && echo 1 || echo 0)"
}

start_api() { # policy-file [extra mock args...]
  local policy="$1"; shift
  MOCK_DIR="$WORK/record-$RANDOM"
  mkdir -p "$MOCK_DIR"
  local port_file="$MOCK_DIR/port"
  python3 "$MOCK" --policy "$policy" --record "$MOCK_DIR" --port-file "$port_file" "$@" \
    >"$MOCK_DIR/mock.log" 2>&1 &
  MOCK_PID=$!
  local waited=0
  while [ ! -s "$port_file" ]; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -gt 50 ]; then echo "mock did not start"; cat "$MOCK_DIR/mock.log"; exit 2; fi
  done
  MOCK_PORT="$(cat "$port_file")"
  HERDR_TS_API_URL="http://127.0.0.1:$MOCK_PORT/api/v2"
  export HERDR_TS_API_URL
}

stop_api() {
  if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; fi
  MOCK_PID=""
}

acl_writes() { # count of recorded POSTs
  if [ -f "$MOCK_DIR/acl-writes.txt" ]; then wc -l <"$MOCK_DIR/acl-writes.txt"; else echo 0; fi
}

key_writes() {
  if [ -f "$MOCK_DIR/keys-writes.txt" ]; then wc -l <"$MOCK_DIR/keys-writes.txt"; else echo 0; fi
}

# ---------- fixtures ----------
cat >"$WORK/ready.hujson" <<'EOF'
{
  // the operator's policy, already ready for a tagged guest
  "tagOwners": {
    "tag:client": ["autogroup:admin"],
    "tag:herdr-host": ["autogroup:admin"],
  },
  "grants": [
    {"src": ["tag:client"], "dst": ["tag:herdr-host"], "ip": ["tcp:22", "tcp:8765"]},
  ],
  "hosts": {"nas": "100.64.0.5"},
  "ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["tag:herdr-host"], "users": ["box"]}],
}
EOF
cat >"$WORK/missing.hujson" <<'EOF'
{
  "tagOwners": {
    "tag:herdr-host": ["autogroup:admin"],
  },
  "grants": [
    {"src": ["tag:client"], "dst": ["tag:herdr-host"], "ip": ["tcp:22"]},
  ],
  "hosts": {"nas": "100.64.0.5"},
  "ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["tag:herdr-host"], "users": ["box"]}],
}
EOF
cat >"$WORK/wildcard.hujson" <<'EOF'
{
  "tagOwners": {
    "tag:client": ["autogroup:admin"],
  },
  "acls": [
    {"action": "accept", "src": ["tag:client"], "dst": ["*:22", "*:8765"]},
  ],
}
EOF
cat >"$WORK/default-port.hujson" <<'EOF'
{
  "tagOwners": {
    "tag:client": ["autogroup:admin"],
  },
  "grants": [
    {"src": ["tag:client"], "dst": ["tag:herdr-host"], "ip": ["tcp:22", "tcp:8765"]},
  ],
}
EOF
cat >"$WORK/unsafe-existing.hujson" <<'EOF'
{
  "tagOwners": {
    "tag:client": ["autogroup:admin"],
  },
  "grants": [
    {"src": ["tag:client"], "dst": ["tag:herdr-host"], "ip": ["tcp:22", "tcp:8765"]},
  ],
  "acls": [
    {"action": "accept", "src": ["tag:client"], "dst": ["tag:other:22"]},
  ],
}
EOF
printf 'this is not a policy\n' >"$WORK/broken.txt"
printf '[]\n' >"$WORK/non-object.json"
# Both values are built from parts so a secret scanner sees no key shape.
FAKE_KEY="tskey""-auth-""example-not-a-secret"
printf '%s\n' "tskey""-api-example-not-a-secret" >"$WORK/api.key"
chmod 600 "$WORK/api.key"
export HERDR_TS_API_KEY_FILE="$WORK/api.key"
export HERDR_ACL_BACKUP_DIR="$WORK/backup"

# ---------- ensure-acl: ready policy ----------
comment "ensure-acl: ready policy, verify only"
start_api "$WORK/ready.hujson"
out="$WORK/out-ready.txt"
bash "$ACL" --no-acl-write >"$out" 2>&1
expect_rc 0 $? "ready policy verifies"
expect_out "$out" "ACL already allows tag:client" "ready policy reports ready"
check "ready policy is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: missing entries, verify only ----------
comment "ensure-acl: missing entries, verify only"
start_api "$WORK/missing.hujson"
out="$WORK/out-verify-missing.txt"
bash "$ACL" --no-acl-write >"$out" 2>&1
expect_rc 3 $? "--no-acl-write reports not ready"
expect_out "$out" "the policy was not changed" "verify mode says it did not write"
expect_out "$out" "tcp:8765" "verify mode names the missing port"
check "verify mode is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: add the missing entries ----------
comment "ensure-acl: add the missing entries"
start_api "$WORK/missing.hujson"
out="$WORK/out-add.txt"
bash "$ACL" >"$out" 2>&1
expect_rc 0 $? "missing entries are added and verified"
expect_out "$out" "ACL updated and verified" "add run reports success"
expect_out "$out" "saved policy backup" "add run saves a backup"
check "one policy write" "$([ "$(acl_writes)" -eq 1 ] && echo 0 || echo 1)"
backup_count=$(find "$WORK/backup" -name 'acl-backup-*.hujson' 2>/dev/null | wc -l)
check "one backup file" "$([ "$backup_count" -eq 1 ] && echo 0 || echo 1)"
mode=$(python3 - "$WORK/backup" <<'PY'
import os, sys
root = sys.argv[1]
if os.name == "nt":
    print("0o600")  # Windows has no POSIX mode bits
else:
    for name in os.listdir(root):
        if name.startswith("acl-backup-"):
            print(oct(os.stat(os.path.join(root, name)).st_mode & 0o777))
            break
PY
)
check "backup file is mode 600 ($mode)" "$([ "$mode" = "0o600" ] && echo 0 || echo 1)"
check "merged policy keeps hosts and ssh" "$(python3 - "$MOCK_DIR" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "acl-body-1.json")
policy = json.loads(open(path, encoding="utf-8").read())
ok = (
    policy.get("hosts") == {"nas": "100.64.0.5"}
    and isinstance(policy.get("ssh"), list)
    and "tag:client" in policy.get("tagOwners", {})
    and "tcp:8765" in policy["grants"][0]["ip"]
    and "tcp:22" in policy["grants"][0]["ip"]
)
print(0 if ok else 1)
PY
)" "merged policy keeps the other rules"
stop_api

comment "ensure-acl: custom pairing port"
start_api "$WORK/default-port.hujson"
out="$WORK/out-port.txt"
HERDR_ACL_BACKUP_DIR="$WORK/backup-port" bash "$ACL" --port 9000 >"$out" 2>&1
expect_rc 0 $? "custom port is added"
check "custom port keeps the default" "$(python3 - "$MOCK_DIR" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "acl-body-1.json")
body = json.loads(open(path, encoding="utf-8").read())
ports = body["grants"][0]["ip"]
print(0 if "tcp:9000" in ports and "tcp:8765" in ports else 1)
PY
)" "custom port is written and the default remains"
stop_api

comment "ensure-acl: wildcard legacy acl"
start_api "$WORK/wildcard.hujson"
out="$WORK/out-wildcard.txt"
bash "$ACL" --no-acl-write >"$out" 2>&1
expect_rc 3 $? "wildcard acl is not ready"
expect_out "$out" "tag:herdr-host" "wildcard acl names the host requirement"
stop_api

start_api "$WORK/wildcard.hujson"
out="$WORK/out-wildcard-write.txt"
bash "$ACL" >"$out" 2>&1
expect_rc 3 $? "wildcard acl is not auto-fixed"
expect_out "$out" "does not remove existing rules" "wildcard acl explains the refusal"
check "wildcard acl is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

start_api "$WORK/unsafe-existing.hujson"
out="$WORK/out-unsafe-existing.txt"
bash "$ACL" >"$out" 2>&1
expect_rc 3 $? "unsafe rule is refused when the host rule exists"
expect_out "$out" "does not remove existing rules" "unsafe rule explains the refusal"
check "unsafe rule is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: unparsable policy ----------
comment "ensure-acl: unparsable policy"
start_api "$WORK/broken.txt"
out="$WORK/out-broken.txt"
bash "$ACL" >"$out" 2>&1
expect_rc 3 $? "unparsable policy exits 3"
expect_out "$out" "cannot be parsed" "unparsable policy says so"
check "unparsable policy is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: policy is not an object ----------
comment "ensure-acl: policy is not an object"
start_api "$WORK/non-object.json"
out="$WORK/out-non-object.txt"
bash "$ACL" >"$out" 2>&1
expect_rc 3 $? "non-object policy exits 3"
expect_out "$out" "the policy must be a JSON object" "non-object policy says so"
expect_missing_out "$out" "Traceback" "non-object policy has no traceback"
check "non-object policy is not written" "$([ "$(acl_writes)" -eq 0 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: token cannot read ----------
comment "ensure-acl: token refused"
start_api "$WORK/ready.hujson" --get-status 403
out="$WORK/out-403.txt"
bash "$ACL" --no-acl-write >"$out" 2>&1
expect_rc 3 $? "refused token exits 3"
expect_out "$out" "cannot read the policy" "refused token says so"
stop_api

# ---------- ensure-acl: token cannot write ----------
comment "ensure-acl: write refused"
start_api "$WORK/missing.hujson" --post-status 403
out="$WORK/out-post403.txt"
HERDR_ACL_BACKUP_DIR="$WORK/backup2" bash "$ACL" >"$out" 2>&1
expect_rc 3 $? "refused write exits 3"
expect_out "$out" "cannot write the policy" "refused write says so"
check "refused write was attempted once" "$([ "$(acl_writes)" -eq 1 ] && echo 0 || echo 1)"
stop_api

# ---------- ensure-acl: no key file ----------
comment "ensure-acl: no API key"
out="$WORK/out-nokey.txt"
HERDR_TS_API_KEY_FILE="$WORK/absent.key" bash "$ACL" >"$out" 2>&1
expect_rc 2 $? "missing API key exits 2"
expect_out "$out" "no Tailscale API token" "missing API key says so"

comment "ensure-acl: token mode"
if posix_modes; then
    chmod 644 "$WORK/api.key"
    out="$WORK/out-mode.txt"
    bash "$ACL" --no-acl-write >"$out" 2>&1
    expect_rc 2 $? "group-readable token exits 2"
    expect_out "$out" "readable by group or others" "group-readable token says so"
    chmod 600 "$WORK/api.key"
else
    echo "skip: POSIX mode bits are not available here"
fi

# ---------- guest-key ----------
comment "guest-key: create a join code"
start_api "$WORK/ready.hujson"
out="$WORK/out-key.txt"
bash "$KEY" >"$out" 2>"$WORK/out-key.err"
expect_rc 0 $? "join code is created"
check "stdout holds only the key" "$([ "$(cat "$out")" = "$FAKE_KEY" ] && echo 0 || echo 1)"
check "stderr is empty" "$([ ! -s "$WORK/out-key.err" ] && echo 0 || echo 1)"
check "api key is not printed" "$(grep -qF "tskey-api-" "$out" && echo 1 || echo 0)"
check "request body names the guest tag" "$(python3 - "$MOCK_DIR" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "keys-body-1.json")
body = json.loads(open(path, encoding="utf-8").read())
create = body["capabilities"]["devices"]["create"]
ok = (
    create["tags"] == ["tag:client"]
    and create["reusable"] is False
    and create["preauthorized"] is True
    and body["expirySeconds"] == 3600
)
print(0 if ok else 1)
PY
)" "request body asks for a single-use tagged key"
stop_api

comment "guest-key: token mode"
if posix_modes; then
    chmod 644 "$WORK/api.key"
    out="$WORK/out-key-mode.txt"
    err="$WORK/out-key-mode.err"
    bash "$KEY" >"$out" 2>"$err"
    expect_rc 2 $? "guest-key refuses group-readable token"
    expect_out "$err" "readable by group or others" "guest-key token mode says so"
    chmod 600 "$WORK/api.key"
else
    echo "skip: POSIX mode bits are not available here"
fi

comment "guest-key: API refuses"
start_api "$WORK/ready.hujson" --keys-status 403
out="$WORK/out-key403.txt"
bash "$KEY" >"$out" 2>"$WORK/out-key403.err"
expect_rc 3 $? "refused key exits 3"
check "refused key prints no key" "$([ ! -s "$out" ] && echo 0 || echo 1)"
expect_out "$WORK/out-key403.err" "API refused the key" "refused key says so"
stop_api

# ---------- summary ----------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
