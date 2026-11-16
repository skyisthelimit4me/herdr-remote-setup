#!/usr/bin/env bash
# Install a systemd unit that keeps the Tailscale node usable after a reboot
# or a re-registration.
#
# Why: if the host loses /var/lib/tailscale (image rebuild, ephemeral disk),
# the node re-registers with a new node key and a new device ID. Without
# re-applying the tag and --ssh, ACL rules stop matching and Tailscale SSH
# stops working. This unit re-asserts them at boot.

set -u

VERSION="$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.0.0")"
ENV_DIR="/etc/herdr-setup"
ENV_FILE="$ENV_DIR/tailscale.env"
UNIT="/etc/systemd/system/herdr-tailscale-ssh.service"

usage() {
  cat <<EOF
Herdr Remote Setup - install autostart (v$VERSION)

Usage:
  sudo ./install-autostart.sh --authkey <tskey-...> [--tag tag:herdr-host] [--no-ssh]

Writes:
  $ENV_FILE       (root 600)   auth key, tag, ssh flag
  $ENV_DIR/boot-guard.sh (755) re-assert guard, checked at boot
  $UNIT                        oneshot unit, runs the guard after tailscaled

The unit is idempotent: the guard only runs 'tailscale up' when the node is
logged out, when --ssh is not enabled, or when the tag is missing. When
'tailscale up' fails the guard exits non-zero, so the unit and the journal
show the failure.
EOF
}

AUTHKEY=""; TAG=""; WANT_SSH=1
while [ $# -gt 0 ]; do
  case "$1" in
    --authkey)  AUTHKEY="${2:-}"; shift 2 ;;
    --authkey=*) AUTHKEY="${1#--authkey=}"; shift ;;
    --tag)      TAG="${2:-}"; shift 2 ;;
    --tag=*)    TAG="${1#--tag=}"; shift ;;
    --no-ssh)   WANT_SSH=0; shift ;;
    --help|-h)  usage; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 2; }
[ -n "$AUTHKEY" ] || { echo "missing --authkey"; usage; exit 2; }
case "$AUTHKEY" in tskey-*) : ;; *) echo "auth key must start with tskey-"; exit 2 ;; esac
if [ -n "$TAG" ]; then case "$TAG" in tag:*) : ;; *) echo "tag must start with tag:"; exit 2 ;; esac; fi

TS_EXE="$(command -v tailscale 2>/dev/null || echo /usr/bin/tailscale)"

mkdir -p "$ENV_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
# Herdr Remote Setup - Tailscale environment (v$VERSION)
TS_AUTHKEY=$AUTHKEY
TS_TAG=$TAG
TS_SSH=$WANT_SSH
TS_EXE=$TS_EXE
EOF
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE" 2>/dev/null || true

GUARD="$ENV_DIR/boot-guard.sh"
cat > "$GUARD" <<'BOOT_GUARD_SCRIPT'
#!/bin/sh
# Re-assert the Tailscale identity, tag, and --ssh after a reboot.
#
# The unit runs this file, never an inline sh -c body: an inline body hides its
# own quoting bugs, and systemd reported success while the guard never ran.
# Reads TS_AUTHKEY, TS_TAG, TS_SSH, TS_EXE from EnvironmentFile.
set -u

TS="${TS_EXE:-/usr/bin/tailscale}"
[ -x "$TS" ] || TS=/usr/bin/tailscale

status="$("$TS" status --json 2>/dev/null)"
compact="$(printf '%s' "$status" | tr -d ' \n')"
need_up=0

case "$compact" in
  *'"BackendState":"Running"'*) : ;;
  *) need_up=1 ;;
esac

if [ "${TS_SSH:-1}" = "1" ]; then
  prefs="$("$TS" debug prefs 2>/dev/null | tr -d ' \n')"
  case "$prefs" in
    *'"RunSSH":true'*) : ;;
    *) need_up=1 ;;
  esac
fi

if [ -n "${TS_TAG:-}" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to check the local tag" >&2
    need_up=1
  elif ! printf '%s' "$status" | python3 -c \
    'import json, sys; d = json.load(sys.stdin); sys.exit(0 if sys.argv[1] in d.get("Self", {}).get("Tags", []) else 1)' \
    "$TS_TAG" 2>/dev/null; then
    need_up=1
  fi
fi

if [ "$need_up" -eq 0 ]; then
  echo "tailscale identity already correct"
  exit 0
fi

if [ -z "${TS_AUTHKEY:-}" ]; then
  echo "no TS_AUTHKEY in /etc/herdr-setup/tailscale.env; cannot re-assert" >&2
  exit 1
fi

set -- up "--authkey=$TS_AUTHKEY" --accept-routes=false
if [ -n "${TS_TAG:-}" ]; then
  set -- "$@" "--advertise-tags=$TS_TAG"
fi
if [ "${TS_SSH:-1}" = "1" ]; then
  set -- "$@" --ssh
fi

echo "re-asserting tailscale identity, ssh=$([ "${TS_SSH:-1}" = "1" ] && echo on || echo off)"
if "$TS" "$@"; then
  echo "tailscale identity re-asserted"
else
  echo "tailscale up failed" >&2
  exit 1
fi
BOOT_GUARD_SCRIPT

chmod 755 "$GUARD"
chown root:root "$GUARD" 2>/dev/null || true

cat > "$UNIT" <<'UNIT_FILE'
[Unit]
Description=Herdr: re-assert Tailscale identity, tag, and SSH after boot
After=tailscaled.service network-online.target
Wants=tailscaled.service
ConditionPathExists=/etc/herdr-setup/tailscale.env
ConditionPathExists=/etc/herdr-setup/boot-guard.sh

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=/etc/herdr-setup/tailscale.env
ExecStart=/bin/sh /etc/herdr-setup/boot-guard.sh

[Install]
WantedBy=multi-user.target
UNIT_FILE

chmod 644 "$UNIT"

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable herdr-tailscale-ssh.service >/dev/null 2>&1 || true

# A failed enable used to print "Enabled" anyway, so a unit that systemd refused
# to load looked installed. Ask systemd for the real state and report that.
ENABLED="unknown"
if command -v systemctl >/dev/null 2>&1; then
  ENABLED="$(systemctl is-enabled herdr-tailscale-ssh.service 2>/dev/null || true)"
fi

echo "Installed: $ENV_FILE (600)"
echo "Installed: $GUARD (755)"
echo "Installed: $UNIT"
case "$ENABLED" in
  enabled) echo "Enabled:   herdr-tailscale-ssh.service" ;;
  *) echo "! Not enabled: herdr-tailscale-ssh.service (systemctl is-enabled said: ${ENABLED:-nothing})" ;;
esac
echo ""
echo "Test now:  sudo systemctl start herdr-tailscale-ssh.service && systemctl status herdr-tailscale-ssh.service --no-pager"
echo "Note: the auth key is stored on disk (root only). Rotate it if it leaks."
