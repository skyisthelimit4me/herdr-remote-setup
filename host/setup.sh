#!/usr/bin/env bash
# Herdr Remote Setup - Host side (Linux and macOS)
# Version: see ../VERSION
#
# Stack: network (Tailscale) -> transport (Tailscale SSH or OpenSSH key) -> herdr
#
# Modes:
#   ts-ssh   Tailscale SSH. No SSH keys. Authorization comes from the tailnet ACL.
#   key      OpenSSH public key. Requires the client key in authorized_keys.
#
# Usage:
#   ./setup.sh [--mode ts-ssh|key] [--tag tag:herdr-host] [--authkey tskey-...]
#              [--enable-ssh] [--json] [--quiet] [--version] [--help]
#
# Exit codes:
#   0 ok, 2 prerequisite, 3 network, 4 transport(SSH), 5 herdr, 6 internal

set -u

VERSION="$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.0.0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || dirname "$0")"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/herdr-setup"
LOG_FILE="$STATE_DIR/setup.log"

JSON=0; QUIET=0
AUTHKEY=""
MODE="key"
TAG=""
ENABLE_SSH=0
ENROLL=0
ENROLL_PORT="${HERDR_ENROLL_PORT:-0}"
ENROLL_TTL="${HERDR_ENROLL_TTL:-600}"
ENROLL_BIND=""
ENROLL_TOKEN=""

C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""
if [ -t 1 ]; then
  C_RESET="$(printf '\033[0m')"; C_RED="$(printf '\033[0;31m')"; C_GRN="$(printf '\033[0;32m')"
  C_YEL="$(printf '\033[1;33m')"; C_BLU="$(printf '\033[0;34m')"; C_CYN="$(printf '\033[0;36m')"
fi

log_line() { mkdir -p "$STATE_DIR" 2>/dev/null || true; printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$LOG_FILE" 2>/dev/null || true; }
say()  { [ "$QUIET" -eq 1 ] || echo "$1"; log_line "$1"; }
step() { [ "$JSON" -eq 1 ] && { log_line "STEP $1"; return; }; say "${C_BLU}>>${C_RESET} $1"; }
ok()   { [ "$JSON" -eq 1 ] && { log_line "OK $1"; return; }; say "${C_GRN}OK${C_RESET} $1"; }
warn() { [ "$JSON" -eq 1 ] && { log_line "WARN $1"; return; }; say "${C_YEL}!${C_RESET} $1"; }
errmsg(){ [ "$JSON" -eq 1 ] && { log_line "ERR $1"; return; }; say "${C_RED}X${C_RESET} $1"; }
fail() { local c="$1"; shift; errmsg "$*"; log_line "EXIT $c: $*"; exit "$c"; }

json_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; printf '%s' "$s"; }

# macOS has no setsid. Popen(start_new_session=True) gives the same
# pgrp==session==pid and no controlling tty that herdr needs.
start_detached() {
  if command -v setsid >/dev/null 2>&1; then
    setsid -f "$@" </dev/null >/dev/null 2>&1
  else
    python3 -c 'import subprocess,sys; subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)' "$@"
  fi
}

# sudo -n never prompts. Plain sudo is the fallback for a real terminal.
sudo_cmd() {
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then printf 'sudo -n'; else printf 'sudo'; fi
  fi
}
SU="$(sudo_cmd)"

usage() {
  cat <<EOF
Herdr Remote Setup - Host (v$VERSION)

Usage:
  ./setup.sh [options]

Modes:
  --mode key      OpenSSH public key. Default and recommended for herdr.
  --mode ts-ssh   Tailscale SSH. NOT compatible with herdr's remote bridge.
  --mode auto     ts-ssh when locally enabled, else key. Not recommended.

Options:
  --tag <tag>       Tailscale tag for this node, e.g. tag:herdr-host.
                    Needed so ACL rules keep matching after re-registration.
  --authkey <key>   One-time Tailscale auth key for the client.
  --enable-ssh      Run 'tailscale up --ssh' to enable Tailscale SSH (sudo).
  --enroll          Start a one-time key enrollment endpoint and embed its
                    token in the connection code. Removes the manual step of
                    adding the client key to authorized_keys.
  --enroll-port <n> Enrollment port (default 0: kernel picks a free port).
  --enroll-ttl <n>  Enrollment lifetime in seconds (default 600).
  --json            Machine-readable result.
  --quiet           Suppress progress.
  --version         Print version.
  --help            This text.

Exit codes: 0 ok, 2 prerequisite, 3 network, 4 transport, 5 herdr, 6 internal.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)       MODE="${2:-}"; shift 2 ;;
    --mode=*)     MODE="${1#--mode=}"; shift ;;
    --tag)        TAG="${2:-}"; shift 2 ;;
    --tag=*)      TAG="${1#--tag=}"; shift ;;
    --authkey)    AUTHKEY="${2:-}"; shift 2 ;;
    --authkey=*)  AUTHKEY="${1#--authkey=}"; shift ;;
    --enable-ssh) ENABLE_SSH=1; shift ;;
    --enroll)     ENROLL=1; shift ;;
    --enroll-port)  ENROLL_PORT="${2:-}"; shift 2 ;;
    --enroll-port=*) ENROLL_PORT="${1#--enroll-port=}"; shift ;;
    --enroll-ttl)   ENROLL_TTL="${2:-}"; shift 2 ;;
    --enroll-ttl=*) ENROLL_TTL="${1#--enroll-ttl=}"; shift ;;
    --json)       JSON=1; shift ;;
    --quiet)      QUIET=1; shift ;;
    --version)    echo "$VERSION"; exit 0 ;;
    --help|-h)    usage; exit 0 ;;
    *)            fail 2 "unknown option: $1" ;;
  esac
done

[ -z "$AUTHKEY" ] && AUTHKEY="${HERDR_TS_AUTHKEY:-}"
[ -z "$TAG" ] && TAG="${HERDR_TS_TAG:-}"

case "$MODE" in ts-ssh|key|auto) : ;; *) fail 2 "--mode must be ts-ssh, key, or auto" ;; esac
if [ -n "$AUTHKEY" ]; then case "$AUTHKEY" in tskey-*) : ;; *) fail 2 "auth key must start with tskey-" ;; esac; fi
if [ -n "$TAG" ]; then case "$TAG" in tag:*) : ;; *) fail 2 "tag must start with tag:" ;; esac; fi

mkdir -p "$STATE_DIR" 2>/dev/null || true

step "Preflight (v$VERSION)"
OS_NAME="$(uname -s)"
case "$OS_NAME" in
  Linux|Darwin) : ;;
  *) fail 2 "this script supports Linux and macOS only (found $OS_NAME)" ;;
esac
command -v base64 >/dev/null 2>&1 || fail 2 "base64 not found"
command -v curl   >/dev/null 2>&1 || warn "curl not found; automatic installs will fail"
if ! command -v setsid >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  fail 2 "need setsid or python3 to start the herdr server as a detached session (macOS: xcode-select --install)"
fi
ok "Platform: $(uname -srm)"
log_line "host v$VERSION start mode=$MODE"

# ---------- network ----------
step "Network layer (Tailscale)"
TS_EXE="$(command -v tailscale 2>/dev/null || true)"
[ -z "$TS_EXE" ] && [ -x /usr/bin/tailscale ] && TS_EXE=/usr/bin/tailscale
[ -z "$TS_EXE" ] && [ -x /usr/local/bin/tailscale ] && TS_EXE=/usr/local/bin/tailscale
[ -z "$TS_EXE" ] && [ -x /opt/homebrew/bin/tailscale ] && TS_EXE=/opt/homebrew/bin/tailscale
[ -z "$TS_EXE" ] && [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ] && TS_EXE=/Applications/Tailscale.app/Contents/MacOS/Tailscale

if [ -z "$TS_EXE" ]; then
  warn "Tailscale not installed"
  if [ "$OS_NAME" = "Darwin" ]; then
    BREW="$(command -v brew 2>/dev/null || true)"
    [ -z "$BREW" ] && [ -x /opt/homebrew/bin/brew ] && BREW=/opt/homebrew/bin/brew
    [ -z "$BREW" ] && [ -x /usr/local/bin/brew ] && BREW=/usr/local/bin/brew
    [ -n "$BREW" ] || fail 3 "Tailscale missing; install it from https://tailscale.com/download/mac"
    step "Installing Tailscale"
    "$BREW" install --cask tailscale || fail 3 "Tailscale install failed"
    # The cask CLI lives inside the app bundle, not on PATH.
    [ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ] && TS_EXE=/Applications/Tailscale.app/Contents/MacOS/Tailscale
    [ -z "$TS_EXE" ] && TS_EXE="$(command -v tailscale 2>/dev/null || true)"
    [ -n "$TS_EXE" ] || fail 3 "Tailscale CLI not found after install"
  else
    command -v curl >/dev/null 2>&1 || fail 3 "Tailscale missing and curl unavailable"
    step "Installing Tailscale"
    curl -fsSL https://tailscale.com/install.sh | sh || fail 3 "Tailscale install failed"
    TS_EXE="$(command -v tailscale 2>/dev/null || echo /usr/bin/tailscale)"
  fi
fi

TS_UP=0
if "$TS_EXE" status >/dev/null 2>&1 && ! "$TS_EXE" status 2>/dev/null | head -5 | grep -qi "logged out\|no state"; then
  TS_UP=1
fi
if [ "$TS_UP" -eq 0 ]; then
  warn "Tailscale is not connected"
  if [ -n "$AUTHKEY" ]; then
    step "Connecting with the supplied auth key"
    $SU "$TS_EXE" up ${AUTHKEY:+--authkey="$AUTHKEY"} ${TAG:+--advertise-tags="$TAG"} --accept-routes=false >/dev/null 2>&1 || true
    sleep 3
    "$TS_EXE" status >/dev/null 2>&1 && TS_UP=1
  fi
fi

# Tailscale 1.104 rejects the short -4 flag; try --4, then the bare list.
TS_IP=""
for attempt in --4 -4; do
  TS_IP="$("$TS_EXE" ip "$attempt" 2>/dev/null | grep -E '^100\.' | head -1 || true)"
  [ -n "$TS_IP" ] && break
done
[ -n "$TS_IP" ] || TS_IP="$("$TS_EXE" ip 2>/dev/null | grep -E '^100\.' | head -1 || true)"
[ -n "$TS_IP" ] && ok "Tailscale IP: $TS_IP" || warn "No Tailscale IPv4 address"

TS_DNS="$("$TS_EXE" status --json 2>/dev/null | tr ',' '\n' | sed -n 's/.*"DNSName": *"\([^"]*\)".*/\1/p' | head -1 || true)"
# The first DNSName in status is usually the local node; strip trailing dot.
TS_DNS="${TS_DNS%.}"
[ -n "$TS_DNS" ] && ok "Tailscale DNS name: $TS_DNS"

ts_ssh_enabled() {
  # 1.104.x exposes the flag only in prefs, not in status JSON.
  if "$TS_EXE" debug prefs 2>/dev/null | grep -q '"RunSSH":[[:space:]]*true'; then
    return 0
  fi
  # Older builds expose SSH host keys in status JSON.
  "$TS_EXE" status --json 2>/dev/null | tr ',' '\n' | grep -qi 'sshhostkeys'
}

if [ "$MODE" = "auto" ]; then
  if ts_ssh_enabled; then MODE="ts-ssh"; else MODE="key"; fi
fi
ok "Requested mode: $MODE"

if [ "$MODE" = "ts-ssh" ]; then
  if ! ts_ssh_enabled; then
    if [ "$ENABLE_SSH" -eq 1 ]; then
      step "Enabling Tailscale SSH"
      $SU "$TS_EXE" up --ssh ${TAG:+--advertise-tags="$TAG"} --accept-routes=false >/dev/null 2>&1 || \
        warn "tailscale up --ssh failed"
      sleep 2
    fi
    if ts_ssh_enabled; then
      ok "Tailscale SSH enabled"
    else
      warn "Tailscale SSH is not enabled on this node"
      warn "Enable it with: sudo tailscale up --ssh ${TAG:+--advertise-tags=$TAG}"
      warn "Also add an 'ssh' section to the tailnet ACL."
      if [ "$MODE" = "ts-ssh" ]; then
        fail 4 "Tailscale SSH requested but not enabled (use --enable-ssh, or --mode key)"
      fi
    fi
  else
    ok "Tailscale SSH enabled"
  fi
fi

if [ "$MODE" = "key" ]; then
  if ts_ssh_enabled; then
    warn "Tailscale SSH is enabled on this node."
    warn "herdr's remote bridge does not work over Tailscale SSH."
    warn "Disable it for herdr: sudo tailscale set --ssh=false"
  fi
fi

# ---------- transport ----------
if [ "$MODE" = "key" ]; then
  step "Transport layer (OpenSSH key)"
  SSH_OK=0
  if [ "$OS_NAME" = "Darwin" ]; then
    command -v pgrep >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1 && SSH_OK=1
    [ "$SSH_OK" -eq 0 ] && $SU launchctl print system/com.openssh.sshd >/dev/null 2>&1 && SSH_OK=1
    if [ "$SSH_OK" -eq 0 ]; then
      warn "SSH server not running; trying to start"
      $SU systemsetup -setremotelogin on >/dev/null 2>&1 || true
      sleep 1
      command -v pgrep >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1 && SSH_OK=1
    fi
    [ "$SSH_OK" -eq 1 ] || fail 4 "SSH server is not running; enable System Settings > General > Sharing > Remote Login"
  else
    if command -v systemctl >/dev/null 2>&1; then
      systemctl is-active --quiet sshd 2>/dev/null && SSH_OK=1
      systemctl is-active --quiet ssh 2>/dev/null && SSH_OK=1
    fi
    if [ "$SSH_OK" -eq 0 ] && command -v pgrep >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1; then SSH_OK=1; fi
    if [ "$SSH_OK" -eq 0 ]; then
      warn "SSH server not running; trying to start"
      $SU systemctl start sshd >/dev/null 2>&1 || $SU systemctl start ssh >/dev/null 2>&1 || true
      sleep 1
      command -v pgrep >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1 && SSH_OK=1
    fi
    [ "$SSH_OK" -eq 1 ] || fail 4 "SSH server is not running"
  fi

  mkdir -p "$HOME/.ssh" 2>/dev/null || true
  chmod 700 "$HOME/.ssh" 2>/dev/null || true
  touch "$HOME/.ssh/authorized_keys" 2>/dev/null || true
  chmod 600 "$HOME/.ssh/authorized_keys" 2>/dev/null || true
  if [ "$OS_NAME" = "Darwin" ]; then
    # macOS sshd refuses keys when $HOME is group or other writable.
    HOME_PERM="$(stat -f '%Lp' "$HOME" 2>/dev/null || true)"
    case "$HOME_PERM" in
      ""|*[!0-7]*) : ;;
      *) if [ $(( 0$HOME_PERM & 022 )) -ne 0 ]; then
           chmod go-w "$HOME" 2>/dev/null || true
           ok "Removed group/other write on $HOME (sshd requires it)"
         fi ;;
    esac
  fi
  KEY_COUNT="$(grep -c '^ssh-' "$HOME/.ssh/authorized_keys" 2>/dev/null || true)"
  [ -n "$KEY_COUNT" ] || KEY_COUNT=0
  ok "OpenSSH server running, authorized keys: $KEY_COUNT"
else
  step "Transport layer (Tailscale SSH)"
  ok "No OpenSSH key or authorized_keys needed"
fi

# ---------- herdr ----------
step "Workspace layer (herdr)"
HERDR_EXE="$(command -v herdr 2>/dev/null || true)"
[ -z "$HERDR_EXE" ] && [ -x "$HOME/.local/bin/herdr" ] && HERDR_EXE="$HOME/.local/bin/herdr"
[ -z "$HERDR_EXE" ] && [ -x /opt/homebrew/bin/herdr ] && HERDR_EXE=/opt/homebrew/bin/herdr
[ -z "$HERDR_EXE" ] && [ -x /usr/local/bin/herdr ] && HERDR_EXE=/usr/local/bin/herdr
if [ -z "$HERDR_EXE" ]; then
  warn "herdr not installed"
  command -v curl >/dev/null 2>&1 || fail 5 "herdr missing and curl unavailable"
  curl -fsSL https://herdr.dev/install.sh | sh || fail 5 "herdr install failed"
  export PATH="$HOME/.local/bin:$PATH"
  HERDR_EXE="$(command -v herdr 2>/dev/null || true)"
  [ -z "$HERDR_EXE" ] && [ -x "$HOME/.local/bin/herdr" ] && HERDR_EXE="$HOME/.local/bin/herdr"
  [ -z "$HERDR_EXE" ] && [ -x /opt/homebrew/bin/herdr ] && HERDR_EXE=/opt/homebrew/bin/herdr
  [ -z "$HERDR_EXE" ] && [ -x /usr/local/bin/herdr ] && HERDR_EXE=/usr/local/bin/herdr
  [ -n "$HERDR_EXE" ] || fail 5 "herdr not found after install"
fi
ok "herdr: $("$HERDR_EXE" --version 2>/dev/null | head -1)"

if "$HERDR_EXE" status 2>&1 | grep -q "status: running"; then
  ok "herdr server running"
else
  step "Starting herdr server"
  start_detached "$HERDR_EXE" server
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    "$HERDR_EXE" status 2>&1 | grep -q "status: running" && break
  done
  "$HERDR_EXE" status 2>&1 | grep -q "status: running" || fail 5 "herdr server did not start"
  ok "herdr server started"
fi

# ---------- enrollment endpoint ----------
if [ "$ENROLL" -eq 1 ]; then
  step "Starting key enrollment endpoint"
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 missing; enrollment disabled"
    ENROLL=0
  else
    ENROLL_TOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    umask 077
    PORTFILE="$STATE_DIR/enroll.port"
    rm -f "$PORTFILE" 2>/dev/null || true

    # The endpoint holds a one-time code, so it listens on one address only:
    # the Tailscale address when there is one, otherwise the loopback address.
    ENROLL_BIND="${HERDR_ENROLL_BIND:-${TS_IP:-127.0.0.1}}"

    # Port 0 lets the kernel pick a free port. The platform binds some ports
    # (for example 127.0.0.1:8791); a fixed port can collide and fail silently.
    HERDR_ENROLL_TOKEN="$ENROLL_TOKEN" \
    HERDR_ENROLL_BIND="$ENROLL_BIND" \
    HERDR_ENROLL_PORT="$ENROLL_PORT" \
    HERDR_ENROLL_TTL="$ENROLL_TTL" \
    HERDR_ENROLL_LOG="$STATE_DIR/enroll.log" \
    HERDR_ENROLL_PORTFILE="$PORTFILE" \
      start_detached python3 "$SCRIPT_DIR/enroll.py"

    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -s "$PORTFILE" ] && break
      sleep 0.5
    done

    if [ -s "$PORTFILE" ]; then
      ENROLL_PORT="$(cat "$PORTFILE" 2>/dev/null | tr -d ' \n')"
      printf 'port=%s\ntoken=%s\nttl=%s\n' "$ENROLL_PORT" "$ENROLL_TOKEN" "$ENROLL_TTL" \
        > "$STATE_DIR/enroll.txt" 2>/dev/null || true
      chmod 600 "$STATE_DIR/enroll.txt" 2>/dev/null || true
      ok "Enrollment listening on :$ENROLL_PORT (ttl ${ENROLL_TTL}s)"
    else
      warn "Enrollment endpoint did not start; continuing without it"
      ENROLL=0
    fi
  fi
fi

# ---------- connection code ----------
step "Building connection code"
HOST_NAME="$(hostname 2>/dev/null || echo unknown)"
USER_NAME="$(whoami 2>/dev/null || echo user)"

IPS=""
if command -v ip >/dev/null 2>&1; then
  IPS="$(ip -4 addr show 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | grep -v '^127\.' | paste -sd, - || true)"
elif [ "$OS_NAME" = "Darwin" ] || command -v ifconfig >/dev/null 2>&1; then
  # Darwin has no ip(8); its ifconfig prints the same "inet ADDR" form.
  IPS="$(ifconfig 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | grep -v '^127\.' | paste -sd, - || true)"
fi
if [ -n "$TS_IP" ]; then
  REST="$(printf '%s' "$IPS" | tr ',' '\n' | grep -v -x "$TS_IP" | paste -sd, - || true)"
  if [ -n "$REST" ]; then IPS="$TS_IP,$REST"; else IPS="$TS_IP"; fi
fi
[ -z "$IPS" ] && IPS="unknown"

TIMESTAMP="$(date +%s)"
CODE_V2="v=2"
CODE_V2="${CODE_V2};mode=${MODE}"
CODE_V2="${CODE_V2};user=${USER_NAME}"
CODE_V2="${CODE_V2};host=${HOST_NAME}"
[ -n "$TS_DNS" ] && CODE_V2="${CODE_V2};dns=${TS_DNS}"
CODE_V2="${CODE_V2};ips=${IPS}"
CODE_V2="${CODE_V2};ts=${TIMESTAMP}"
[ -n "$TAG" ] && CODE_V2="${CODE_V2};tag=${TAG}"
[ -n "$AUTHKEY" ] && CODE_V2="${CODE_V2};key=${AUTHKEY}"
if [ "$ENROLL" -eq 1 ] && [ -n "$ENROLL_TOKEN" ]; then
  CODE_V2="${CODE_V2};enroll=${ENROLL_PORT}:${ENROLL_TOKEN}"
fi

if command -v base64 >/dev/null 2>&1; then
  # BSD base64 (macOS) has no -w 0; the fallback strips newlines instead.
  CONNECTION_CODE="$(printf '%s' "$CODE_V2" | base64 -w 0 2>/dev/null || printf '%s' "$CODE_V2" | base64 2>/dev/null | tr -d '\n')"
else
  fail 2 "base64 not found"
fi

CODE_FILE="$STATE_DIR/connection-code.txt"
umask 077
printf '%s\n' "$CONNECTION_CODE" > "$CODE_FILE" 2>/dev/null || true
chmod 600 "$CODE_FILE" 2>/dev/null || true

# ---------- output ----------
IP_JSON="$(printf '%s' "$IPS" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?",":""), $i}}')"

if [ "$JSON" -eq 1 ]; then
  printf '{"version":"%s","mode":"%s","host":"%s","dns":"%s","user":"%s","ips":[%s],"tailscaleIp":"%s","tag":"%s","hasAuthKey":%s,"hasEnroll":%s,"enrollPort":%s,"code":"%s","codeFile":"%s","timestamp":%s}\n' \
    "$VERSION" "$MODE" "$(json_escape "$HOST_NAME")" "$(json_escape "$TS_DNS")" "$(json_escape "$USER_NAME")" \
    "$IP_JSON" "$(json_escape "$TS_IP")" "$(json_escape "$TAG")" \
    "$([ -n "$AUTHKEY" ] && echo true || echo false)" \
    "$([ "$ENROLL" -eq 1 ] && echo true || echo false)" "$ENROLL_PORT" \
    "$CONNECTION_CODE" "$(json_escape "$CODE_FILE")" "$TIMESTAMP"
else
  echo ""
  echo "${C_GRN}================================================================${C_RESET}"
  echo "                 Setup complete (v$VERSION)"
  echo "${C_GRN}================================================================${C_RESET}"
  echo ""
  echo "${C_CYN}Connection code${C_RESET}"
  echo "----------------------------------------------------------------"
  echo ""
  echo "$CONNECTION_CODE"
  echo ""
  echo "----------------------------------------------------------------"
  echo ""
  echo "Details"
  echo "  mode      : ${MODE}"
  echo "  host      : ${USER_NAME}@${HOST_NAME}"
  echo "  dns       : ${TS_DNS:-none}"
  echo "  addresses : ${IPS}"
  echo "  tailscale : ${TS_IP:-none}"
  echo "  tag       : ${TAG:-none}"
  if [ -n "$AUTHKEY" ]; then echo "  auth key  : included (single use, sensitive)"; else echo "  auth key  : not included"; fi
  if [ "$ENROLL" -eq 1 ]; then
    echo "  enroll    : port ${ENROLL_PORT}, one-time token in the code"
  fi
  echo "  saved to  : ${CODE_FILE}"
  echo ""
  if [ "$MODE" = "ts-ssh" ]; then
    echo "Next: run the client setup. Tailscale SSH authorizes by tailnet identity,"
    echo "      so no SSH key exchange is required."
  else
    echo "Next: run the client setup, then authorize its public key on this host."
  fi
  echo ""
fi

log_line "host v$VERSION done mode=$MODE ips=$IPS dns=$TS_DNS"
exit 0
