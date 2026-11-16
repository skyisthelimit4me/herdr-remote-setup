#!/bin/bash
# Herdr Remote Setup - client (macOS).
# Version: see ../VERSION
#
# Stack: network (Tailscale) -> transport (OpenSSH key) -> workspace (herdr)
#
# Usage:
#   bash setup-macos.sh --code "<code>" [--json] [--no-watchdog] [--log-dir DIR]
#   bash setup-macos.sh --version
#   bash setup-macos.sh --self-test
#
# Exit codes: 0 ok, 2 prerequisite, 3 network, 4 transport, 5 herdr, 6 internal
#
# macOS ships bash 3.2: no associative arrays, no ${var,,}, no mapfile,
# no "wait -n", no "&>>". set -e is not used, so a warning cannot abort the flow
# and every stage decides its own exit code.

set -u

EXIT_OK=0
EXIT_PREREQ=2
EXIT_NET=3
EXIT_KEY=4
EXIT_HERDR=5
EXIT_INTERNAL=6

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="0.0.0"
if [ -f "$PACKAGE_ROOT/VERSION" ]; then
    VERSION="$(tr -d ' \t\r\n' < "$PACKAGE_ROOT/VERSION")"
fi

CODE_ARG=""
JSON_MODE=0
LOG_DIR_ARG=""
NO_WATCHDOG=0
ACTION="run"
WATCHDOG_MINUTES=2

LOG_DIR=""
LOG_FILE=""
TMP_DIR=""

# ---------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --code)
            if [ $# -lt 2 ]; then
                printf 'X --code needs a value\n' >&2
                exit "$EXIT_PREREQ"
            fi
            CODE_ARG="$2"
            shift 2
            ;;
        --code=*)
            CODE_ARG="${1#--code=}"
            shift
            ;;
        --json)
            JSON_MODE=1
            shift
            ;;
        --version)
            ACTION="version"
            shift
            ;;
        --self-test)
            ACTION="selftest"
            shift
            ;;
        --no-watchdog)
            NO_WATCHDOG=1
            shift
            ;;
        --log-dir)
            if [ $# -lt 2 ]; then
                printf 'X --log-dir needs a value\n' >&2
                exit "$EXIT_PREREQ"
            fi
            LOG_DIR_ARG="$2"
            shift 2
            ;;
        --log-dir=*)
            LOG_DIR_ARG="${1#--log-dir=}"
            shift
            ;;
        --help|-h)
            ACTION="help"
            shift
            ;;
        *)
            printf 'X unknown argument: %s\n' "$1" >&2
            exit "$EXIT_PREREQ"
            ;;
    esac
done

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# Never let a tskey-... value reach a log line or the console.
redact() {
    printf '%s' "$1" | sed 's/tskey-[A-Za-z0-9_-]*/tskey-***REDACTED***/g'
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        | awk 'BEGIN { ORS="" } { if (NR > 1) printf "\\n"; printf "%s", $0 }'
}

log() {
    printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${2:-INFO}" "$(redact "$1")" >> "$LOG_FILE" 2>/dev/null
}

say() {
    if [ -z "$1" ]; then
        if [ "$JSON_MODE" -eq 0 ]; then printf '\n'; fi
        return 0
    fi
    if [ "$JSON_MODE" -eq 0 ]; then printf '%s\n' "$1"; fi
    log "$1"
}

step() {
    if [ "$JSON_MODE" -eq 0 ]; then printf '>> %s\n' "$1"; fi
    log "STEP $1"
}

ok() {
    if [ "$JSON_MODE" -eq 0 ]; then printf 'OK %s\n' "$1"; fi
    log "OK $1"
}

warn() {
    if [ "$JSON_MODE" -eq 0 ]; then printf '! %s\n' "$1"; fi
    log "WARN $1"
}

fail() {
    _code="$1"
    shift
    if [ "$JSON_MODE" -eq 0 ]; then printf 'X %s\n' "$*"; fi
    log "EXIT $_code : $*"
    if [ "$JSON_MODE" -eq 1 ]; then
        printf '{"version":"%s","ok":false,"exitCode":%s,"error":"%s","log":"%s"}\n' \
            "$(json_escape "$VERSION")" "$_code" "$(json_escape "$*")" "$(json_escape "$LOG_FILE")"
    fi
    exit "$_code"
}

b64_pad() {
    _s="$1"
    while [ $(( ${#_s} % 4 )) -ne 0 ]; do
        _s="${_s}="
    done
    printf '%s' "$_s"
}

# macOS base64 decodes with -D; GNU coreutils on other systems uses -d.
# Whitespace is stripped first because base64 output wraps at 76 columns.
b64_decode() {
    _raw="$(printf '%s' "$1" | tr -d ' \t\r\n')"
    _raw="$(b64_pad "$_raw")"
    _dec=""
    if _try="$(printf '%s' "$_raw" | base64 -d 2>/dev/null)"; then
        _dec="$_try"
    fi
    if [ -z "$_dec" ]; then
        if _try="$(printf '%s' "$_raw" | base64 -D 2>/dev/null)"; then
            _dec="$_try"
        fi
    fi
    printf '%s' "$_dec"
}

CODE_FORMAT=""
CODE_MODE="key"
CODE_USER=""
CODE_HOST=""
CODE_DNS=""
CODE_IPS=""
CODE_KEY=""
CODE_TAG=""
ENROLL_PORT=""
ENROLL_TOKEN=""
PARSE_ERROR=""

parse_code() {
    _text="$(b64_decode "$1")"
    if [ -z "$_text" ]; then
        PARSE_ERROR="code is not valid base64"
        return 1
    fi

    _colons="$(printf '%s' "$_text" | tr -cd ':' | wc -c | tr -d ' ')"
    _fields=$(( _colons + 1 ))
    _is_v2=0
    case "$_text" in
        v=*|*";v="*) _is_v2=1 ;;
    esac
    if [ "$_is_v2" -eq 0 ] && [ "$_fields" -lt 3 ]; then
        PARSE_ERROR="code has too few fields"
        return 1
    fi

    CODE_FORMAT="v1"
    CODE_MODE="key"
    CODE_USER=""
    CODE_HOST=""
    CODE_DNS=""
    CODE_IPS=""
    CODE_KEY=""
    CODE_TAG=""
    ENROLL_PORT=""
    ENROLL_TOKEN=""

    if [ "$_is_v2" -eq 1 ]; then
        CODE_FORMAT="v2"
        _save_ifs="$IFS"
        set -f
        IFS=';'
        for _pair in $_text; do
            case "$_pair" in
                v=*) ;;
                mode=*) CODE_MODE="${_pair#mode=}" ;;
                user=*) CODE_USER="${_pair#user=}" ;;
                host=*) CODE_HOST="${_pair#host=}" ;;
                dns=*)  CODE_DNS="${_pair#dns=}" ;;
                ips=*)
                    _ips="${_pair#ips=}"
                    _save2="$IFS"
                    IFS=','
                    for _ip in $_ips; do
                        if [ -n "$_ip" ]; then
                            if [ -z "$CODE_IPS" ]; then
                                CODE_IPS="$_ip"
                            else
                                CODE_IPS="$CODE_IPS $_ip"
                            fi
                        fi
                    done
                    IFS="$_save2"
                    ;;
                key=*) CODE_KEY="${_pair#key=}" ;;
                tag=*) CODE_TAG="${_pair#tag=}" ;;
                enroll=*)
                    _en="${_pair#enroll=}"
                    ENROLL_PORT="${_en%%:*}"
                    case "$_en" in
                        *:*) ENROLL_TOKEN="${_en#*:}" ;;
                        *) ENROLL_TOKEN="" ;;
                    esac
                    ;;
            esac
        done
        IFS="$_save_ifs"
        set +f
    else
        _uh="${_text%%:*}"
        _rest="${_text#*:}"
        _ipsf="${_rest%%:*}"
        _rest="${_rest#*:}"
        _fourth=""
        case "$_rest" in
            *:*) _fourth="${_rest#*:}"; _fourth="${_fourth%%:*}" ;;
        esac
        CODE_USER="${_uh%%@*}"
        case "$_uh" in
            *@*) CODE_HOST="${_uh#*@}" ;;
            *) CODE_HOST="" ;;
        esac
        case "$_fourth" in
            tskey-*) CODE_KEY="$_fourth" ;;
        esac
        _save_ifs="$IFS"
        set -f
        IFS=','
        for _ip in $_ipsf; do
            if [ -n "$_ip" ]; then
                if [ -z "$CODE_IPS" ]; then
                    CODE_IPS="$_ip"
                else
                    CODE_IPS="$CODE_IPS $_ip"
                fi
            fi
        done
        IFS="$_save_ifs"
        set +f
    fi

    case "$ENROLL_PORT" in
        ''|*[!0-9]*) ENROLL_PORT="" ;;
    esac
    if [ -z "$ENROLL_PORT" ]; then
        ENROLL_PORT=""
        ENROLL_TOKEN=""
    fi

    if [ -z "$CODE_USER" ] || [ -z "$CODE_HOST" ] || [ -z "$CODE_IPS" ]; then
        PARSE_ERROR="code fields are empty"
        return 1
    fi
    return 0
}

find_tailscale() {
    if command -v tailscale >/dev/null 2>&1; then
        command -v tailscale
        return 0
    fi
    for _p in \
        /Applications/Tailscale.app/Contents/MacOS/Tailscale \
        /usr/local/bin/tailscale \
        /opt/homebrew/bin/tailscale \
        /opt/homebrew/Cellar/tailscale/*/bin/tailscale
    do
        if [ -x "$_p" ]; then
            printf '%s' "$_p"
            return 0
        fi
    done
    if command -v brew >/dev/null 2>&1; then
        _pre="$(brew --prefix 2>/dev/null)"
        if [ -n "$_pre" ] && [ -x "$_pre/bin/tailscale" ]; then
            printf '%s' "$_pre/bin/tailscale"
            return 0
        fi
    fi
    return 1
}

TS_EXE=""
TS_TARGET_IP=""
DNS_LABEL=""

ts_visible() {
    _s="$("$TS_EXE" status 2>&1)"
    if [ -n "$TS_TARGET_IP" ]; then
        case "$_s" in
            *"$TS_TARGET_IP"*) return 0 ;;
        esac
    fi
    if [ -n "$DNS_LABEL" ]; then
        case "$_s" in
            *"$DNS_LABEL"*) return 0 ;;
        esac
    fi
    return 1
}

find_herdr() {
    if command -v herdr >/dev/null 2>&1; then
        command -v herdr
        return 0
    fi
    for _p in "$HOME/.local/bin/herdr" /opt/homebrew/bin/herdr /usr/local/bin/herdr; do
        if [ -x "$_p" ]; then
            printf '%s' "$_p"
            return 0
        fi
    done
    return 1
}

KEY=""
PUB_KEY=""

probe_target() {
    _out="$("$SSH_BIN" -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=8 \
        -o StrictHostKeyChecking=no -o BatchMode=yes "$CODE_USER@$1" "echo CONNECT_OK" 2>&1)"
    case "$_out" in
        *CONNECT_OK*) return 0 ;;
    esac
    return 1
}

# Pull a string field out of one flattened JSON object. Machines are flat,
# so a greedy line match is enough and no python3/jq is required.
json_field() {
    printf '%s' "$1" \
        | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*/\1/p' \
        | head -n 1
}

json_id() {
    _v="$(json_field "$1" id)"
    if [ -z "$_v" ]; then
        _v="$(printf '%s' "$1" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
    fi
    printf '%s' "$_v"
}

usage() {
    cat <<'EOF'
Herdr Remote Setup - client (macOS)

Usage:
  bash setup-macos.sh --code "<code>" [options]

Options:
  --code <code>       Connection code from the host (required)
  --json              Print one JSON object instead of console text
  --no-watchdog       Skip the watchdog LaunchAgent
  --log-dir <dir>     Log directory (default $HERDR_MACOS_LOG_DIR or
                      $HOME/Library/Logs/HerdrSetup)
  --version           Print the package version
  --self-test         Parse fixtures offline and exit
  --help              Show this help

Exit codes: 0 ok, 2 prerequisite, 3 network, 4 transport, 5 herdr, 6 internal
EOF
}

# ---------------------------------------------------------------
# Early actions: no network, no side effects
# ---------------------------------------------------------------
case "$ACTION" in
    help)
        usage
        exit "$EXIT_OK"
        ;;
    version)
        printf '%s\n' "$VERSION"
        exit "$EXIT_OK"
        ;;
    selftest)
        _problems=""
        if [ ! -f "$PACKAGE_ROOT/VERSION" ]; then
            _problems="$_problems
VERSION file missing"
        fi
        if [ ! -f "$SCRIPT_DIR/watchdog-macos.sh" ]; then
            _problems="$_problems
watchdog-macos.sh missing"
        fi
        if [ ! -f "$SCRIPT_DIR/install-watchdog-macos.sh" ]; then
            _problems="$_problems
install-watchdog-macos.sh missing"
        fi

        _v2payload='v=2;mode=key;user=alice;host=host1;dns=host1.tail.ts.net;ips=100.64.0.1,10.0.0.5;ts=1700000000;tag=tag:herdr-host;key=example-auth-key;enroll=8787:abc123def456'
        _v2code="$(printf '%s' "$_v2payload" | base64 | tr -d '\r\n')"
        if parse_code "$_v2code"; then
            [ "$CODE_FORMAT" = "v2" ] || _problems="$_problems
v2 parse: format"
            [ "$CODE_MODE" = "key" ] || _problems="$_problems
v2 parse: mode"
            [ "$CODE_USER" = "alice" ] || _problems="$_problems
v2 parse: user"
            [ "$CODE_DNS" = "host1.tail.ts.net" ] || _problems="$_problems
v2 parse: dns"
            [ "$CODE_TAG" = "tag:herdr-host" ] || _problems="$_problems
v2 parse: tag"
            [ "$ENROLL_PORT" = "8787" ] || _problems="$_problems
v2 parse: enroll port"
            [ "$ENROLL_TOKEN" = "abc123def456" ] || _problems="$_problems
v2 parse: enroll token"
            [ "$CODE_IPS" = "100.64.0.1 10.0.0.5" ] || _problems="$_problems
v2 parse: ips"
        else
            _problems="$_problems
v2 parse failed: $PARSE_ERROR"
        fi

        _v1payload='alice@host1:100.64.0.1,10.0.0.5:1700000000'
        _v1code="$(printf '%s' "$_v1payload" | base64 | tr -d '\r\n')"
        if parse_code "$_v1code"; then
            [ "$CODE_FORMAT" = "v1" ] || _problems="$_problems
v1 parse: format"
            [ "$CODE_MODE" = "key" ] || _problems="$_problems
v1 parse: default mode"
            [ "$CODE_USER" = "alice" ] || _problems="$_problems
v1 parse: user"
            [ "$CODE_HOST" = "host1" ] || _problems="$_problems
v1 parse: host"
        else
            _problems="$_problems
v1 parse failed: $PARSE_ERROR"
        fi

        if [ -z "$_problems" ]; then
            printf 'SELFTEST OK (v%s; v1+v2 parse ok)\n' "$VERSION"
            exit "$EXIT_OK"
        fi
        printf '%s\n' "$_problems" | while IFS= read -r _pl; do
            if [ -n "$_pl" ]; then printf 'SELFTEST FAIL: %s\n' "$_pl"; fi
        done
        exit "$EXIT_INTERNAL"
        ;;
esac

# ---------------------------------------------------------------
# Log
# ---------------------------------------------------------------
if [ -n "$LOG_DIR_ARG" ]; then
    LOG_DIR="$LOG_DIR_ARG"
elif [ -n "${HERDR_MACOS_LOG_DIR:-}" ]; then
    LOG_DIR="$HERDR_MACOS_LOG_DIR"
else
    LOG_DIR="$HOME/Library/Logs/HerdrSetup"
fi

if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
    printf 'X cannot create log directory: %s\n' "$LOG_DIR" >&2
    exit "$EXIT_INTERNAL"
fi
LOG_FILE="$LOG_DIR/setup-$(date -u +%Y%m%d-%H%M%S).log"

if [ -z "$CODE_ARG" ]; then
    fail "$EXIT_PREREQ" "Missing --code (use --version or --self-test for diagnostics)"
fi

step "Herdr Remote Setup client v$VERSION"
log "log file: $LOG_FILE"

# ---------------------------------------------------------------
step "Decoding connection code"
if ! parse_code "$CODE_ARG"; then
    fail "$EXIT_PREREQ" "Invalid connection code: $PARSE_ERROR"
fi

MODE="$CODE_MODE"
ok "Format: $CODE_FORMAT"
ok "Mode: $MODE"
ok "Remote: $CODE_USER@$CODE_HOST"
if [ -n "$CODE_DNS" ]; then ok "DNS name: $CODE_DNS"; fi
ok "Addresses: $(printf '%s' "$CODE_IPS" | sed 's/ /, /g')"
if [ -n "$CODE_KEY" ]; then ok "Tailscale auth key: present"; else warn "No auth key in code"; fi

if [ "$MODE" = "ts-ssh" ]; then
    warn "Code says mode=ts-ssh; herdr needs key mode. Running the OpenSSH key flow."
    MODE="key"
fi

for _ip in $CODE_IPS; do
    case "$_ip" in
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*)
            TS_TARGET_IP="$_ip"
            break
            ;;
    esac
done
if [ -n "$CODE_DNS" ]; then
    DNS_LABEL="${CODE_DNS%%.*}"
fi

# ---------------------------------------------------------------
step "Checking prerequisites"
if [ "$(uname -s)" != "Darwin" ]; then
    fail "$EXIT_PREREQ" "This script targets macOS (uname -s is $(uname -s))"
fi
SSH_BIN="$(command -v ssh 2>/dev/null)"
if [ -z "$SSH_BIN" ]; then
    fail "$EXIT_PREREQ" "OpenSSH client missing"
fi
ok "OpenSSH client present"
if ! command -v ssh-keygen >/dev/null 2>&1; then
    fail "$EXIT_PREREQ" "ssh-keygen missing"
fi

NEED_TS=0
if [ -n "$TS_TARGET_IP" ]; then NEED_TS=1; fi
if [ -n "$CODE_DNS" ]; then
    case "$CODE_DNS" in
        *.ts.net|*.ts.net.) NEED_TS=1 ;;
    esac
fi

if [ "$NEED_TS" -eq 0 ]; then
    step "No tailnet address in code; skipping Tailscale"
fi

# ---------------------------------------------------------------
if [ "$NEED_TS" -eq 1 ]; then
    step "Network layer (Tailscale)"
    TS_EXE="$(find_tailscale)"

    if [ -z "$TS_EXE" ]; then
        warn "Tailscale not installed"
        if command -v brew >/dev/null 2>&1; then
            step "Installing Tailscale (Homebrew cask)"
            _out="$(brew install --cask tailscale 2>&1)"
            log "$_out"
            # The cask installs the app; tailscaled starts when it first opens.
            if [ -d /Applications/Tailscale.app ]; then
                open -a Tailscale >/dev/null 2>&1 || true
                sleep 3
            fi
            TS_EXE="$(find_tailscale)"
        else
            fail "$EXIT_NET" "Tailscale is not installed and Homebrew is not available. Install it from https://tailscale.com/download/mac (standalone app); the CLI is then /Applications/Tailscale.app/Contents/MacOS/Tailscale"
        fi
        if [ -z "$TS_EXE" ]; then
            fail "$EXIT_NET" "Tailscale install failed. Install it from https://tailscale.com/download/mac (standalone app) and rerun; the CLI is then /Applications/Tailscale.app/Contents/MacOS/Tailscale"
        fi
        ok "Tailscale installed: $TS_EXE"
    else
        ok "Tailscale found: $TS_EXE"
    fi

    if ts_visible; then
        ok "Tailnet path ready"
    else
        if [ -n "$CODE_KEY" ]; then
            step "Joining the tailnet"
            _out="$("$TS_EXE" up "--authkey=$CODE_KEY" --accept-routes=false 2>&1)"
            _rc=$?
            log "$_out"
            if [ "$_rc" -ne 0 ]; then
                # Some builds need root for 'up'. sudo -n never prompts, so the
                # script cannot hang on a password request.
                if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
                    step "Retrying tailscale up with sudo -n"
                    _out="$(sudo -n "$TS_EXE" up "--authkey=$CODE_KEY" --accept-routes=false 2>&1)"
                    _rc=$?
                    log "$_out"
                fi
            fi
            if [ "$_rc" -ne 0 ]; then
                warn "tailscale up returned $_rc; will still poll for the host"
            fi
        else
            warn "Target not visible and no auth key"
            warn "Run 'tailscale up' and log in, then rerun"
        fi

        step "Waiting for the host"
        _waited=0
        _visible=0
        while [ "$_waited" -lt 120 ]; do
            if ts_visible; then
                _visible=1
                break
            fi
            sleep 5
            _waited=$(( _waited + 5 ))
        done
        if [ "$_visible" -eq 0 ]; then
            fail "$EXIT_NET" "Host is not reachable in the tailnet"
        fi
        ok "Tailnet path ready"
    fi
fi

# ---------------------------------------------------------------
step "Workspace layer (herdr)"
HERDR_BIN="$(find_herdr)"
if [ -z "$HERDR_BIN" ]; then
    warn "herdr not installed"
    step "Running the online installer"
    _out="$(curl -fsSL https://herdr.dev/install.sh 2>&1 | sh 2>&1)"
    _rc=$?
    log "$_out"
    HERDR_BIN="$(find_herdr)"
    if [ -z "$HERDR_BIN" ]; then
        fail "$EXIT_HERDR" "herdr could not be installed (installer exit $_rc). Run: curl -fsSL https://herdr.dev/install.sh | sh"
    fi
    ok "herdr installed: $HERDR_BIN"
else
    ok "herdr found: $HERDR_BIN"
fi

# ---------------------------------------------------------------
# Transport: OpenSSH key only. Tailscale SSH breaks herdr's remote bridge.
# ---------------------------------------------------------------
step "Transport layer (OpenSSH key)"
SSH_DIR="$HOME/.ssh"
KEY="$SSH_DIR/id_ed25519"
mkdir -p "$SSH_DIR" 2>/dev/null
chmod 700 "$SSH_DIR" 2>/dev/null
if [ ! -f "$KEY" ]; then
    warn "Generating SSH key"
    _out="$(ssh-keygen -t ed25519 -f "$KEY" -N '' -C "$(whoami)@$(hostname -s)" 2>&1)"
    log "$_out"
fi
if [ ! -f "$KEY.pub" ]; then
    fail "$EXIT_KEY" "Public key missing: $KEY.pub"
fi
PUB_KEY="$(cat "$KEY.pub")"
ok "Public key: $KEY.pub"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/herdr-setup.XXXXXX" 2>/dev/null)"
if [ -z "$TMP_DIR" ] || [ ! -d "$TMP_DIR" ]; then
    fail "$EXIT_INTERNAL" "cannot create a temporary directory"
fi

TARGETS=""
if [ -n "$CODE_DNS" ]; then
    TARGETS="$CODE_DNS"
fi
for _ip in $CODE_IPS; do
    case " $TARGETS " in
        *" $_ip "*) ;;
        *) TARGETS="$TARGETS $_ip" ;;
    esac
done
TARGETS="${TARGETS# }"

WORKING_TARGET=""

for _t in $TARGETS; do
    say "Trying $CODE_USER@$_t"
    if probe_target "$_t"; then
        WORKING_TARGET="$CODE_USER@$_t"
        break
    fi
    warn "Failed: $_t"
done

if [ -z "$WORKING_TARGET" ] && [ -n "$ENROLL_TOKEN" ]; then
    step "Requesting key enrollment from the host"
    say "Token and port come from the connection code; no manual key copy is needed."
    _enroll_file="$TMP_DIR/enroll.json"
    printf '{"code":"%s","key":"%s"}' "$(json_escape "$ENROLL_TOKEN")" "$(json_escape "$PUB_KEY")" > "$_enroll_file"

    _enrolled=0
    for _t in $TARGETS; do
        _resp="$(curl -sS --max-time 10 -H 'Content-Type: application/json' \
            --data-binary "@$_enroll_file" "http://$_t:$ENROLL_PORT/enroll" 2>&1)"
        _rc=$?
        # A 401 still returns a body; only an explicit ok:true means accepted.
        case "$_resp" in
            *'"ok": true'*|*'"ok":true'*)
                if [ "$_rc" -eq 0 ]; then
                    ok "Host accepted the key via $_t"
                    _enrolled=1
                    break
                fi
                ;;
        esac
        warn "Enrollment failed via $_t (curl exit $_rc): $_resp"
    done

    if [ "$_enrolled" -eq 1 ]; then
        sleep 2
        for _t in $TARGETS; do
            say "Retrying $CODE_USER@$_t after enrollment"
            if probe_target "$_t"; then
                WORKING_TARGET="$CODE_USER@$_t"
                break
            fi
            warn "Still failing: $_t"
        done
    else
        warn "Enrollment endpoint unreachable. The host service may have expired (default TTL 600s)."
    fi
fi

if [ -z "$WORKING_TARGET" ]; then
    fail "$EXIT_KEY" "SSH authentication failed and enrollment did not succeed. Add this key on the host manually:
$PUB_KEY
On the host, append that line to ~/.ssh/authorized_keys and rerun."
fi

ok "SSH session: $WORKING_TARGET"

# ---------------------------------------------------------------
step "Registering the machine in herdr"
MACHINE_NAME="${CODE_HOST%%.*}"

EXISTING_ID=""
EXISTING_LABEL=""
EXISTING_TARGET=""

_list="$("$HERDR_BIN" machine list --json 2>/dev/null)"
if [ -n "$_list" ]; then
    _machines_file="$TMP_DIR/machines.txt"
    printf '%s' "$_list" | tr -d '\r\n' | tr '{' '\n' | grep '"target"' > "$_machines_file" 2>/dev/null
    while IFS= read -r _line; do
        if [ -z "$_line" ]; then
            continue
        fi
        _tgt="$(json_field "$_line" target)"
        if [ -z "$_tgt" ]; then
            continue
        fi
        _hit=0
        case "$_tgt" in
            *"$CODE_HOST"*) _hit=1 ;;
        esac
        if [ "$_hit" -eq 0 ] && [ -n "$CODE_DNS" ]; then
            case "$_tgt" in
                *"$CODE_DNS"*) _hit=1 ;;
            esac
        fi
        if [ "$_hit" -eq 0 ]; then
            for _ip in $CODE_IPS; do
                case "$_tgt" in
                    *"$_ip"*) _hit=1; break ;;
                esac
            done
        fi
        if [ "$_hit" -eq 1 ]; then
            EXISTING_ID="$(json_id "$_line")"
            EXISTING_LABEL="$(json_field "$_line" label)"
            EXISTING_TARGET="$_tgt"
            break
        fi
    done < "$_machines_file"
else
    log "machine list --json unavailable; adding a new entry"
fi

if [ -n "$EXISTING_TARGET" ]; then
    if [ -n "$EXISTING_LABEL" ]; then
        MACHINE_NAME="$EXISTING_LABEL"
    fi
    if [ "$EXISTING_TARGET" != "$WORKING_TARGET" ]; then
        # Removing a machine whose surface is attached triggers herdr #3842.
        # Without a parsed id, leave the entry alone.
        if [ -n "$EXISTING_ID" ]; then
            _out="$("$HERDR_BIN" machine remove "$EXISTING_ID" 2>&1)"
            log "$_out"
            _out="$("$HERDR_BIN" machine add "$WORKING_TARGET" --label "$MACHINE_NAME" 2>&1)"
            log "$_out"
            ok "Machine entry updated: $MACHINE_NAME"
        else
            warn "Existing entry targets $EXISTING_TARGET but its id was not parsed; leaving it unchanged"
        fi
    else
        ok "Machine entry already present: $MACHINE_NAME"
    fi
else
    _out="$("$HERDR_BIN" machine add "$WORKING_TARGET" --label "$MACHINE_NAME" 2>&1)"
    log "$_out"
    ok "Machine entry created: $MACHINE_NAME"
fi

REACHABLE="false"
_status_out="$("$HERDR_BIN" machine status "$MACHINE_NAME" 2>&1)"
_status_rc=$?
# Check the negative forms first: a plain substring test for "reachable" would
# also match "not reachable" and "reachable: false".
case "$_status_out" in
    *"not reachable"*|*unreachable*|*"reachable: false"*|*"reachable=false"*|\
    *'"reachable": false'*|*'"reachable":false'*)
        REACHABLE="false"
        ;;
    *reachable*)
        REACHABLE="true"
        ;;
esac
if [ "$_status_rc" -ne 0 ] && [ "$REACHABLE" = "true" ]; then
    REACHABLE="false"
fi
if [ "$REACHABLE" = "true" ]; then
    ok "herdr machine reachable"
else
    warn "herdr status: $_status_out"
fi

STATE_DIR="$HOME/Library/Application Support/HerdrSetup"
mkdir -p "$STATE_DIR" 2>/dev/null
_machines_txt="$STATE_DIR/machines.txt"
if [ -f "$_machines_txt" ]; then
    if ! grep -Fxq "$MACHINE_NAME" "$_machines_txt" 2>/dev/null; then
        printf '%s\n' "$MACHINE_NAME" >> "$_machines_txt"
    fi
else
    printf '%s\n' "$MACHINE_NAME" > "$_machines_txt"
fi
printf '%s\n' "$MACHINE_NAME" > "$STATE_DIR/last-machine.txt" 2>/dev/null || true
chmod 600 "$STATE_DIR/last-machine.txt" 2>/dev/null || true

# ---------------------------------------------------------------
if [ "$NO_WATCHDOG" -eq 0 ]; then
    step "Installing the connection watchdog"
    _installer="$SCRIPT_DIR/install-watchdog-macos.sh"
    if [ -f "$_installer" ]; then
        _out="$(/bin/bash "$_installer" --interval-minutes "$WATCHDOG_MINUTES" 2>&1)"
        _rc=$?
        log "$_out"
        if [ "$_rc" -eq 0 ]; then
            ok "Watchdog installed (every $WATCHDOG_MINUTES min)"
        else
            warn "Watchdog install failed (exit $_rc): $_out"
        fi
    else
        warn "install-watchdog-macos.sh not found; watchdog skipped"
    fi
else
    warn "Watchdog skipped (--no-watchdog)"
fi

# ---------------------------------------------------------------
if [ "$JSON_MODE" -eq 1 ]; then
    printf '{"version":"%s","ok":true,"exitCode":0,"mode":"%s","host":"%s","dns":"%s","target":"%s","machine":"%s","reachable":%s,"log":"%s"}\n' \
        "$(json_escape "$VERSION")" \
        "$(json_escape "$MODE")" \
        "$(json_escape "$CODE_HOST")" \
        "$(json_escape "$CODE_DNS")" \
        "$(json_escape "$WORKING_TARGET")" \
        "$(json_escape "$MACHINE_NAME")" \
        "$REACHABLE" \
        "$(json_escape "$LOG_FILE")"
else
    say ""
    say "================================================================"
    say "  Setup complete (v$VERSION, mode $MODE)"
    say "================================================================"
    say ""
    say "  herdr --machine $MACHINE_NAME"
    say "  herdr --remote $WORKING_TARGET"
    say ""
    say "  log: $LOG_FILE"
    say ""
fi

log "client setup v$VERSION complete mode=$MODE target=$WORKING_TARGET reachable=$REACHABLE"
exit "$EXIT_OK"
