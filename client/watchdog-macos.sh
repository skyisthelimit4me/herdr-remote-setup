#!/bin/bash
# Herdr remote watchdog (macOS).
# Detects the known "surface revocation" stall (herdr issue #3842) and
# restarts only the local client. The local server, panes, and the remote
# server are left untouched.
#
# Usage:
#   bash watchdog-macos.sh [--dry-run] [--stale-minutes 3] [--machine NAME]
#                          [--quiet] [--client-log PATH]
#
# The relaunched client is started with --machine NAME. The name comes from
# --machine, then HERDR_MACHINE, then the last label that the macOS setup
# recorded in ~/Library/Application Support/HerdrSetup/machines.txt.
#
# Exit codes:
#   0  healthy, nothing to do
#   2  cannot evaluate (missing files, no herdr, no Terminal automation)
#   10 client restarted
#   11 dry run: restart needed

set -u

EXIT_OK=0
EXIT_CANNOT=2
EXIT_RESTARTED=10
EXIT_DRYRUN=11

DRY_RUN=0
STALE_MINUTES=3
QUIET=0
CLIENT_LOG_ARG=""
MACHINE_ARG=""
ACTION="run"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --stale-minutes)
            if [ $# -lt 2 ]; then
                printf 'X --stale-minutes needs a value\n' >&2
                exit "$EXIT_CANNOT"
            fi
            STALE_MINUTES="$2"
            shift 2
            ;;
        --stale-minutes=*)
            STALE_MINUTES="${1#--stale-minutes=}"
            shift
            ;;
        --quiet|-q)
            QUIET=1
            shift
            ;;
        --client-log)
            if [ $# -lt 2 ]; then
                printf 'X --client-log needs a value\n' >&2
                exit "$EXIT_CANNOT"
            fi
            CLIENT_LOG_ARG="$2"
            shift 2
            ;;
        --client-log=*)
            CLIENT_LOG_ARG="${1#--client-log=}"
            shift
            ;;
        --machine)
            if [ $# -lt 2 ]; then
                printf 'X --machine needs a value\n' >&2
                exit "$EXIT_CANNOT"
            fi
            MACHINE_ARG="$2"
            shift 2
            ;;
        --machine=*)
            MACHINE_ARG="${1#--machine=}"
            shift
            ;;
        --help|-h)
            ACTION="help"
            shift
            ;;
        --self-test)
            ACTION="selftest"
            shift
            ;;
        *)
            printf 'X unknown argument: %s\n' "$1" >&2
            exit "$EXIT_CANNOT"
            ;;
    esac
done

case "$STALE_MINUTES" in
    ''|*[!0-9]*)
        printf 'X --stale-minutes must be a number\n' >&2
        exit "$EXIT_CANNOT"
        ;;
esac

classify_lines() {
    STATE="unknown"
    LAST_LINE=""
    LINES_SEEN=0
    while IFS= read -r _line; do
        LINES_SEEN=1
        case "$_line" in
            *"handshake succeeded"*)
                STATE="ok"
                LAST_LINE="$_line"
                ;;
            *"did not acknowledge surface revocation"*|*"endpoint health check timed out"*)
                STATE="stuck"
                LAST_LINE="$_line"
                ;;
            *"endpoint transport failed"*|*"connection was lost"*)
                STATE="fail"
                LAST_LINE="$_line"
                ;;
        esac
    done
}

# Return true only for arguments that launch the TUI.
#
# Herdr accepts global options before an optional command. A command such as
# `herdr --machine host agent list` is not a TUI, even when the first argument
# is an option. Consume the options and their values, then reject any remaining
# positional token.
_is_tui_command() {
    set -f
    set -- $1
    set +f
    while [ $# -gt 0 ]; do
        case "$1" in
            --session|--machine|--remote|--remote-keybindings)
                if [ $# -lt 2 ]; then
                    return 1
                fi
                shift 2
                ;;
            --session=*|--machine=*|--remote=*|--remote-keybindings=*)
                shift
                ;;
            --handoff)
                shift
                ;;
            --help|-h|--version|-V|--default-config|--skill)
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    done
    return 0
}

self_test() {
    failures=0

    check() {
        if [ "$2" -eq 0 ]; then
            printf 'ok %s\n' "$1"
        else
            printf 'FAIL %s\n' "$1"
            failures=$((failures + 1))
        fi
    }

    classify_lines <<'EOF'
client started normally
EOF
    check "benign log is unknown" "$([ "$STATE" = "unknown" ] && echo 0 || echo 1)"
    check "benign log is not a restart" "$([ "$STATE" != "stuck" ] && [ "$STATE" != "fail" ] && echo 0 || echo 1)"

    classify_lines <<'EOF'
handshake succeeded
EOF
    check "healthy log is ok" "$([ "$STATE" = "ok" ] && echo 0 || echo 1)"

    classify_lines <<'EOF'
did not acknowledge surface revocation
EOF
    check "revocation is stuck" "$([ "$STATE" = "stuck" ] && echo 0 || echo 1)"

    classify_lines <<'EOF'
connection was lost
EOF
    check "transport failure is fail" "$([ "$STATE" = "fail" ] && echo 0 || echo 1)"

    classify_lines <<'EOF'
handshake succeeded
connection was lost
EOF
    check "last failure wins" "$([ "$STATE" = "fail" ] && echo 0 || echo 1)"

    classify_lines <<'EOF'
connection was lost
handshake succeeded
EOF
    check "recovery wins" "$([ "$STATE" = "ok" ] && echo 0 || echo 1)"

    _is_tui_command ""
    check "bare client matches" "$?"
    _is_tui_command "--machine box"
    check "client with a machine matches" "$?"
    _is_tui_command "--machine=box --session main"
    check "client with options matches" "$?"
    _is_tui_command "status"
    check "status command is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"
    _is_tui_command "machine status"
    check "machine command is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"
    _is_tui_command "server"
    check "server is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"
    _is_tui_command "remote-client-bridge"
    check "bridge is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"
    _is_tui_command "--help"
    check "help flag is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"
    _is_tui_command "--machine"
    check "option without a value is excluded" "$([ $? -ne 0 ] && echo 0 || echo 1)"

    if [ "$failures" -ne 0 ]; then
        printf 'self-test failed (%d)\n' "$failures"
        return 1
    fi
    printf 'SELFTEST OK (watchdog state gate; TUI client match)\n'
    return 0
}

if [ "$ACTION" = "help" ]; then
    cat <<'EOF'
Herdr remote watchdog (macOS)

Usage:
  bash watchdog-macos.sh [--dry-run] [--stale-minutes N] [--machine NAME]
                         [--quiet] [--client-log PATH]

  --dry-run            Report what would be stopped, exit 11
  --stale-minutes N    Only act when the client log is older than N minutes (default 3)
  --machine NAME       Label of the remote machine to relaunch the client for
  --quiet              Do not write to stdout
  --client-log PATH    Override the client log path

Exit codes: 0 healthy, 2 cannot evaluate, 10 restarted, 11 dry run
EOF
    exit "$EXIT_OK"
fi

if [ "$ACTION" = "selftest" ]; then
    self_test
    exit $?
fi

LOG_DIR="$HOME/Library/Logs/HerdrSetup"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
mkdir -p "$LOG_DIR" 2>/dev/null

log() {
    _line="$(date -u +%Y-%m-%dT%H:%M:%SZ) $1"
    printf '%s\n' "$_line" >> "$WATCHDOG_LOG" 2>/dev/null
    if [ "$QUIET" -eq 0 ]; then
        printf '%s\n' "$_line"
    fi
}

# The macOS herdr client log path was not observed on a real Mac. This list is
# an assumption based on the Linux and Windows locations:
#   ~/Library/Application Support/herdr/herdr-client.log  (Application Support layout)
#   ~/.config/herdr/herdr-client.log                     (XDG layout)
#   ~/Library/Logs/herdr/herdr-client.log                (Logs layout)
# Override with --client-log or HERDR_CLIENT_LOG once the real path is known.
CLIENT_LOG=""
if [ -n "$CLIENT_LOG_ARG" ]; then
    CLIENT_LOG="$CLIENT_LOG_ARG"
elif [ -n "${HERDR_CLIENT_LOG:-}" ]; then
    CLIENT_LOG="$HERDR_CLIENT_LOG"
else
    for _p in \
        "$HOME/Library/Application Support/herdr/herdr-client.log" \
        "$HOME/.config/herdr/herdr-client.log" \
        "$HOME/Library/Logs/herdr/herdr-client.log"
    do
        if [ -f "$_p" ]; then
            CLIENT_LOG="$_p"
            break
        fi
    done
fi

if [ -z "$CLIENT_LOG" ]; then
    log "no client log found (checked Application Support, .config, Library/Logs)"
    exit "$EXIT_CANNOT"
fi
if [ ! -f "$CLIENT_LOG" ]; then
    log "no client log at $CLIENT_LOG"
    exit "$EXIT_CANNOT"
fi

classify_lines < <(tail -n 120 "$CLIENT_LOG" 2>/dev/null)
state="$STATE"
last_line="$LAST_LINE"

if [ "$LINES_SEEN" -eq 0 ]; then
    log "client log is empty"
    exit "$EXIT_OK"
fi

# BSD stat does not accept GNU date -r, so read the mtime directly.
_now="$(date +%s)"
_mtime="$(stat -f %m "$CLIENT_LOG" 2>/dev/null)"
case "$_mtime" in
    ''|*[!0-9]*) _mtime="$_now" ;;
esac
_age_sec=$(( _now - _mtime ))
if [ "$_age_sec" -lt 0 ]; then
    _age_sec=0
fi
_age_min=$(( _age_sec / 60 ))

log "state=$state logAge=${_age_min}min last=${last_line}"

if [ "$state" = "ok" ] || [ "$state" = "unknown" ]; then
    log "no failure state; waiting"
    exit "$EXIT_OK"
fi

_stale_sec=$(( STALE_MINUTES * 60 ))
if [ "$_age_sec" -lt "$_stale_sec" ]; then
    log "recent activity; waiting"
    exit "$EXIT_OK"
fi


# Find the TUI client only. The match is on the program name, not a substring
# of the whole command line: `herdr-core connect`, an SSH control master, and a
# Node helper all carry "herdr" in their arguments and none of them is the
# client. The local server, API commands, and this watchdog are skipped too.
PIDS=""
for _pid in $(pgrep -f 'herdr' 2>/dev/null); do
    _comm="$(ps -o comm= -p "$_pid" 2>/dev/null)"
    _comm="${_comm#"${_comm%%[! ]*}"}"
    if [ "${_comm##*/}" != "herdr" ]; then
        continue
    fi
    _cmd="$(ps -o command= -p "$_pid" 2>/dev/null)"
    if [ -z "$_cmd" ]; then
        continue
    fi
    _rest="${_cmd#"$_comm"}"
    _rest="${_rest#"${_rest%%[! ]*}"}"
    if ! _is_tui_command "$_rest"; then
        continue
    fi
    PIDS="$PIDS $_pid"
done
PIDS="${PIDS# }"

# The relaunch needs the client binary, whatever the selector finds.
HERDR=""
if command -v herdr >/dev/null 2>&1; then
    HERDR="$(command -v herdr)"
else
    for _p in "$HOME/.local/bin/herdr" /opt/homebrew/bin/herdr /usr/local/bin/herdr; do
        if [ -x "$_p" ]; then
            HERDR="$_p"
            break
        fi
    done
fi
if [ -z "$HERDR" ]; then
    log "herdr not found"
    exit "$EXIT_CANNOT"
fi

if [ -z "$PIDS" ]; then
    log "no local client process; nothing to restart"
    exit "$EXIT_OK"
fi

_csv=""
for _pid in $PIDS; do
    if [ -z "$_csv" ]; then
        _csv="$_pid"
    else
        _csv="$_csv,$_pid"
    fi
done

if [ "$DRY_RUN" -eq 1 ]; then
    log "DRY RUN: would stop $_csv and relaunch"
    exit "$EXIT_DRYRUN"
fi

for _pid in $PIDS; do
    log "stopping client pid=$_pid"
    kill -9 "$_pid" 2>/dev/null
done

sleep 3

# A TUI needs a console, and this watchdog runs from launchd with no terminal.
# Terminal opens a window and runs the client; osascript must exist beforehand.
if ! command -v osascript >/dev/null 2>&1; then
    log "osascript not found; cannot relaunch the client in Terminal"
    exit "$EXIT_CANNOT"
fi

MACHINE="$MACHINE_ARG"
if [ -z "$MACHINE" ]; then
    MACHINE="${HERDR_MACHINE:-}"
fi
if [ -z "$MACHINE" ]; then
    _state="$HOME/Library/Application Support/HerdrSetup"
    _last="$_state/last-machine.txt"
    _labels="$_state/machines.txt"
    if [ -f "$_last" ]; then
        MACHINE="$(grep -v '^[[:space:]]*$' "$_last" 2>/dev/null | tail -n 1 | tr -d '\r')"
        MACHINE="${MACHINE#"${MACHINE%%[! ]*}"}"
        MACHINE="${MACHINE%"${MACHINE##*[! ]}"}"
    elif [ -f "$_labels" ]; then
        MACHINE="$(grep -v '^[[:space:]]*$' "$_labels" 2>/dev/null | tail -n 1 | tr -d '\r')"
        MACHINE="${MACHINE#"${MACHINE%%[! ]*}"}"
        MACHINE="${MACHINE%"${MACHINE##*[! ]}"}"
    fi
fi
case "$MACHINE" in
    *[!A-Za-z0-9._@:-]*) MACHINE="" ;;
esac
if [ -z "$MACHINE" ]; then
    log "no machine label; relaunching without --machine"
fi

_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

_esc="$(_quote "$HERDR")"
if [ -n "$MACHINE" ]; then
    _m_esc="$(_quote "$MACHINE")"
    _launch="exec $_esc --machine $_m_esc"
else
    _launch="exec $_esc"
fi
_launch="$(printf '%s' "$_launch" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"

if ! osascript -e 'tell application "Terminal" to do script "'"$_launch"'"' >/dev/null 2>&1; then
    log "osascript failed to open a Terminal window"
    exit "$EXIT_CANNOT"
fi
if ! osascript -e 'tell application "Terminal" to activate' >/dev/null 2>&1; then
    log "osascript failed to activate Terminal"
    exit "$EXIT_CANNOT"
fi

log "relaunched $HERDR${MACHINE:+ --machine $MACHINE} in Terminal"
exit "$EXIT_RESTARTED"
