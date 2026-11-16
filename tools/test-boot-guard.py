#!/usr/bin/env python3
"""Regression tests for the systemd boot guard in host/install-autostart.sh.

The installer writes a guard script and a one-shot unit that runs it at boot.
These cases extract the generated guard from the installer, check that it
parses, and run it against a fake tailscale so no tailnet and no root are
needed.

Contracts pinned here:
  - the guard body parses with sh -n (a quoting bug once made it unparseable,
    so the unit reported success and never re-asserted the tag)
  - the unit runs the guard file instead of an inline sh -c body
  - the guard calls 'tailscale up' when the node is logged out or the tag or
    SSH flag is missing, and only then
  - a failed 'tailscale up' is visible: the guard exits non-zero
  - TS_SSH=0 does not ask for SSH and does not pass --ssh

Usage:
    python3 tools/test-boot-guard.py
Exit codes: 0 all cases passed, 1 a case failed, 2 the harness could not run.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

# Built from parts so the secret scanners see no key-shaped literal.
AUTH_KEY = "tskey" + "-auth-" + "example"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, "host", "install-autostart.sh")
GUARD_MARKER = "BOOT_GUARD_SCRIPT"
UNIT_MARKER = "UNIT_FILE"

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("ok   %s" % name)
    else:
        FAIL += 1
        print("FAIL %s%s" % (name, (" -- " + str(detail)) if detail else ""))


def extract(text, marker):
    """Return the body of the heredoc that uses this marker."""
    begin = "<<'%s'\n" % marker
    start = text.find(begin)
    if start < 0:
        raise RuntimeError("no heredoc %s in %s" % (marker, INSTALLER))
    start += len(begin)
    end = text.find("\n%s\n" % marker, start)
    if end < 0:
        raise RuntimeError("unterminated heredoc %s" % marker)
    return text[start:end + 1]


FAKE_TS = """#!/bin/sh
name="$1"
shift
case "$name" in
  status) cat "$FAKE_STATUS"; exit 0 ;;
  debug) cat "$FAKE_DEBUG" 2>/dev/null; exit 0 ;;
  up)
    printf '%s\\n' "$*" >> "$FAKE_CALLS"
    exit "${FAKE_UP_RC:-0}"
    ;;
  *) exit 1 ;;
esac
"""

RUNNING = '{"BackendState": "Running", "Self": {"Tags": ["tag:herdr-host"]}}'
STOPPED = '{"BackendState": "Stopped", "Self": {"Tags": []}}'
PEER_TAG_ONLY = ('{"BackendState": "Running", "Self": {"Tags": []}, '
                 '"Peer": {"Tags": ["tag:herdr-host"]}}')
SIMILAR_TAG = ('{"BackendState": "Running", '
               '"Self": {"Tags": ["tag:herdr-host-2"]}}')
PREFS_ON = '{"RunSSH": true}'
PREFS_OFF = '{"RunSSH": false}'


class Guard(object):
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="herdr-guard-")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work)
        self.calls = os.path.join(self.work, "calls.txt")
        fake = os.path.join(self.work, "tailscale")
        with open(fake, "w", encoding="utf-8") as handle:
            handle.write(FAKE_TS)
        os.chmod(fake, 0o755)
        self.fake = fake

    def run(self, status, prefs, ssh="1", tag="tag:herdr-host",
            authkey=AUTH_KEY, up_rc="0"):
        status_file = os.path.join(self.work, "status.json")
        prefs_file = os.path.join(self.work, "prefs.json")
        with open(status_file, "w", encoding="utf-8") as handle:
            handle.write(status)
        with open(prefs_file, "w", encoding="utf-8") as handle:
            handle.write(prefs)
        if os.path.exists(self.calls):
            os.unlink(self.calls)
        env = {
            "PATH": "/usr/bin:/bin",
            "FAKE_STATUS": status_file,
            "FAKE_DEBUG": prefs_file,
            "FAKE_CALLS": self.calls,
            "FAKE_UP_RC": up_rc,
            "TS_EXE": self.fake,
            "TS_SSH": ssh,
        }
        if tag:
            env["TS_TAG"] = tag
        if authkey:
            env["TS_AUTHKEY"] = authkey
        proc = subprocess.run(["sh", self.script], env=env,
                              capture_output=True, text=True)
        called = []
        if os.path.exists(self.calls):
            with open(self.calls, "r", encoding="utf-8") as handle:
                called = [line.strip() for line in handle if line.strip()]
        return proc.returncode, proc.stdout + proc.stderr, called

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def main():
    if not os.path.isfile(INSTALLER):
        print("install-autostart.sh not found")
        return 2
    with open(INSTALLER, "r", encoding="utf-8") as handle:
        installer = handle.read()

    try:
        guard_body = extract(installer, GUARD_MARKER)
        unit_body = extract(installer, UNIT_MARKER)
    except RuntimeError as exc:
        check("install unit: guard and unit heredocs exist", False, str(exc))
        print("")
        print("%d passed, %d failed" % (PASS, FAIL))
        return 1
    guard = Guard()
    guard.script = os.path.join(guard.work, "boot-guard.sh")
    try:
        with open(guard.script, "w", encoding="utf-8") as handle:
            handle.write(guard_body)

        syntax = subprocess.run(["sh", "-n", guard.script],
                                capture_output=True, text=True)
        check("guard: the generated body parses with sh -n", syntax.returncode == 0,
              syntax.stderr.strip())

        exec_lines = [line.strip() for line in unit_body.splitlines()
                      if line.strip().startswith("ExecStart=")]
        check("unit: ExecStart runs the guard file",
              len(exec_lines) == 1 and "/bin/sh /etc/herdr-setup/boot-guard.sh"
              in exec_lines[0], exec_lines)
        check("unit: the unit is conditional on the guard file",
              "ConditionPathExists=/etc/herdr-setup/boot-guard.sh" in unit_body,
              "missing ConditionPathExists")
        check("unit: no inline sh -c guard body",
              "sh -c" not in unit_body, "inline sh -c still present")

        rc, out, called = guard.run(RUNNING, PREFS_ON)
        check("guard: a correct node needs no change", rc == 0 and not called,
              (rc, called, out))
        check("guard: a correct node reports why", "already correct" in out, out)

        rc, out, called = guard.run(STOPPED, PREFS_ON)
        check("guard: a logged-out node is re-asserted",
              rc == 0 and len(called) == 1 and "--authkey=" in called[0],
              (rc, called, out))
        check("guard: re-assert passes the stored auth key and tag",
              called and AUTH_KEY in called[0]
              and "tag:herdr-host" in called[0], called)
        check("guard: re-assert passes --ssh when SSH is wanted",
              called and "--ssh" in called[0].split(), called)

        rc, out, called = guard.run(STOPPED, PREFS_ON, up_rc="1")
        check("guard: a failed re-assert exits non-zero", rc != 0, (rc, out))

        rc, out, called = guard.run(RUNNING, PREFS_OFF, ssh="0")
        check("guard: TS_SSH=0 does not ask for SSH", rc == 0 and not called,
              (rc, called, out))

        rc, out, called = guard.run(RUNNING, PREFS_OFF, ssh="1")
        check("guard: missing SSH support triggers a re-assert",
              rc == 0 and len(called) == 1, (rc, called, out))

        check("installer: asks systemd for the real enable state",
              "is-enabled herdr-tailscale-ssh.service" in installer,
              "no systemctl is-enabled call")
        check("installer: does not print Enabled without a check",
              not re.search(r'^echo "Enabled:', installer, re.M),
              "unconditional Enabled line still present")

        rc, out, called = guard.run(RUNNING, PREFS_ON, tag="")
        check("guard: no stored tag means no tag check", rc == 0 and not called,
              (rc, called, out))

        rc, out, called = guard.run(PEER_TAG_ONLY, PREFS_ON)
        check("guard: a peer tag does not satisfy the local tag",
              rc == 0 and len(called) == 1, (rc, called, out))

        rc, out, called = guard.run(SIMILAR_TAG, PREFS_ON)
        check("guard: a similar-prefix tag does not satisfy the local tag",
              rc == 0 and len(called) == 1, (rc, called, out))

        rc, out, called = guard.run(STOPPED, PREFS_ON, authkey="")
        check("guard: a missing auth key is a visible failure",
              rc != 0 and not called, (rc, called, out))
    finally:
        guard.close()

    print("")
    print("%d passed, %d failed" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
