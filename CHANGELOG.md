# Changelog

## 4.0.3 - 2026-11-16

Fix pairing races and watchdog false positives.

### Fixed

- `host/pair.py`: one lock now covers the PIN check, the key append, and the
  PIN rotation. Two concurrent requests cannot add two keys with one PIN.
- `host/pair.py`: reject a PIN that is not six ASCII digits before the
  constant-time compare. A non-ASCII PIN now returns 401 instead of closing
  the connection.
- `host/pair.py`: each request has a 10-second socket timeout.
- `host/ensure-acl.sh`: a legacy `acls` rule must name `tag:herdr-host` in
  `dst`. A rule that names another tag or a wildcard no longer counts as ready.
  The script refuses to write while such a rule remains.
- `host/ensure-acl.sh`: the trailing-comma cleanup keeps commas inside string
  values.
- `host/ensure-acl.sh`: the pairing port is part of the ACL grant. A custom
  `--port` now works end to end.
- `host/ensure-acl.sh` and `host/guest-key.sh`: refuse an API token file that
  is readable by group or others, or that root does not own.
- `client/watchdog.ps1` and `client/watchdog-macos.sh`: an `unknown` log state
  is healthy. The watchdog restarts only on `stuck` or `fail`.
- `client/watchdog.ps1` and `client/watchdog-macos.sh`: match only the TUI
  command, `herdr` or `herdr --machine`. They no longer stop `herdr status`,
  `herdr-core`, the SSH helper, or an unrelated job.
- `host/enroll.py` and `host/pair.py`: serve concurrently with a backlog of 128.
  A burst of twenty parallel attempts used to overflow the default queue of 5,
  and the refused connections looked like an empty reply.
- `host/pair.py`: `--once` keeps the listener open for half a second after the
  successful reply, so a request that arrived in the same burst still gets its
  401 instead of a connection reset.
- `host/ensure-acl.sh` and `host/guest-key.sh`: the token ownership check is
  skipped where the platform has no user id, so the suite runs on Windows. The
  POSIX-only mode cases report `skip` there.

### Added

- `tools/test-pair.py`: localhost tests for the PIN protocol, the non-ASCII
  PIN, malformed JSON, duplicate keys, repeated one-winner races, and the rate
  limit.
- Self-tests for the watchdog state gate and the Windows and macOS client
  matchers.

### Changed

- README, ARCHITECTURE, and TROUBLESHOOTING describe the watchdog state gate,
  the TUI-only macOS match, and the ACL token requirement.

## 4.0.2 - 2026-11-16

Host-generated guest join codes and ACL automation.

### Added

- `host/guest-key.sh`: creates a one-time Tailscale auth key for a guest with
  `POST /api/v2/tailnet/-/keys`. The key joins as `tag:client`, is single use,
  is not ephemeral, is preauthorized, and expires after one hour. The script
  reads the API token from `/etc/herdr-setup/tailscale-api.key`, prints only the
  key, and never prints the token.
- `host/ensure-acl.sh`: reads the tailnet policy, adds only the missing
  `tagOwners.tag:client` entry and the `tag:client` to `tag:herdr-host` grant on
  tcp:22 and tcp:8765, writes it back, and verifies the result. It backs up the
  policy under `/etc/herdr-setup` before a write, refuses an unparsable or
  unexpected policy, and supports `--no-acl-write` for a check-only run.
- `host/pair.sh` now checks the policy and prints a `Guest join code` when a
  token is stored. A missing or rejected token falls back to PIN-only with a
  warning. New flags: `--no-join-code`, `--no-acl-write`.
- `client/pair.ps1 -JoinCode` joins the host's tailnet with the code before the
  PIN step, and redacts key-shaped strings from its log. It refuses a code with
  the wrong prefix and reports when the machine is already on a tailnet.
- `app/herdr-connect.ps1` has an optional **Join code** field above the PIN and
  shows a warning when it is filled.
- `tools/mock-ts-api.py` and `tools/test-ts-api.sh`: offline tests for both host
  scripts against a mock API, including the ready, missing, unparsable, refused,
  and verify-only paths.
- `docs/USAGE.md`: the complete operator guide. Requirements, one-time host
  preparation, the API token, sharing, both client paths, checks, guest cleanup,
  uninstall, and the failure table.

### Fixed

- Tailscale 1.104 rejects `tailscale ip -4`. `host/pair.sh` and `host/setup.sh`
  now try `--4`, then the bare `ip` list filtered to `100.`, then `-4`.

### Changed

- `docs/acl-policy.hujson` names tcp:8765 in the tagged-client grant, so a guest
  can reach the pairing service as well as SSH.
- README, QUICKSTART, SETUP-A-AND-B, ARCHITECTURE, TROUBLESHOOTING, and
  SECURITY describe the join code, the ACL automation, and the API token.

## 4.0.1 - 2026-11-16

Fix the host desktop entries.

### Fixed

- `host/install-desktop.sh` wrote a menu entry whose `Exec` pointed at
  `setup-gui.sh`, which needs zenity. On a host without zenity the icon did
  nothing. The entry now starts `app/launch-app.sh`, the Share / Connect /
  Advanced menu.
- The installer now writes `herdr-remote-setup.desktop`,
  `herdr-share.desktop` (direct 6-digit PIN), and
  `herdr-new-client-code.desktop` (Advanced), and removes the old duplicate
  `herdr-setup-app.desktop`.
- It now creates two Desktop shortcuts, **Herdr Remote Setup** and
  **Herdr: Share This Computer**, and sets the GNOME trusted flag on both.
- CI and `CONTRIBUTING.md` validate the new entry names, and CI fails if the
  old duplicate is installed again.
- `MANIFEST.sha256` no longer lists `host/__pycache__/*.pyc`. The file is
  gitignored, so a fresh clone failed `verify-package.ps1` with `MISSING`.
  `tools/make-manifest.ps1` now skips `*.pyc` and `__pycache__`.

## 4.0.0 - 2026-11-16

Simple PIN pairing for non-IT users.

### Added

- `host/pair.py`: a pairing service on the host Tailscale address. It shows a
  6-digit PIN, accepts the client SSH public key plus the PIN, appends the key,
  and limits wrong PIN attempts. It never logs a PIN or a key.
- `host/pair.sh`: one-command host share flow. It checks Tailscale, sshd, and
  herdr, starts the herdr server detached, and runs the pairing service.
- `host/launch-pair.sh`: clickable host launcher for the share flow.
- `client/pair.ps1`: Windows client for the PIN flow. It signs in to Tailscale
  interactively, finds the host, sends its key and PIN, tests SSH, registers the
  machine in herdr, and installs the watchdog.
- `app/herdr-connect.ps1` and `app/Herdr-Connect.cmd`: the simple Windows app.
  Two actions, Connect to a computer and Share this computer. Connect scans the
  tailnet, lists sharing computers, takes the PIN, streams the setup output, and
  offers Open herdr.
- `app/herdr-setup.sh`: a simple Linux and macOS menu for Share, Connect, and
  Advanced. The previous role/OS app is now `app/herdr-setup-advanced.sh` and is
  reachable from Advanced.
- `Herdr-Setup.cmd` now starts the simple app. The old role/OS app remains under
  Advanced setup.
- `host/Herdr-Provision.desktop` and `host/Herdr-Provision.command` now start
  the share flow. The connection-code flow is still available from
  `host/provision.sh`.

### Changed

- The primary user path needs no connection code, no Tailscale auth key, and no
  IP address. The host reads a 6-digit PIN to the client.
- Tailscale login is interactive. The client opens the browser login when the
  host is not visible.
- `VERSION` is 4.0.0.

### Verified

- Linux host share produced a PIN and bound `100.x.y.z:18765` for the
  test.
- Wrong PIN returned HTTP 401. A correct PIN returned HTTP 200 and appended the
  key.
- A Windows client paired with a temporary key, connected over SSH, added a test
  machine entry, and `herdr machine status` reported `reachable`.
- The host pairing service exited after `--once`; the test key and test machine
  entry were removed.
- The Windows app constructed and its self-tests pass.
- The shell dispatcher self-test and the Advanced flow still pass.

### Limits

- The Windows host role is not shipped. Share runs on Linux and macOS.
- The PIN client is Windows-only in 4.0.0. The macOS client uses the Advanced
  connection-code flow. A macOS PIN client is a follow-up.
- The pairing service uses fixed port 8765 and plain HTTP on the tailnet. The
  tailnet (WireGuard) encrypts the traffic, and the PIN gates the key exchange.
- The PIN is a secret. Do not share it outside the two machines.

---

## 3.1.3 - 2026-11-15

Hide the Windows watchdog console window.

### Added

- `client/watchdog-hidden.vbs`: starts `watchdog.ps1 -Quiet` through
  `wscript.exe` with a hidden window.

### Changed

- `client/install-watchdog.ps1` registers the `HerdrWatchdog` task with
  `wscript.exe "<path>\watchdog-hidden.vbs"` instead of a visible PowerShell
  process. The two-minute check no longer flashes a console window.
- `VERSION` is 3.1.3.

### Verified

- `cscript //nologo client\watchdog-hidden.vbs` exits 0 and appends a line to
  `watchdog.log`.
- The installed task action is
  `C:\WINDOWS\System32\wscript.exe "…\client\watchdog-hidden.vbs"`.
- `Start-ScheduledTask -TaskName HerdrWatchdog` appends a watchdog log line.

---

## 3.1.2 - 2026-11-15

Add the two-machine runbook.

### Added

- `docs/SETUP-A-AND-B.md`: end-to-end instructions for Host A and Machine B,
  including the supported pairs, auth key rules, launchers, verification,
  troubleshooting, and security rules.

### Changed

- README and QUICKSTART link the new page.
- `VERSION` is 3.1.2.

---

## 3.1.1 - 2026-11-15

Restore the portable double-click launchers.

### Added

- `host/Herdr-Provision.desktop` and `app/Herdr-Setup.desktop`. Each file uses
  the `%k` field code to resolve its own folder, so the repository stores no
  absolute path. Both pass `desktop-file-validate`, and the resolved path works
  when it contains a space.
- `install-desktop.sh` remains the option for absolute menu entries and a
  Desktop shortcut.

### Changed

- `VERSION` is 3.1.1.
- README, QUICKSTART, ARCHITECTURE, and TROUBLESHOOTING describe the portable
  launchers.

---

## 3.1.0 - 2026-11-15

Public repository release. The product behavior is unchanged.

### Added

- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `.gitattributes`,
  `.editorconfig`, and issue and pull request templates.
- `.github/workflows/ci.yml` runs the public scan and self-tests on Ubuntu,
  Windows, and macOS.
- `tools/check-public.py` fails on key material, private key headers, internal
  hostnames, author home paths, and the private orchestration bundle name.
- `host/install-desktop.sh` now installs a Desktop shortcut, sets the GNOME
  trusted flag when `gio` exists, and supports `--uninstall`.

### Changed

- Public tree no longer carries the private orchestration bundle, the legacy
  prototypes, the internal handoff, or old release archives. They live outside
  this repository.
- `docs/acl-policy.hujson` is a generic template. The tailnet device inventory
  and customer hostnames are removed.
- `docs/ACCESS-MODEL.md` is rewritten in English and corrected. It no longer
  recommends Tailscale SSH for herdr clients.
- The prebuilt `.desktop` files are removed. `install-desktop.sh` generates
  absolute `Exec` paths at install time, so no author path is stored.
- Example users, hosts, and paths in the docs are generic. No real account,
  hostname, IP address, or public key remains.
- `VERSION` is 3.1.0.

### Fixed

- The ACL example no longer contradicts the key-mode decision.

### Notes

- This release is repository hygiene only. The Linux host and Windows client
  flows were re-tested; the macOS paths remain unverified because no Mac was
  reachable.

---

## 3.0.0 - 2026-11-14

macOS support for both roles, and one thin app to pick Role and OS.

### Added

- macOS host support in `host/setup.sh`: Darwin preflight, Tailscale app-bundle
  and Homebrew discovery, `brew install --cask tailscale`, Remote Login check
  through `systemsetup` and `launchctl`, a group-writable `$HOME` fix that sshd
  requires, herdr discovery in `~/.local/bin` and Homebrew paths, and
  `ifconfig` address discovery.
- `start_detached` helper. It uses `setsid -f` where available and
  `python3 subprocess.Popen(start_new_session=True)` on macOS, which has no
  `setsid`. Both the herdr server and `enroll.py` use it.
- `host/Herdr-Provision.command`: double-clickable macOS launcher for the host
  flow. It keeps the Terminal window open so the code stays readable.
- `client/setup-macos.sh`: macOS client. Same eight steps as the Windows
  client: decode v1/v2 code, Tailscale, herdr, SSH key, enrollment, machine
  registration, reachability check, watchdog. Bash 3.2 safe.
- `client/watchdog-macos.sh`: same stall detection as the Windows watchdog,
  restart through `osascript` and Terminal, exit codes 0/2/10/11.
- `client/install-watchdog-macos.sh`: watchdog as a LaunchAgent
  `dev.herdr.watchdog`, with `launchctl bootstrap` and `plutil -lint`.
- `app/herdr-setup.ps1` and `app/Herdr-Setup.cmd`: Windows front end. WinForms,
  PowerShell 5.1, no third-party runtime.
- `app/herdr-setup.sh`, `app/Herdr-Setup.command`, `app/launch-app.sh`, and
  `app/Herdr-Setup.desktop`: Linux and macOS front end. One shell menu.
- One support matrix per front end: Host+Linux, Host+macOS, Client+Windows,
  Client+macOS run; Host+Windows and Client+Linux are not shipped and show
  guidance instead.
- `--self-test`, `--dry-run`, and headless `-NoGui` paths so the app can be
  verified without a second machine.
- `tools/verify-package.ps1` fails on secret-shaped `tskey-auth-...` literals
  in shipped code files.

### Changed

- `VERSION` is 3.0.0.
- `install-desktop.sh` also installs **Herdr Remote Setup (App)**.
- `host/Herdr-Provision.desktop` Exec points at the v3.0.0 mirror path.
- `host/provision.sh` no longer requires the execute bit on `setup.sh`, and
  calls it through `bash`. A zip or scp copy may not keep file modes.
- README, QUICKSTART, ARCHITECTURE, TROUBLESHOOTING and HANDOFF describe macOS
  and the app.

### Fixed

- The client self-test fixture contained a `tskey-auth-...` shaped literal. It
  is now `example-auth-key`, and the new secret scan keeps it out.
- `KEY_COUNT` printed a second `0` line on an empty `authorized_keys`.
- The macOS client accepts an enrollment response only when the body says
  `"ok": true`, not on the HTTP status alone.
- The macOS client leaves an existing machine entry alone when it cannot parse
  the entry id, instead of removing and re-adding it, which triggers #3842.

### Notes

- macOS host and client paths are implemented but **not runtime verified**. No
  macOS machine was reachable for the release test. The macOS scripts pass
  `bash -n`, the LaunchAgent plist parses, and the detached-start mechanism was
  proven on Linux, but no real Mac ran them.
- The app runtime choice is evidence based. The Linux host has python3 but no
  `tkinter` and no `DISPLAY`, so Tkinter cannot run there. Windows PowerShell
  5.1 with WinForms needs no install. macOS Command Line Tools `python3` does
  not ship tkinter reliably. See `docs/ARCHITECTURE.md`.

---

## 2.1.0 - 2026-11-14

One-command provisioning, automatic enrollment, automatic watchdog.

### Added

- `host/provision.sh`: single entry point. Resolves the Tailscale auth key from
  `--authkey`, `$HERDR_TS_AUTHKEY`, `/etc/herdr-setup/authkey`, or a prompt, then
  runs `setup.sh --mode key --enroll` and prints the code.
- `host/provision-gui.sh`: one-dialog version for desktop users.
- `--save-key` stores the auth key at `/etc/herdr-setup/authkey` (root 600).
- `host/enroll.py` and `host/enroll.sh`: one-time SSH key enrollment endpoint.
  The token is embedded in the connection code as `enroll=<port>:<token>`.
- Client posts its public key to the enrollment endpoint when key auth fails,
  then retries SSH.
- `client/watchdog.ps1`: detects the stalled-client state and restarts only the
  client. Relaunch uses an interactive scheduled task, because a TUI needs a
  console.
- `client/install-watchdog.ps1`: installs or removes the watchdog task.
- Client installs the watchdog by default (`-NoWatchdog` to skip).
- `install-desktop.sh` adds a second menu entry, **Herdr: New Client Code**.
- `host/Herdr-Provision.desktop` + `host/launch-provision.sh`: double-clickable
  launcher that opens a terminal and runs the flow without any command. Works
  without zenity.
- `docs/QUICKSTART.md`: one-page end-to-end flow with expected output.
- TROUBLESHOOTING section for the three observed stall causes.

### Changed

- Product flow is now: host `./provision.sh` -> client double-click -> paste
  code -> done. No separate enrollment or watchdog commands.
- **Default transport is now `key`.** `ts-ssh` is documented as incompatible
  with herdr's remote bridge: the bridge is wrapped by
  `tailscaled be-child ssh --force-v1-behavior`, which breaks surface
  activation and revocation.
- `host/setup.sh --mode key` warns when Tailscale SSH is still enabled.
- README, ARCHITECTURE, ACCESS-MODEL updated.

### Fixed

- Enrollment listener failed silently on a busy port; it now binds port 0 and
  reports the real port through a port file.
- `enroll.txt` had shifted fields (port/token/ttl).
- Remote server started with `nohup` reports `detached_server_daemon: false`
  and blocks saved machines. Use `setsid -f herdr server`.

### Notes

- Observed upstream issue: herdrdev/herdr#3842 (surface revocation timeout,
  single-shot re-activation).
- Preview channel test pending.

---

## 2.0.0 - 2026-11-14

Tailscale SSH transport, dual-mode product.

### Added

- `--mode ts-ssh|key|auto` on the host; the client honours the mode in the code.
- Tailscale SSH support: no SSH key exchange, authorization from the tailnet ACL.
- `host/install-autostart.sh`: systemd unit that re-asserts Tailscale identity,
  tag, and `--ssh` after a reboot or re-registration.
- Connection code **v2** (`v=2;mode=...;dns=...`), with automatic v1 fallback.
- `docs/ACCESS-MODEL.md`: operator / client / herdr-host roles, tagging rules,
  customer onboarding and revocation, ACL matrix.
- `docs/acl-policy.hujson`: paste-ready tailnet policy.
- Client self-test now covers both v1 and v2 parsing.
- Client prefers the MagicDNS name over a pinned 100.x address.

### Changed

- Host reports `dns`, `tag`, and `mode` in human and `--json` output.
- Client reports the chosen mode in results and logs.
- ACL guidance added to the README (`action: accept` required for unattended).
- `VERSION` bumped to 2.0.0.

### Notes

- Reboot does not change the node. Losing `/var/lib/tailscale` does.
- `ts-ssh` fails if a re-registered node loses its tag; the autostart unit
  prevents that.

### Fixed

- `SSH_HostKeys` is absent from `tailscale status --json` on 1.104.x; both the
  host script and the autostart unit now read `RunSSH` from `tailscale debug prefs`.
- Client verification used `herdr --machine <name> status`, which is not a
  valid command; it now uses `herdr machine status <name>`.
- Client removed and re-created machine entries by label; it now matches by
  target and keeps the user-chosen label.

---

## 1.0.0 - 2026-11-14

Productization release.

### Added

- Network layer: the client installs Tailscale and joins the tailnet with a
  one-time auth key embedded in the connection code.
- `client/assets/herdr-windows-x86_64.zip` offline package.
- `-ShowVersion`, `-SelfTest`, `--json`, `--quiet`, `--version`.
- Structured exit codes (0, 2, 3, 4, 5, 6).
- Log files with `tskey-...` redaction.
- `tools/verify-package.ps1`, `make-manifest.ps1`, `uninstall.ps1`.
- `MANIFEST.sha256`.
- Generated desktop entry (`install-desktop.sh`), spec-compliant.

### Fixed

- `ssh-keygen` failed when `%USERPROFILE%\.ssh` was missing.
- PowerShell 5.1 incompatibilities (`&&`, stderr-as-error, TLS 1.2).
- herdr install failed when GitHub was unreachable.
- Hardcoded user paths in launchers.
- Console mojibake from Unicode box characters in `.bat`.

### Previous versions

- 0.9.x prototype scripts (`herdr-setup-machine-a.sh`,
  `herdr-setup-machine-b.bat`, `herdr-remote-setup-b.ps1`).
