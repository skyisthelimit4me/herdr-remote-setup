# Using Herdr Remote Setup

This guide is the complete operator instruction for version 4.0.3. It covers
the simple PIN flow, the optional guest join code, the checks, and the cleanup.

Read `README.md` section 0 for the short version, and `docs/ARCHITECTURE.md` for
how the pieces fit.

---

## 1. What you need

| Role | Operating system | Notes |
|---|---|---|
| Host | Linux or macOS | Shares its herdr with the client |
| Client | Windows 10 or 11 | The app and the PIN client ship for Windows |
| Client, advanced | Linux, macOS, Windows | The connection-code flow, not the PIN |

Both machines need a Tailscale account, unless the host prints a guest join
code. Then the guest needs no Tailscale account of its own, only the code.

Software the host needs. `host/pair.sh` installs herdr when it is missing, and
starts sshd when it can.

- `python3`
- OpenSSH server
- `tailscale`
- `herdr`

The client app installs Tailscale and herdr when it can, through `winget` or the
vendor installer.

---

## 2. Put the package on the host

Unzip the release on the host, for example under `~/herdr-remote-setup`.

```bash
cd ~/herdr-remote-setup
cat VERSION
bash host/setup.sh --version
```

`host/setup.sh` is the full host preparation. `host/pair.sh` is the share flow
you run for each guest. The desktop package adds clickable entries:

```bash
bash host/install-desktop.sh
```

That writes `herdr-remote-setup.desktop`, `herdr-share.desktop`, and
`herdr-new-client-code.desktop` to the applications menu, plus two Desktop
shortcuts. It needs no zenity.

---

## 3. One-time host preparation

### 3.1 Join the tailnet and tag the host

```bash
sudo tailscale up --advertise-tags=tag:herdr-host
tailscale status --json | grep tag:herdr-host
```

The tag matters. `tag:client` grants target `tag:herdr-host`, so an untagged
host matches no guest rule. The share flow warns when the tag is missing.

### 3.2 Allow SSH

```bash
sudo systemctl enable --now sshd     # Debian, Ubuntu, Fedora
sudo systemsetup -setremotelogin on  # macOS
```

The host flow checks this and starts sshd when it can.

### 3.3 Optional, for guest join codes

A guest join code removes all per-guest admin-console work. It needs one
Tailscale API token, created once, stored once.

1. Create the token at https://login.tailscale.com/admin/settings/keys under
   **API access tokens**. You must be an Owner, Admin, IT admin, or Network
   admin. Name it `herdr-guest-keys-and-acl`, and pick the shortest expiry that
   covers the engagement, from 1 to 90 days.
2. Store it root-only on the host. The `cat` form keeps it out of shell history.

   ```bash
   sudo mkdir -p /etc/herdr-setup
   sudo sh -c 'umask 077; cat > /etc/herdr-setup/tailscale-api.key'
   # paste the token, press Enter, then Ctrl-D
   sudo chown root:root /etc/herdr-setup/tailscale-api.key
   sudo chmod 600 /etc/herdr-setup/tailscale-api.key
   ```

   The scripts refuse a token file that group or others can read, or that root
   does not own. A refusal is exit 2, and the PIN flow continues.

3. Check the policy without changing it.

   ```bash
   sudo bash host/ensure-acl.sh --no-acl-write
   ```

   Exit 0 and `ACL already allows tag:client` means ready. Exit 3 prints the
   JSON snippet to add and names the reason.

A full access token can create devices and rewrite the whole policy. Treat it as
a trust anchor. Use a dedicated token, and revoke it when the work ends. Without
the token the flow is PIN-only, which still needs the guest on your tailnet.

Details are in `SECURITY.md` and `docs/TROUBLESHOOTING.md`.

---

## 4. Share the host, for each guest

Double-click **Herdr: Share This Computer**, or run:

```bash
bash host/pair.sh
```

The window shows four things:

```text
Herdr Share v4.0.3
  Computer : <host name>
  User     : <login user>
  Address  : 100.x.y.z:8765
  herdr    : herdr 0.9.5

Guest join code: <one-time key>     (only when the token is stored)

  PIN      : 123456
```

Read the join code, if there is one, the address, and the PIN to the guest. Keep
the window open until the guest connects. The PIN rotates after each success
and expires after 30 minutes by default.

### Flags

| Flag | Effect |
|---|---|
| `--ttl 900` | PIN lifetime in seconds. Default 1800 |
| `--pin 123456` | Fix the PIN, for a test |
| `--once` | Stop after one successful pairing |
| `--port 8765` | Pairing port. Default 8765 |
| `--bind 100.x.y.z` | Bind address. Default is the Tailscale IPv4 |
| `--no-join-code` | PIN only, no API call, no join code |
| `--no-acl-write` | Check the policy, never write it |

`--port` also updates the ACL grant, so a custom port works end to end. Run
`sudo bash host/ensure-acl.sh --port N` to check that grant on its own; add
`--no-acl-write` to leave the policy alone.

The join code is a secret. Do not paste it into a ticket or a chat. It works
once, expires after one hour, and the host prints it to the terminal only.

---

## 5. Connect from Windows

### 5.1 With the app

1. Unzip the package on the Windows machine and double-click
   `app\Herdr-Setup.cmd`.
2. Click **Connect to a computer**.
3. Pick the host from the list, or type its address.
4. If the host printed a join code, paste it into **Join code**. The app warns
   that this joins the host's tailnet as a tagged guest device.
5. Type the 6-digit PIN.
6. Click **Connect**, then **Open herdr**.

The app installs Tailscale and herdr when they are missing, joins the tailnet,
sends the SSH public key with the PIN, tests SSH, runs `herdr machine add`, and
installs the watchdog. Leave **Join code** empty to sign in to Tailscale
yourself.

### 5.2 From the command line

```powershell
cd client
powershell -ExecutionPolicy Bypass -File .\pair.ps1 -HostName 100.x.y.z -Pin 123456
```

Add `-JoinCode <code>` for the guest flow, `-Json` for machine-readable output,
`-NoWatchdog` to skip the watchdog, and `-Label <name>` to name the herdr
machine.

| Exit code | Meaning |
|---|---|
| 0 | Connected |
| 2 | Prerequisite or PIN problem |
| 3 | Network or tailnet problem |
| 4 | SSH transport problem |
| 5 | herdr problem |
| 6 | Internal error |

---

## 6. Connect from macOS or Linux

The PIN app is Windows-only in 4.0.3. On macOS use the Advanced connection-code
flow. README sections 1 to 6 describe it, and `docs/SETUP-A-AND-B.md` is the
two-machine runbook.

---

## 7. What pairing changes on each machine

Host:

- `~/.ssh/authorized_keys` gets the client public key, one line per client.
- `~/.local/state/herdr-setup/pair.pin`, `pair.port`, and `pair.log` hold the
  current PIN, port, and log. No key or join code is written there.
- With the API token, `/etc/herdr-setup/acl-backup-<timestamp>.hujson` holds the
  policy as it was before a write.

Client:

- Tailscale joins the host tailnet, as `tag:client` when a join code is used.
- `~/.ssh/id_ed25519` is created when no key exists.
- `herdr machine add <user@ip>` registers the host.
- `install-watchdog.ps1` registers the `HerdrWatchdog` task and the
  `HerdrWatchdogLaunch` task. The watchdog restarts a stalled herdr client every
  two minutes, hidden, and leaves the servers alone.
- Logs go to `%LOCALAPPDATA%\HerdrSetup\logs`.

---

## 8. Checks

Run these on the host from the package root.

```bash
bash host/ensure-acl.sh --self-test
bash host/guest-key.sh --self-test
bash tools/test-ts-api.sh
```

Run these on any machine with PowerShell.

```powershell
powershell -File tools\verify-package.ps1
powershell -File client\pair.ps1 -SelfTest
powershell -File app\herdr-connect.ps1 -SelfTest
```

`verify-package.ps1` prints `VERIFY OK (n files)` when every file matches
`MANIFEST.sha256` and no code file holds a key-shaped literal.

---

## 9. End a guest session

Host:

```bash
# see which keys are present
wc -l ~/.ssh/authorized_keys
# remove one line by hand, or ask the client to send its key again
```

Client:

```powershell
herdr machine remove <label>
```

Tailnet, when a join code was used:

1. Open https://login.tailscale.com/admin/machines
2. Find the guest device, tagged `tag:client`.
3. Remove it.

Then revoke the API token at https://login.tailscale.com/admin/settings/keys
when no more guests are expected.

---

## 10. Uninstall

Host:

```bash
bash host/install-desktop.sh --uninstall
rm -rf ~/.local/state/herdr-setup   # PIN state and log
sudo rm -f /etc/herdr-setup/tailscale-api.key
sudo rm -f /etc/herdr-setup/acl-backup-*.hujson
```

Do not delete `~/.ssh/authorized_keys` unless you know every line in it.

Client:

```powershell
powershell -File client\install-watchdog.ps1 -Uninstall
```

Then remove the herdr machine entry with `herdr machine remove <label>`.

---

## 11. Security rules

- A join code and a PIN are both secrets. Read them out, do not paste them into
  a chat or a ticket.
- The host never prints the API token, and no script writes it to a log.
- The host adds ACL entries and never removes another rule. It backs the policy
  up first.
- A guest with a join code is a device in the owner's tailnet. The ACL limits it
  to the herdr host on tcp:22 and tcp:8765, but it can list peers. If that is too
  much, use device sharing with the guest's own Tailscale account.
- Never commit a key, a token, a PIN, or a connection code to this repository.
  `tools/check-public.py` and `tools/verify-package.ps1` enforce that before a
  release.

---

## 12. Where to look when something fails

| Symptom | First check |
|---|---|
| The client finds no host | Is the share window open? Does `tailscale status` show the host? |
| Wrong PIN | Restart `host/pair.sh` for a new PIN |
| No join code on the host | `sudo bash host/ensure-acl.sh --no-acl-write`, see the reason in the window |
| Join code refused | It is single use and expires in one hour. Get a new one |
| The client is already on a tailnet | Log out on that machine first, only with consent |
| SSH fails after the PIN | Check sshd and `~/.ssh/authorized_keys` on the host |
| herdr cannot connect | `herdr machine status <label>` on the client |
| The client window reopens by itself | That is the watchdog. `HERDR_...` logs are under `%LOCALAPPDATA%\HerdrSetup\logs` |

`docs/TROUBLESHOOTING.md` has the full matrix, including the herdr surface
revocation stall and the Tailscale SSH conflicts.
