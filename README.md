# herdr-port-forwarder

A [Herdr](https://herdr.dev) plugin. When a pane on a saved SSH machine prints a loopback
address such as `http://localhost:5173/`, and a program on that machine accepts connections on
the port, the plugin forwards the port to your computer. Open `http://localhost:5173/` locally to
reach the remote development server. The sidebar shows the forwarded ports on the workspace
that printed them, for example `main · ⇄ 5173 8000→8001`.

Install it only on the computer where you run the Herdr TUI. The remote machines do not need
the plugin; it reaches them over SSH.

## Setup

Requirements on this computer: Herdr 0.9.1 or later, python 3.8 or later, and OpenSSH. Linux or macOS only. Each remote machine needs Herdr and an SSH server that allows TCP forwarding.

```bash
herdr plugin install bhoov/herdr-port-forwarder
herdr plugin action invoke bhoov.port-forwarder.setup
```

`setup` adds the ports to the Workspace sidebar, binds `prefix+shift+f` to the popup in your
Herdr `config.toml`, reloads the config, and starts the plugin. After this, the plugin starts
on its own with the Herdr server.

To update, run both commands again.

## Using it

- **Sidebar.** `⇄ 5173 8000→8001` means that remote port 5173 is at `http://localhost:5173/`
  and remote port 8000 is at `http://localhost:8001/`, because a local program already used
  8000. Workspaces without forwards look as before.
- **Popup.** `prefix+shift+f`, with a Local workspace focused, lists every forward in the sidebar notation, for example
  `localhost:8001 ⇄ workbox:8000`. A yellow local port differs from the remote port. Click a
  row to open it in the browser. Press `q` or Esc to close the popup.
- **Toasts.** A toast shows when a forward opens (`Forwarded :5173 ← workbox`) and when a
  forward or a machine's connection fails.

## Details

### Behavior

- Addresses: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]` and `[::]`. Ports below 1024 are not
  forwarded.
- The local port is the same number when it is free. If a local program already uses it, the
  plugin uses the next free port, up to 20 numbers higher. It remembers the mapping, so a
  restarted plugin gives the port the same local number.
- A forward closes when the remote port stops accepting connections for two scans in a row.
- Every enabled saved machine is scanned while the local Herdr server runs. The machine does not
  have to be selected in the TUI.
- The sidebar row in the setup adds the token at the end of the branch line. A row that is too
  wide is cut at the end, so the ports are cut before the branch. Drag the sidebar edge to widen
  it, or open the popup. Clicking the row selects the workspace; it does not open the browser.
- `prefix+shift+f` is not used by any Herdr default key. A plugin cannot declare its own
  keybinding, so `setup` adds it to your config.
- The popup key works while a Local workspace is focused. Herdr runs a custom key on the server
  of the focused workspace, and the plugin runs only on this computer, so the key does nothing
  while a workspace on a saved machine is focused. The sidebar shows the ports in both cases.

### Sidebar row and key

`setup` appends these to `config.toml`, keeping a copy of the previous file as
`config.toml.bak-port-forwarder`:

```toml
[ui.sidebar.spaces]
rows = [
  ["state_icon", "workspace"],
  ["branch", "git_status", { token = "$ports", fg = "#89b4fa" }],
]

[[keys.command]]
key = "prefix+shift+f"
type = "plugin_action"
command = "bhoov.port-forwarder.show"
description = "forwarded ports"
```

With your own Space layout, add `{ token = "$ports" }` to one of its rows. Then run
`herdr server reload-config`.

### Actions

| Action | Effect |
| --- | --- |
| `bhoov.port-forwarder.setup` | Add the sidebar row and the popup key to the config if they are missing, then restart the daemon. |
| `bhoov.port-forwarder.show` | Open the popup. |
| `bhoov.port-forwarder.restart` | Stop the daemon if it runs, then start it. Use it after changing the config. |
| `bhoov.port-forwarder.stop` | Close all forwards, clear the tokens and stop the daemon. |

### Configuration

Optional. Create `config.json` in the directory that `herdr plugin config-dir bhoov.port-forwarder`
prints, then run the `restart` action:

```json
{
  "scan_interval_seconds": 3,
  "notify": true,
  "machines": ["workbox"]
}
```

- `scan_interval_seconds`: pause between two scans of one machine.
- `notify`: show toasts.
- `machines`: labels or profile ids of the machines to forward from. `null` (the default) means
  every enabled saved machine.

### How it works

For each enabled saved machine, the daemon opens one SSH connection in master mode
(`ssh -M -S <socket>`), with the machine's normal SSH settings. It sets
`ClearAllForwardings=yes`, so `LocalForward` lines in your SSH config do not apply to this
connection. The commands that use the connection run with `-F /dev/null` for the same reason.
Every scan runs over that connection:

1. It runs the remote `herdr workspace list`, `herdr pane list` and, for each pane,
   `herdr pane read --source visible`, and finds loopback addresses in the output. It reads the
   last 200 lines of scrollback (`--source recent-unwrapped`) only the first time it sees a pane,
   because with Herdr 0.9.1 a scrollback read makes the remote panes stutter. After that, an
   address must be on screen during a scan.
2. It probes each announced port with `ssh -W localhost:<port>`. A refused channel means the port
   does not accept connections.
3. It adds forwards with `ssh -O forward -L localhost:<local>:localhost:<remote>` and removes them
   with `ssh -O cancel`. The listeners belong to the master connection and accept connections
   only from this computer.
4. It reports the `$ports` token with `herdr workspace report-metadata --ttl-ms`, so the token
   expires if the plugin stops without clearing it.

State is in the directory that Herdr gives the plugin (`HERDR_PLUGIN_STATE_DIR`): `daemon.log`,
`status.json` (read by the popup) and `registry.json` (remembered local ports). Control sockets
are in `/tmp/hpf-<uid>/`.

### Limits

- The token is part of the remote server's state, so every client attached to that machine sees
  it, including clients on other computers where the port is not forwarded.
- The plugin reads snapshots of pane output. An address that scrolls more than 200 rows between
  two scans is not seen.
- Only one daemon runs for each user on a computer. Forwards last as long as the local Herdr
  server, not as long as a TUI client.
- The SSH connection runs in batch mode. A machine that needs a password or other interactive
  authentication fails with a toast; set up key authentication or an agent for it.

### Local development

```bash
herdr plugin link /path/to/herdr-port-forwarder
herdr plugin action invoke bhoov.port-forwarder.restart
python3 -m unittest discover -s tests
```
