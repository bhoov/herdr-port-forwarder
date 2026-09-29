# herdr-port-forwarder

A [Herdr](https://herdr.dev) plugin. When a pane on a saved SSH machine prints a loopback
address such as `http://localhost:5173/`, and a program on that machine accepts connections on
the port, the plugin forwards the port to your computer. Open `http://localhost:5173/` locally to
reach the remote development server.

- Addresses: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]` and `[::]`. Ports below 1024 are not
  forwarded.
- The local port is the same number when it is free. If a local program already uses it, the
  plugin uses the next free port, up to 20 numbers higher. It remembers the mapping, so a
  restarted plugin gives the port the same local number.
- A forward closes when the remote port stops accepting connections.
- Every enabled saved machine is scanned while the local Herdr server runs. The machine does not
  have to be selected in the TUI.

## Where forwards show

**Space sidebar rows.** The plugin sets a `$ports` token on the remote workspace whose pane
printed the address. Add a row with that token to your layout in `~/.config/herdr/config.toml`
(these are the default rows with the token added at the end of the branch line):

```toml
[ui.sidebar.spaces]
rows = [
  ["state_icon", "workspace"],
  ["branch", "git_status", { token = "$ports", fg = "#89b4fa" }],
]
```

A token with no value disappears together with its ` · ` separator, so workspaces without
forwards look as before. A row that is too wide is cut at the end, so the ports are cut before
the branch; drag the sidebar edge to widen it, or open the popup.

The row reads, for example, `⇄ 5173 8000→8001`: remote port 5173 uses local port 5173, and
remote port 8000 uses local port 8001 because 8000 was in use on this computer. The row
disappears when the workspace has no forwards. Clicking the row selects the workspace; it does
not open the browser.

**Toasts.** A toast shows when a forward opens (`Forwarded :5173 ← workbox`) and when a machine's
connection fails.

**Popup.** The action `bhoov.port-forwarder.show` opens a popup that lists each forward with its
full URL. Click a URL to open it. A plugin cannot declare its own keybinding, so bind the action
in your config. `prefix+shift+p` is free in Herdr's default keys (`prefix+p` is the previous tab):

```toml
[[keys.command]]
key = "prefix+shift+p"
type = "plugin_action"
command = "bhoov.port-forwarder.show"
description = "forwarded ports"
```

## Install

```bash
herdr plugin install bhoov/herdr-port-forwarder
```

For a local checkout:

```bash
herdr plugin link /path/to/herdr-port-forwarder
herdr plugin action invoke bhoov.port-forwarder.restart
```

The daemon starts automatically when the local Herdr server starts. After installing or
linking, start it once with the `restart` action as shown above, or restart the Herdr server.

Requirements on this computer: Herdr 0.9.1 or later, `python3` (3.8 or later, standard library
only) and OpenSSH. Linux and macOS only. The remote machine needs Herdr on `PATH` or in one of
the usual install locations, and its SSH server must allow TCP forwarding. Nothing is installed
on the remote machine.

## Actions

| Action | Effect |
| --- | --- |
| `bhoov.port-forwarder.show` | Open the popup. |
| `bhoov.port-forwarder.restart` | Stop the daemon if it runs, then start it. Use it after changing the config. |
| `bhoov.port-forwarder.stop` | Close all forwards, clear the tokens and stop the daemon. |

## Configuration

Optional. Create `config.json` in the directory that `herdr plugin config-dir bhoov.port-forwarder`
prints:

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

## How it works

For each enabled saved machine, the daemon opens one SSH connection in master mode
(`ssh -M -S <socket>`), with the machine's normal SSH settings. It sets
`ClearAllForwardings=yes`, so `LocalForward` lines in your SSH config do not apply to this
connection. Every scan runs over that connection and costs one round trip:

1. It runs the remote `herdr workspace list`, `herdr pane list` and, for each pane,
   `herdr pane read --source recent-unwrapped --lines 200`, and finds loopback addresses in the
   output.
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

## Limits

- The token is part of the remote server's state, so every client attached to that machine sees
  it, including clients on other computers where the port is not forwarded.
- The plugin reads snapshots of pane output. An address that scrolls more than 200 rows between
  two scans is not seen.
- Only one daemon runs for each user on a computer. Forwards last as long as the local Herdr
  server, not as long as a TUI client.
- The SSH connection runs in batch mode. A machine that needs a password or other interactive
  authentication fails with a toast; set up key authentication or an agent for it.

## Tests

```bash
python3 -m unittest discover -s tests
```
