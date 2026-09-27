# Tunnelbox Daemon

A Windows background service that lets you run a specific app through its own WireGuard tunnel, while everything else on the machine keeps using your normal connection. Think "split tunnelling", but scoped to one app at a time rather than the whole system.

The GUI client lives in a separate repository: [tunnelbox-gui](https://github.com/mkden1/tunnelbox-gui).

## How it works

1. **Containment.** When you launch an app under a profile, the daemon creates a Windows [Job Object](https://learn.microsoft.com/windows/win32/procthread/job-objects) and spawns the app inside it. Every child process it creates is automatically part of the same job, so a whole process tree is tracked as one unit.
2. **Tunnel.** The daemon opens a real WireGuard session itself, using [`boringtun`](https://github.com/cloudflare/boringtun) as the protocol implementation, and creates a virtual network adapter with [Wintun](https://www.wintun.net/) to carry that tunnel's traffic.
3. **Routing.** For every executable in the profile, the daemon installs a pair of Windows Filtering Platform (WFP) filters at the ALE layer: block on the real network adapter, permit on the Wintun adapter. This is done through the OS's own filtering engine — no custom kernel-mode driver is needed for this part.
4. **Control.** A GUI (or any client) talks to the daemon over a named pipe with a small JSON request/response protocol (see below). The daemon can also register itself as a Windows Service, so it starts automatically and survives logging out.

This works reliably for apps that behave like a typical desktop application: a browser, an Electron app, most native TCP-based software.

## Building

```bash
cargo build --release
```

Needs a Windows toolchain (MSVC). `wintun.dll` must sit next to the built executable at runtime — it's already committed here for convenience (see Licensing below).

Installing as a Windows Service (`tunnelbox-daemon.exe install`) and connecting a tunnel both require Administrator privileges, since both WFP filter installation and virtual adapter creation are privileged operations.

## IPC protocol

Requests are JSON over a named pipe (`\\.\pipe\tunnelbox-daemon`), one per line:

```json
{"id": "t-001", "cmd": "profile_create", "payload": {"name": "test"}}
```

The daemon replies with `{"id": ..., "ok": true/false, "payload": ..., "error": ...}`, echoing the same `id`.

| Command | Purpose |
|---|---|
| `profile_list` / `profile_create` / `profile_update` / `profile_delete` | Manage profiles (a named set of apps + tunnel config) |
| `tunnel_connect` / `tunnel_disconnect` / `tunnel_status` | Bring a profile's tunnel up or down |
| `app_bind` / `app_unbind` | Add or remove an executable from a profile |
| `app_launch` | Launch an executable inside a profile's Job Object |
| `wireguard_import` | Import a WireGuard config (`.conf`) into a profile |
| `daemon_status` | Version and Wintun load status |

`daemontest.ps1` is a small manual test script that exercises this protocol directly over the named pipe, useful as a working example if you don't want to build the GUI.

## Known limitations

This project is not under active development — see below.

- **No kernel-mode enforcement.** The WFP filters used here operate on the executable's path (an "app ID"), not on a specific running process. That's sufficient for most desktop apps, but it can't distinguish between two different instances of a shared runtime binary (e.g. two unrelated apps both launched via `java.exe`), and it can't intercept UDP traffic that a specific app sends outside of a cooperating proxy path.
- **This is why a per-app VPN for games didn't work out.** I tried extending this to cover a game client (traffic that mixes HTTP/HTTPS auth calls with direct UDP for the actual game connection). An early SOCKS5-proxy-based design was rejected first — most game clients don't support SOCKS5's UDP associate, and Java's own proxy handling doesn't reliably respect `HTTP_PROXY`/`ALL_PROXY` for a child process. I then rebuilt the tunnelling engine around [WinDivert](https://reqrypt.org/windivert.html) — capturing packets in user space and classifying them by polling the Job Object's live PID membership, instead of relying on WFP's exe-path filters — hoping that would be granular and protocol-agnostic enough. It compiles, but reliably attributing every packet (TCP *and* UDP) to the right process from user space, without race conditions around short-lived connections and process launch timing, turned out to need exactly the kind of guarantee only a real kernel-mode network filter driver can give you. That's the same conclusion I'd reached earlier when a WFP-based transparent-redirect design was ruled out for needing a signed kernel-mode callout driver: Windows requires kernel drivers to carry an EV code-signing certificate (and WHQL certification for some driver classes), which is a real ongoing cost, not something worth taking on for a personal project. That attempt lives on the [`experiment/windivert-rewrite`](https://github.com/mkden1/tunnelbox/tree/experiment/windivert-rewrite) branch, uncompleted.
- No automated tests; `daemontest.ps1` is a manual smoke test.

## Licensing

This project is MIT licensed (see `LICENSE`). `wintun.dll` is a separate redistributable component from the WireGuard project with its own license: https://www.wintun.net/License/
