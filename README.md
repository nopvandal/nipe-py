# nipe-py

Route all your traffic through the [Tor](https://www.torproject.org/) network.

A dependency-free (Python **stdlib-only**) reimplementation of
[htrgouvea/nipe](https://github.com/htrgouvea/nipe). It runs a private Tor
instance with a transparent proxy (`TransPort`) plus DNS resolver (`DNSPort`),
then installs `iptables` OUTPUT rules that redirect all outbound TCP through Tor
and all DNS through Tor's resolver — while exempting the tor daemon itself and
local/LAN destinations. Stray UDP/ICMP is rejected so nothing leaks.

## Requirements

- Linux with `iptables` (and `ip6tables` for IPv6)
- `tor`
- Python 3 (standard library only — no `pip install` needed)
- root privileges

## Usage

```console
$ sudo ./nipe.py {install|start|stop|restart|status}
```

| Command   | Action                                                              |
| --------- | ------------------------------------------------------------------- |
| `install` | Install `tor` and `iptables` via your distro's package manager.     |
| `start`   | Start the private Tor instance and redirect all traffic through it. |
| `stop`    | Flush the firewall rules and stop the Tor instance.                 |
| `restart` | `stop` then `start`.                                                 |
| `status`  | Query `check.torproject.org` and report whether traffic is on Tor.  |

Example:

```console
$ sudo ./nipe.py start
[*] Waiting for Tor to bootstrap...

[+] Status: true
[+] Ip: <a Tor exit-node IP>
```

## How it works

- A dedicated data directory (`/var/lib/nipe-tor`) keeps this instance from
  colliding with the system Tor's `DataDirectory` lock.
- In the `nat` table, DNS (`:53`) is redirected to Tor's `DNSPort` and all other
  TCP is redirected to Tor's `TransPort`; the mirrored `filter` table accepts the
  same traffic so it is not dropped later.
- Established connections, Tor's own UID, and local/RFC1918/ULA/link-local
  destinations bypass Tor.
- Everything else that isn't Tor-bound UDP/ICMP is rejected.

## Credits

Original Perl implementation: [htrgouvea/nipe](https://github.com/htrgouvea/nipe)
by Heitor Gouvêa and contributors. This is an independent Python rewrite.
