# nipe-py

Route all your traffic through the [Tor](https://www.torproject.org/) network.

A Python rewrite of [htrgouvea/nipe](https://github.com/htrgouvea/nipe) with no
dependencies beyond the standard library. It starts a private Tor instance and
adds `iptables` rules that push all outbound TCP and DNS through it. Local and
LAN traffic is left alone, and anything that can't be routed through Tor is
rejected rather than sent in the clear.

## Requirements

- Linux with `iptables` (and `ip6tables` for IPv6)
- `tor`
- Python 3
- root

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

## Notes

The Tor config is generated at `/run/nipe-torrc` on every start, so edits to it
won't survive. Change the constants at the top of `nipe.py` instead. The
instance uses its own data directory (`/var/lib/nipe-tor`) and no SOCKS port, so
it can run alongside a system Tor.

## Credits

Original Perl implementation: [htrgouvea/nipe](https://github.com/htrgouvea/nipe)
by Heitor Gouvêa and contributors. This is an independent Python rewrite.
