# nipe-py

Route all your traffic through the [Tor](https://www.torproject.org/) network.

A Python rewrite of [htrgouvea/nipe](https://github.com/htrgouvea/nipe) with no
dependencies beyond the standard library. It starts a private Tor instance and
adds `iptables` rules that push all outbound TCP and DNS through it. Local and
LAN traffic is left alone, and anything that cannot be routed through Tor is
rejected rather than sent in the clear.

## Requirements

- Linux with `iptables` (and `ip6tables` if IPv6 is enabled)
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
| `stop`    | Remove the firewall rules and stop the Tor instance.                |
| `restart` | `stop` then `start`.                                                 |
| `status`  | Query `check.torproject.org` and report whether traffic is on Tor.  |

Every command exits non-zero on failure, so `sudo ./nipe.py start && ...` is
safe to use in a script: `start` fails rather than returning while traffic is
still in the clear.

Example:

```console
$ sudo ./nipe.py start
[*] Waiting for Tor to bootstrap...
[*] Bootstrapped 100%

[+] Status: true
[+] Ip: <a Tor exit-node IP>
```

## What gets blocked

The rule set is default-deny: outbound TCP is redirected into Tor, UDP port 53
is redirected into Tor's resolver, on-link destinations are exempted, and
everything else is rejected. That is deliberate, and it has consequences worth
knowing about.

- **UDP other than DNS is rejected.** Tor carries TCP only, so NTP, QUIC and
  WireGuard cannot be proxied. NTP in particular means the clock stops being
  corrected while nipe runs, and Tor refuses a consensus once the clock drifts
  far enough, so do not leave nipe running for days on a host with a bad RTC.
- **Forwarded traffic is rejected.** Packets from Docker containers, VMs and a
  Wi-Fi hotspot never traverse the `OUTPUT` chain, so they cannot be redirected
  into Tor from here. They are refused instead of being allowed out with the
  host's real address, which means containers lose internet access while nipe
  is running.
- **DNS is limited to A, AAAA and PTR.** That is all Tor's `DNSPort` answers,
  so SRV, MX and TXT lookups fail. DNS over TCP still works: it is carried by
  the transparent proxy rather than the resolver.
- **IPv6 is all or nothing.** If IPv6 is enabled but `ip6tables` is missing,
  `start` refuses to run rather than leave IPv6 unfiltered, since glibc prefers
  AAAA and most traffic would leak.

## Notes

The rules live in dedicated `NIPE_NAT`, `NIPE_OUT` and `NIPE_FWD` chains that
are jumped to from the front of `OUTPUT` and `FORWARD`, so your existing
firewall (ufw, firewalld, Docker, kube-proxy) is left intact and `stop` removes
exactly what nipe added. Each family's rules are applied in a single
`iptables-restore` transaction, so they are never half-installed.

The Tor config is generated at `/run/nipe-torrc` on every start, so edits to it
will not survive. Change the constants at the top of `nipe.py` instead. The
instance uses its own data directory (`/var/lib/nipe-tor`) and no SOCKS port, so
it can run alongside a system Tor, though the two cannot both hold the
transparent-proxy and DNS ports.

`start` waits for Tor's own `Bootstrapped 100%` before reporting success, and
flushes conntrack and the DNS cache so that connections and cached answers from
before the switch cannot outlive it.

## Credits

Original Perl implementation: [htrgouvea/nipe](https://github.com/htrgouvea/nipe)
by Heitor Gouvêa and contributors. This is an independent Python rewrite.
