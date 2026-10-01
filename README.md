# nipe-py

Route all your traffic through the [Tor](https://www.torproject.org/) network.

A Python rewrite of [htrgouvea/nipe](https://github.com/htrgouvea/nipe) with no
dependencies beyond the standard library. It starts a private Tor instance and
adds `iptables` rules that push all outbound TCP and DNS through it. Local and
LAN traffic is left alone, and anything that cannot be routed through Tor is
rejected rather than sent in the clear.

## Requirements

- Linux with `iptables` (and `ip6tables` if IPv6 is enabled), see
  [Portability](#portability)
- `tor`
- Python 3
- root

## Usage

```console
$ sudo ./nipe.py {install|start|stop|restart|status}
```

| Command   | Action                                                                                  |
| --------- | --------------------------------------------------------------------------------------- |
| `install` | Install `tor` and `iptables` via your distro's package manager (`pacman -Syu` on Arch). |
| `start`   | Start the private Tor instance and redirect all traffic through it.                     |
| `stop`    | Remove the firewall rules and stop the Tor instance.                                    |
| `restart` | Same as `start`, which already stops the old Tor and replaces the rules.                |
| `status`  | Query `check.torproject.org` and report whether traffic is on Tor.                      |

Every command exits non-zero on failure, so `sudo ./nipe.py start && ...` is
safe to use in a script: `start` fails rather than returning while traffic is
still in the clear. Once Tor has bootstrapped and the rules are live, `start`
exits 0 even if `check.torproject.org` cannot be reached (it prints a warning);
it exits non-zero if the check service reports traffic is not on Tor (nipe stays
running, fail-closed).

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
  so SRV, MX and TXT lookups fail. TCP DNS to public resolvers is carried by
  the transparent proxy; TCP DNS to a LAN resolver (e.g. a home router) is
  rejected, because a LAN resolver would forward the query upstream in the
  clear. A loopback stub like systemd-resolved still answers, but its TCP
  fallback to a LAN upstream fails.
- **IPv6 is all or nothing.** If the kernel has IPv6 support at all, nipe
  installs ip6tables rules regardless of `disable_ipv6`, because interfaces
  can re-enable IPv6 individually (NetworkManager does) or appear later with
  IPv6 on. If `ip6tables` is missing on such a kernel, `start` refuses to run;
  the only way around it is installing ip6tables or booting with
  `ipv6.disable=1`.
- **Inbound connections from the internet get no replies.** Replies to a
  public address are rejected like any other outbound packet, so servers on the
  host stop answering and running `start` over SSH on a remote machine (a VPS)
  cuts off the session. LAN peers are unaffected. Replies are not exempted
  because after the conntrack flush, an already-open outbound connection whose
  next packet comes from the remote is tracked as inbound, so exempting replies
  would let it continue outside Tor.

## Portability

nipe depends on:

- `iptables`, `ip6tables` and `iptables-restore`.
- `/proc/<pid>/comm` to confirm the pidfile still points at our Tor,
  `/proc/sys/net/ipv6` to detect IPv6 support, and `/proc/net/if_inet6` to check
  loopback has `::1` before Tor listens on it.
- `/run` for the generated torrc, `conntrack` for the state flush, and
  `resolvectl` or `nscd` for the DNS flush.
- An unprivileged `debian-tor`, `toranon` or `tor` account for Tor to drop to,
  and a distro package manager for `install`.

macOS needs more than substitutes for those. `pf` applies `rdr` only to traffic
arriving on an interface, so there is no counterpart to the `nat` `OUTPUT` chain
this relies on to redirect the host's own packets. Reaching a transparent proxy
from locally originated traffic takes `route-to` on the outbound rules or a
`utun` with policy routing. Upstream Nipe is Linux-only for the same reason.

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
