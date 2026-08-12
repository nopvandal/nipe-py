#!/usr/bin/env python3
"""nipe: route all your traffic through the Tor network.

A dependency-free (stdlib-only) reimplementation of Nipe. It runs a private Tor
instance with a transparent proxy (TransPort) and a DNS resolver (DNSPort), then
installs iptables rules that redirect all outbound TCP through Tor and all DNS
through Tor's resolver. Everything that cannot be routed through Tor is
rejected, never sent in the clear.

The rules live in dedicated NIPE_* chains that are jumped to from the front of
OUTPUT/FORWARD, so the host's own firewall (ufw, firewalld, Docker, kube-proxy)
is left intact and teardown removes exactly what nipe added.

Usage:  sudo ./nipe.py {install|start|stop|restart|status}
"""

from __future__ import annotations

import contextlib
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

# --- Configuration ----------------------------------------------------------
# tor defaults both of these to 0 and prescribes no number; 9040/5353 are just
# what the transparent-proxy guides settled on. 9040 is uncontested, so we take
# it. Upstream nipe uses 9051, which those guides also avoid: it's the usual
# ControlPort, safe for upstream only because it never enables one.
TRANS_PORT = "9040"  # Tor transparent-proxy port (all TCP funnels here)
# 9061 is upstream's arbitrary pick, kept because it's unclaimed. Don't
# "correct" it to the guides' 5353, that's IANA-registered mDNS, and any desktop
# running Avahi already holds it.
DNS_PORT = "9061"  # Tor DNS port (all UDP :53 lookups funnel here)

# Ranges tor maps .onion names into (AutomapHostsOnResolve). These are matched
# ahead of the local-network exemptions below, so they must not overlap anything
# a real host can live in: 127.192.0.0/10 is loopback space (tor's own default),
# and a random /48 makes an accidental collision with a real ULA LAN negligible.
VIRT_NET_V4 = "127.192.0.0/10"
VIRT_NET_V6 = "fd6e:6970:6500::/48"

# Destinations that must NOT go through Tor. Anything reachable only on-link
# belongs here, otherwise it is redirected into Tor (which refuses to exit to a
# private address) or rejected outright: link-local carries cloud metadata
# (169.254.169.254) and CGNAT carries Tailscale, while multicast and broadcast
# carry mDNS, LLMNR, SSDP and DHCP.
LOCAL_NETS_V4 = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
)
# ff00::/8 covers the multicast that Neighbor Discovery, Router Solicitation and
# MLD depend on; without it the IPv6 link layer stops resolving neighbours.
LOCAL_NETS_V6 = ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

# Dedicated data dir so we never collide with the system tor's DataDirectory
# lock, and a dedicated torrc regenerated on every start.
DATA_DIR = Path("/var/lib/nipe-tor")
TORRC = Path("/run/nipe-torrc")
PID_FILE = DATA_DIR / "tor.pid"  # written by tor (as the tor user)
LOG_FILE = DATA_DIR / "notices.log"

# tor's unprivileged user varies by distro; first match in /etc/passwd wins.
TOR_USER_CANDIDATES = ("debian-tor", "toranon", "tor")

# Our chains. Nothing outside them is ever modified.
NAT_CHAIN = "NIPE_NAT"  # nat OUTPUT
OUT_CHAIN = "NIPE_OUT"  # filter OUTPUT
FWD_CHAIN = "NIPE_FWD"  # filter FORWARD

XT_LOCK_WAIT = "5"  # seconds to wait for /run/xtables.lock
BOOTSTRAP_TIMEOUT = 120.0  # seconds to wait for "Bootstrapped 100%"
CHECK_URL = "https://check.torproject.org/api/ip"
PACKAGES = ("tor", "iptables")

# A transparent proxy sees every application arrive from 127.0.0.1 with no SOCKS
# credentials, so tor's default isolation (IsolateClientAddr, IsolateSOCKSAuth)
# cannot tell them apart and everything would share one circuit and one exit.
ISOLATION = "IsolateClientProtocol IsolateDestAddr IsolateDestPort"


class NipeError(Exception):
    """A failure that should abort the current command with a message."""


class Family(NamedTuple):
    """Everything that differs between the IPv4 and IPv6 rule sets."""

    label: str
    iptables: str
    restore: str
    virt_net: str
    local_nets: tuple[str, ...]


V4 = Family("IPv4", "iptables", "iptables-restore", VIRT_NET_V4, LOCAL_NETS_V4)
V6 = Family("IPv6", "ip6tables", "ip6tables-restore", VIRT_NET_V6, LOCAL_NETS_V6)


def run(cmd: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command quietly, capturing its output.

    Never raises for a failing command or a missing/unusable binary: callers get
    a CompletedProcess with a non-zero returncode and the diagnostics in stderr,
    so a failure is reported rather than silently ignored.
    """
    try:
        return subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: {exc}")


def run_visible(cmd: list[str]) -> int:
    """Run a command with the caller's stdio attached, returning its exit code."""
    try:
        return subprocess.run(cmd, check=False).returncode
    except OSError as exc:
        print(f"[!] {cmd[0]}: {exc}", file=sys.stderr)
        return 127


def _fail(proc: subprocess.CompletedProcess[str], context: str) -> NipeError:
    detail = (proc.stderr or proc.stdout).strip().splitlines()
    tail = detail[-1] if detail else f"exit status {proc.returncode}"
    return NipeError(f"{context}: {tail}")


def tor_user() -> str:
    """Return the name of the unprivileged user tor should drop to."""
    for name in TOR_USER_CANDIDATES:
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        return name
    raise NipeError(
        "could not find a tor user (debian-tor/toranon/tor). Is Tor installed?"
    )


def require_root() -> None:
    """Abort unless we are running as root."""
    if os.geteuid() != 0:
        raise NipeError("nipe must be run as root.")


# --- Firewall ---------------------------------------------------------------
def ipv6_enabled() -> bool:
    """Report whether the kernel currently has IPv6 turned on."""
    try:
        disabled = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text()
    except OSError:
        return False
    return disabled.strip() == "0"


def _families() -> list[Family]:
    """Return the address families to configure, or refuse to leave one open.

    IPv6 that we cannot filter is worse than no IPv6 support at all: glibc
    prefers AAAA, so a dual-stack host would send most of its traffic out in the
    clear while the IPv4 path looked healthy.
    """
    families = [V4]
    if not ipv6_enabled():
        return families
    for binary in (V6.iptables, V6.restore):
        if shutil.which(binary) is None:
            raise NipeError(
                f"IPv6 is enabled but {binary} is missing, so IPv6 traffic would "
                "leak in the clear. Install it, or disable IPv6 with "
                "'sysctl -w net.ipv6.conf.all.disable_ipv6=1'."
            )
    families.append(V6)
    return families


def _ruleset(family: Family, user: str) -> str:
    """Render the whole rule set for one address family as iptables-restore input.

    One restore call per family means one atomic transaction, one exit code to
    check and one lock acquisition, with no window in which the rules are half
    applied.
    """
    nat = [
        # Tor's own traffic must reach the network directly, or nothing works.
        f"-A {NAT_CHAIN} -m owner --uid-owner {user} -j RETURN",
        # .onion addresses tor handed out -> transparent proxy.
        (
            f"-A {NAT_CHAIN} -d {family.virt_net} -p tcp -j REDIRECT "
            f"--to-ports {TRANS_PORT}"
        ),
        # UDP DNS -> tor's resolver, including queries aimed at a loopback or LAN
        # resolver, which is why this precedes the exemptions below. TCP DNS is
        # deliberately left to the TransPort catch-all: tor's DNSPort has no TCP
        # listener, so redirecting it here would only produce ECONNREFUSED.
        f"-A {NAT_CHAIN} -p udp --dport 53 -j REDIRECT --to-ports {DNS_PORT}",
    ]
    nat += [f"-A {NAT_CHAIN} -d {net} -j RETURN" for net in family.local_nets]
    nat.append(f"-A {NAT_CHAIN} -p tcp -j REDIRECT --to-ports {TRANS_PORT}")

    out = [
        # Redirected traffic has already been rewritten to the loopback address.
        f"-A {OUT_CHAIN} -o lo -j RETURN",
        f"-A {OUT_CHAIN} -m owner --uid-owner {user} -j RETURN",
    ]
    out += [f"-A {OUT_CHAIN} -d {net} -j RETURN" for net in family.local_nets]
    # Default deny, with no protocol qualifier: ESP, GRE, SCTP, DCCP, IPIP and
    # 6in4 would otherwise walk straight out past a udp/icmp-only block list.
    out.append(f"-A {OUT_CHAIN} -j REJECT")

    # Routed traffic (containers, VMs, a hotspot) never enters OUTPUT, so it
    # would bypass every rule above. We cannot transparently proxy it from here,
    # so it is refused rather than allowed out with the host's real address.
    fwd = [f"-A {FWD_CHAIN} -d {net} -j RETURN" for net in family.local_nets]
    fwd.append(f"-A {FWD_CHAIN} -j REJECT")

    lines = [
        "*nat",
        f":{NAT_CHAIN} - [0:0]",
        *nat,
        "COMMIT",
        "*filter",
        f":{OUT_CHAIN} - [0:0]",
        f":{FWD_CHAIN} - [0:0]",
        *out,
        *fwd,
        "COMMIT",
    ]
    return "\n".join(lines) + "\n"


def _jumps() -> list[tuple[str, str, str]]:
    """Return the (table, parent chain, nipe chain) jumps nipe installs."""
    return [
        ("nat", "OUTPUT", NAT_CHAIN),
        ("filter", "OUTPUT", OUT_CHAIN),
        ("filter", "FORWARD", FWD_CHAIN),
    ]


def _teardown(family: Family) -> None:
    """Remove nipe's chains and jumps, leaving every foreign rule untouched."""
    ipt = family.iptables
    if shutil.which(ipt) is None:
        return
    for table, parent, chain in _jumps():
        base = [ipt, "-w", XT_LOCK_WAIT, "-t", table]
        # A jump can appear more than once if a previous run was interrupted.
        for _ in range(8):
            if run([*base, "-D", parent, "-j", chain]).returncode != 0:
                break
        run([*base, "-F", chain])
        run([*base, "-X", chain])


def _install(family: Family, user: str) -> None:
    """Apply nipe's rule set for one family and make it live."""
    _teardown(family)
    proc = run(
        [family.restore, "-w", XT_LOCK_WAIT, "--noflush"], _ruleset(family, user)
    )
    if proc.returncode != 0:
        raise _fail(proc, f"could not install the {family.label} rules")
    # The redirect goes live before the deny does, so no traffic is stranded.
    for table, parent, chain in _jumps():
        base = [family.iptables, "-w", XT_LOCK_WAIT, "-t", table]
        proc = run([*base, "-I", parent, "-j", chain])
        if proc.returncode != 0:
            raise _fail(proc, f"could not activate the {family.label} {chain} chain")


def teardown_all() -> None:
    """Remove nipe's rules for both families, whatever state they are in."""
    for family in (V4, V6):
        _teardown(family)


def rules_installed() -> bool:
    """Report whether nipe's IPv4 chains are currently live."""
    cmd = ["iptables", "-w", XT_LOCK_WAIT, "-t", "nat", "-n", "-L", NAT_CHAIN]
    return run(cmd).returncode == 0


def flush_conntrack() -> None:
    """Best-effort conntrack flush.

    The nat table is only consulted for the first packet of a flow, so any
    connection that was open when nipe started would otherwise keep running
    outside Tor for the lifetime of its conntrack entry (five days for an idle
    TCP stream). Dropping the entries forces every flow through the new rules.
    """
    run(["conntrack", "-F"])


def flush_dns_cache() -> None:
    """Best-effort DNS cache flush.

    tor stamps a flat 30 minute TTL on the answers it resolves, so without this
    a name looked up through an exit relay would keep being used for direct
    connections after nipe stops, and names cached before nipe started would
    never be automapped.
    """
    for cmd in (["resolvectl", "flush-caches"], ["nscd", "-i", "hosts"]):
        if shutil.which(cmd[0]) is not None:
            run(cmd)


# --- Tor process ------------------------------------------------------------
def write_torrc(user: str, ipv6: bool) -> None:
    """Generate the private tor configuration for this run."""
    listeners = [
        f"TransPort 127.0.0.1:{TRANS_PORT} {ISOLATION}",
        f"DNSPort 127.0.0.1:{DNS_PORT}",
    ]
    if ipv6:
        # Without these, ip6tables REDIRECT would hand every IPv6 connection to
        # [::1]:TRANS_PORT, where a v4-only tor is not listening.
        listeners += [
            f"TransPort [::1]:{TRANS_PORT} {ISOLATION}",
            f"DNSPort [::1]:{DNS_PORT}",
        ]
    # SOCKSPort 0: we only transparent-proxy, and tor's implicit default (9050)
    # would fail to bind when the system tor already holds it, killing startup.
    body = "\n".join(
        [
            f"DataDirectory {DATA_DIR}",
            f"PidFile {PID_FILE}",
            f"Log notice file {LOG_FILE}",
            "RunAsDaemon 1",
            f"User {user}",
            "ClientOnly 1",
            "SOCKSPort 0",
            *listeners,
            f"VirtualAddrNetworkIPv4 {VIRT_NET_V4}",
            f"VirtualAddrNetworkIPv6 {VIRT_NET_V6}",
            "AutomapHostsOnResolve 1",
        ]
    )
    TORRC.write_text(body + "\n")
    TORRC.chmod(0o644)


def prepare_data_dir(user: str) -> None:
    """Create the data dir and hand it, and everything in it, to the tor user.

    mkdir(exist_ok=True) does not re-apply the mode to an existing directory and
    a plain chown is not recursive, so a directory left over from an earlier run
    (or from a distro that used a different tor user) would keep permissions tor
    cannot use and would fail to start with its log unwritable.
    """
    entry = pwd.getpwnam(user)
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    DATA_DIR.chmod(0o700)
    for path in (DATA_DIR, *DATA_DIR.rglob("*")):
        with contextlib.suppress(OSError):
            os.chown(path, entry.pw_uid, entry.pw_gid)


def _tor_pid() -> int | None:
    """Return the PID of our tor daemon, or None if it is not running.

    The pidfile lives in a directory the tor user owns and survives an unclean
    exit, so its contents are checked against /proc before anything is signalled;
    root must never SIGTERM a recycled PID, and 0 or a negative value would
    signal an entire process group or every process on the system.
    """
    try:
        pid = int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None
    if pid <= 1:
        return None
    try:
        comm = Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return None
    return pid if comm == "tor" else None


def stop_tor(timeout: float = 10.0) -> None:
    """Stop our tor daemon and wait for it to actually exit.

    Returning early would race the next start for the DataDirectory lock and the
    listening ports, which tor treats as a fatal bind error.
    """
    pid = _tor_pid()
    if pid is None:
        PID_FILE.unlink(missing_ok=True)
        return
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _tor_pid() is None:
            break
        time.sleep(0.05)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
        time.sleep(0.2)
    PID_FILE.unlink(missing_ok=True)


def start_tor() -> None:
    """Launch the private tor daemon, reporting why it failed if it did."""
    LOG_FILE.unlink(missing_ok=True)
    proc = run(["tor", "-f", str(TORRC)])
    if proc.returncode != 0:
        raise _fail(proc, "Tor failed to start")
    if _tor_pid() is None:
        raise NipeError(f"Tor exited immediately after starting. See {LOG_FILE}")


def wait_for_bootstrap(timeout: float = BOOTSTRAP_TIMEOUT) -> None:
    """Block until tor reports a finished bootstrap in its own log.

    Asking check.torproject.org instead would conflate "tor is not ready" with
    "the network is down" and "that site is blocked", and would tell a third
    party about this host before the circuit it is meant to be testing exists.
    """
    progress = re.compile(r"Bootstrapped (\d+)%")
    deadline = time.monotonic() + timeout
    reported = -1
    while time.monotonic() < deadline:
        if _tor_pid() is None:
            raise NipeError(f"Tor died while bootstrapping. See {LOG_FILE}")
        try:
            log = LOG_FILE.read_text(errors="replace")
        except OSError:
            log = ""
        percentages = [int(match) for match in progress.findall(log)]
        if percentages and percentages[-1] != reported:
            reported = percentages[-1]
            print(f"[*] Bootstrapped {reported}%")
        if reported >= 100:
            return
        time.sleep(0.5)
    raise NipeError(
        f"Tor did not finish bootstrapping within {timeout:.0f}s. See {LOG_FILE}"
    )


# --- Commands ---------------------------------------------------------------
def tor_check(timeout: float = 15.0) -> dict[str, Any]:
    """Ask the Tor Project whether this host's traffic is arriving over Tor.

    The default urllib opener honours http_proxy/https_proxy from the
    environment, which under 'sudo -E' or a systemd unit would answer the one
    question nipe asks over a path that is not Tor. This opener has no proxies.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(CHECK_URL, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise NipeError("the Tor check service returned an unexpected response")
    return payload


def cmd_start() -> int:
    """Start the private Tor instance and route all traffic through it."""
    require_root()
    user = tor_user()
    families = _families()

    stop_tor()
    teardown_all()
    prepare_data_dir(user)
    write_torrc(user, ipv6=V6 in families)

    try:
        # Rules first: a failure now leaves the host exactly as it was, and the
        # tor user's exemption is in place before tor needs the network.
        for family in families:
            _install(family, user)
        flush_conntrack()
        flush_dns_cache()
        start_tor()
        print("[*] Waiting for Tor to bootstrap...")
        wait_for_bootstrap()
        flush_dns_cache()
    except NipeError:
        # Never leave redirects pointing at a tor that is not there, and never
        # leave the machine unprotected after reporting a failure.
        stop_tor()
        teardown_all()
        raise
    return cmd_status()


def cmd_stop() -> int:
    """Remove nipe's firewall rules and stop the Tor instance."""
    require_root()
    teardown_all()
    stop_tor()
    TORRC.unlink(missing_ok=True)
    flush_conntrack()
    flush_dns_cache()
    print("[*] Stopped. Traffic is no longer routed through Tor.")
    return 0


def cmd_restart() -> int:
    """Stop, then start."""
    cmd_stop()
    return cmd_start()


def cmd_status() -> int:
    """Report whether traffic is currently leaving over Tor."""
    require_root()
    if _tor_pid() is None or not rules_installed():
        print("[!] nipe is not running.")
        return 1
    try:
        data = tor_check()
    except (OSError, urllib.error.URLError, ValueError, NipeError) as exc:
        print(f"[!] Could not reach the Tor check service: {exc}")
        return 1
    is_tor = bool(data.get("IsTor"))
    print(f"\n[+] Status: {'true' if is_tor else 'false'}")
    print(f"[+] Ip: {data.get('IP', 'unknown')}\n")
    return 0 if is_tor else 1


# Each entry is (probe binary, optional preparation steps, install step). The
# preparation steps may fail harmlessly: EPEL is absent on Fedora, and an
# apt-get update failure still leaves a usable cache.
INSTALLERS: tuple[tuple[str, tuple[list[str], ...], list[str]], ...] = (
    (
        "apt-get",
        (["apt-get", "update"],),
        ["apt-get", "install", "-y", *PACKAGES],
    ),
    (
        "dnf",
        (["dnf", "install", "-y", "epel-release"],),
        ["dnf", "install", "-y", *PACKAGES],
    ),
    (
        "yum",
        (["yum", "install", "-y", "epel-release"],),
        ["yum", "install", "-y", *PACKAGES],
    ),
    ("pacman", (), ["pacman", "-Sy", "--noconfirm", *PACKAGES]),
    ("zypper", (), ["zypper", "--non-interactive", "install", *PACKAGES]),
    ("xbps-install", (), ["xbps-install", "-Sy", *PACKAGES]),
)


def cmd_install() -> int:
    """Install tor and iptables with the distro's package manager."""
    require_root()
    for binary, preparation, install in INSTALLERS:
        if shutil.which(binary) is None:
            continue
        for step in preparation:
            run_visible(step)
        # Inherit stdio: a silent multi-minute download is indistinguishable
        # from a hang, and the package manager's error text is the only clue
        # when the package is missing from the configured repositories.
        if run_visible(install) != 0:
            raise NipeError(f"{binary} failed to install {' and '.join(PACKAGES)}.")
        return 0
    raise NipeError(
        "no supported package manager found. Install 'tor' and 'iptables' manually."
    )


COMMANDS = {
    "install": cmd_install,
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
}


def main() -> int:
    """Dispatch the requested command and return its exit status."""
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print(f"Usage: sudo ./nipe.py {{{'|'.join(COMMANDS)}}}", file=sys.stderr)
        return 2
    try:
        return COMMANDS[sys.argv[1]]()
    except NipeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
