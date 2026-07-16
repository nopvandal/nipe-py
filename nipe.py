#!/usr/bin/env python3
"""nipe — route all your traffic through the Tor network.

A dependency-free (stdlib-only) reimplementation of Nipe. It runs a private Tor
instance with a transparent proxy (TransPort) + DNS resolver (DNSPort), then
installs iptables OUTPUT rules that redirect all outbound TCP through Tor and
all DNS through Tor's resolver, while exempting the tor daemon itself and
local/LAN destinations. Stray UDP/ICMP is rejected.

Usage:  sudo ./nipe.py {install|start|stop|restart|status}
"""

import json
import os
import pwd
import shutil
import subprocess
import sys
import time
import urllib.request

# --- Configuration ----------------------------------------------------------
# 9040 is tor's conventional TransPort. Upstream nipe uses 9051, which is tor's
# conventional ControlPort -- safe only because it never enables one.
TRANS_PORT = "9040"          # Tor transparent-proxy port (all TCP funnels here)
DNS_PORT = "9061"            # Tor DNS port (all :53 lookups funnel here); tor's
                             # conventional 5353 would collide with mDNS/Avahi.
VIRT_NET_V4 = "10.66.0.0/255.255.0.0"   # AutomapHostsOnResolve range (.onion)
VIRT_NET_V6 = "fd00::/8"
# Dedicated data dir so we never collide with the system tor's DataDirectory lock.
DATA_DIR = "/var/lib/nipe-tor"
TORRC = "/run/nipe-torrc"
PID_FILE = os.path.join(DATA_DIR, "tor.pid")   # written by tor (as the tor user)
LOG_FILE = os.path.join(DATA_DIR, "notices.log")

# Destinations that must NOT go through Tor (loopback + RFC1918 / ULA / link-local).
LOCAL_NETS_V4 = ["127.0.0.1/8", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]
LOCAL_NETS_V6 = ["::1/128", "fc00::/7", "fe80::/10"]

# tor's unprivileged user varies by distro; first match in /etc/passwd wins.
TOR_USER_CANDIDATES = ["debian-tor", "toranon", "tor"]


def run(cmd, check=False):
    """Run a command quietly, returning its exit code.

    Returns 127 if the binary is missing instead of raising, so a missing
    ip6tables/tor doesn't crash us mid-way and leave a half-configured firewall.
    """
    try:
        return subprocess.run(cmd, check=check,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode
    except FileNotFoundError:
        return 127


def tor_user():
    for name in TOR_USER_CANDIDATES:
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    sys.exit("[!] Could not find a tor user (debian-tor/toranon/tor). Is Tor installed?")


def require_root():
    if os.geteuid() != 0:
        sys.exit("[!] nipe must be run as root.")


# --- Firewall ---------------------------------------------------------------
def _route(ipt, uid, virt_net, local_nets, icmp_proto):
    """Install redirect rules for one address family (iptables or ip6tables).

    In the `nat` table we REDIRECT to Tor / RETURN for exemptions; the mirrored
    `filter` table ACCEPTs the same traffic so it is not later dropped.
    """
    for table in ("nat", "filter"):
        exempt = "RETURN" if table == "nat" else "ACCEPT"

        run([ipt, "-t", table, "-F", "OUTPUT"])
        # Let established connections and Tor's own traffic pass untouched.
        run([ipt, "-t", table, "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED", "-j", exempt])
        run([ipt, "-t", table, "-A", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", exempt])

        # DNS: redirect :53 to Tor's DNSPort (nat); accept the DNSPort itself (filter).
        if table == "nat":
            dns_target, dns_match = ["REDIRECT", "--to-ports", DNS_PORT], "53"
        else:
            dns_target, dns_match = [exempt], DNS_PORT
        for proto in ("udp", "tcp"):
            run([ipt, "-t", table, "-A", "OUTPUT", "-p", proto, "--dport", dns_match, "-j", *dns_target])

        trans = ["REDIRECT", "--to-ports", TRANS_PORT] if table == "nat" else [exempt]
        # Tor's virtual (.onion) address range -> transparent proxy.
        run([ipt, "-t", table, "-A", "OUTPUT", "-d", virt_net, "-p", "tcp", "-j", *trans])
        # Local/LAN destinations bypass Tor entirely.
        for net in local_nets:
            run([ipt, "-t", table, "-A", "OUTPUT", "-d", net, "-j", exempt])
        # Everything else (all remaining TCP) -> transparent proxy.
        run([ipt, "-t", table, "-A", "OUTPUT", "-p", "tcp", "-j", *trans])

    # Nothing else may leak out: drop non-Tor UDP and ICMP.
    run([ipt, "-t", "filter", "-A", "OUTPUT", "-p", "udp", "-j", "REJECT"])
    run([ipt, "-t", "filter", "-A", "OUTPUT", "-p", icmp_proto, "-j", "REJECT"])


def _flush(ipt):
    for table in ("nat", "filter"):
        run([ipt, "-t", table, "-F", "OUTPUT"])


def has_ipv6():
    return os.path.isdir("/proc/sys/net/ipv6")


# --- Tor process ------------------------------------------------------------
def write_torrc(uid):
    # SOCKSPort 0: we only transparent-proxy, and tor's implicit default (9050)
    # would fail to bind when the system tor already holds it, killing startup.
    with open(TORRC, "w") as f:
        f.write(f"""\
DataDirectory {DATA_DIR}
PidFile {PID_FILE}
RunAsDaemon 1
User {uid}
Log notice file {LOG_FILE}
ClientOnly 1
SOCKSPort 0
TransPort {TRANS_PORT}
DNSPort {DNS_PORT}
VirtualAddrNetwork {VIRT_NET_V4}
VirtualAddrNetworkIPv6 {VIRT_NET_V6}
AutomapHostsOnResolve 1
""")


def stop_tor():
    try:
        with open(PID_FILE) as f:
            os.kill(int(f.read().strip()), 15)
    except (FileNotFoundError, ProcessLookupError, ValueError):
        pass


# --- Commands ---------------------------------------------------------------
def cmd_start():
    require_root()
    uid = tor_user()
    stop_tor()

    # Dedicated, tor-user-owned data dir so tor can write its pidfile + logs
    # after it drops privileges, and so we don't lock the system tor's dir.
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    shutil.chown(DATA_DIR, user=uid)

    write_torrc(uid)
    if run(["tor", "-f", TORRC]) != 0:
        sys.exit(f"[!] Failed to start Tor. Check {LOG_FILE}")

    _route("iptables", uid, VIRT_NET_V4, LOCAL_NETS_V4, "icmp")
    if has_ipv6():
        _route("ip6tables", uid, VIRT_NET_V6, LOCAL_NETS_V6, "icmpv6")

    print("[*] Waiting for Tor to bootstrap...")
    cmd_status(retries=12, delay=5)


def cmd_stop():
    require_root()
    _flush("iptables")
    if has_ipv6():
        _flush("ip6tables")
    stop_tor()


def cmd_restart():
    cmd_stop()
    cmd_start()


def cmd_status(retries=1, delay=0):
    for attempt in range(retries):
        try:
            with urllib.request.urlopen("https://check.torproject.org/api/ip", timeout=15) as r:
                data = json.load(r)
            print(f"\n[+] Status: {'true' if data.get('IsTor') else 'false'}")
            print(f"[+] Ip: {data.get('IP')}\n")
            return
        except Exception:
            if attempt < retries - 1:
                time.sleep(delay)
    print("\n[!] ERROR: could not reach the Tor Project check server.\n")


def cmd_install():
    require_root()
    managers = [
        (["apt-get", "install", "-y", "tor", "iptables"], "apt-get"),
        (["dnf", "install", "-y", "tor", "iptables"], "dnf"),
        (["yum", "-y", "install", "epel-release", "tor", "iptables"], "yum"),
        (["pacman", "-S", "--noconfirm", "tor", "iptables"], "pacman"),
        (["zypper", "install", "-y", "tor", "iptables"], "zypper"),
        (["xbps-install", "-y", "tor", "iptables"], "xbps-install"),
    ]
    for cmd, binary in managers:
        if shutil.which(binary):
            run(cmd, check=False)
            return
    sys.exit("[!] No supported package manager found. Install 'tor' and 'iptables' manually.")


COMMANDS = {
    "install": cmd_install,
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print("Usage: sudo ./nipe.py {install|start|stop|restart|status}")
        sys.exit(1)
    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()
