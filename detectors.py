"""
raspberry-ids / detectors.py
============================
Five independent, stateful detection engines.

Each detector exposes a single public method:
    check(packet) -> None

Internally they maintain sliding-window counters and call alerter.alert()
when a threshold is crossed.
"""

import math
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from scapy.layers.inet  import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2   import ARP
from scapy.layers.dns  import DNS, DNSQR

import alerter
import config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _CountWindow:
    """
    Thread-safe sliding window that counts events per key.
    Returns the count in the current window after each add().
    """
    def __init__(self, window_seconds: float):
        self._win  = window_seconds
        self._data: Dict[Any, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: Any) -> int:
        now = time.monotonic()
        cutoff = now - self._win
        with self._lock:
            dq = self._data[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(now)
            return len(dq)


class _UniqueWindow:
    """
    Thread-safe sliding window that tracks unique *values* per key.
    Returns the number of distinct values seen in the window after each add().
    """
    def __init__(self, window_seconds: float):
        self._win  = window_seconds
        self._data: Dict[Any, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: Any, value: Any) -> int:
        now = time.monotonic()
        cutoff = now - self._win
        with self._lock:
            dq = self._data[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            dq.append((now, value))
            return len({v for _, v in dq})


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _src_ip(packet) -> Optional[str]:
    if packet.haslayer(IP):
        return packet[IP].src
    if packet.haslayer(IPv6):
        return packet[IPv6].src
    return None


# ---------------------------------------------------------------------------
# 1. Port-scan detector
# ---------------------------------------------------------------------------

class PortScanDetector:
    """
    Detects port scans (including Nmap SYN / stealth scans).

    Triggers when a single source IP contacts more than PORT_SCAN_THRESHOLD
    distinct destination ports within PORT_SCAN_WINDOW seconds.
    """

    def __init__(self):
        self._win = _UniqueWindow(config.PORT_SCAN_WINDOW)

    def check(self, packet) -> None:
        src = _src_ip(packet)
        if src is None:
            return

        # Only care about TCP/UDP (port-based protocols)
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            return

        unique_ports = self._win.add(src, dst_port)

        if unique_ports >= config.PORT_SCAN_THRESHOLD:
            alerter.alert(
                alert_type = "port_scan",
                title      = f"Port scan detected from {src}",
                detail     = (
                    f"Source IP  : {src}\n"
                    f"Unique ports touched in last {config.PORT_SCAN_WINDOW}s: {unique_ports}\n"
                    f"Threshold  : {config.PORT_SCAN_THRESHOLD}\n"
                    f"Last port  : {dst_port}"
                ),
                severity   = "WARNING",
            )


# ---------------------------------------------------------------------------
# 2. Brute-force detector
# ---------------------------------------------------------------------------

class BruteForceDetector:
    """
    Detects brute-force login attempts against SSH, FTP, Telnet, RDP.

    Triggers when the same source IP sends more than BRUTE_FORCE_THRESHOLD
    TCP SYN packets (or any packet, for UDP services) to a sensitive port
    within BRUTE_FORCE_WINDOW seconds.
    """

    def __init__(self):
        # key = (src_ip, dst_port)
        self._win = _CountWindow(config.BRUTE_FORCE_WINDOW)

    def check(self, packet) -> None:
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]

        # Only track connection initiations (SYN set, ACK clear) or all packets
        # to the sensitive port — SYN-only is less noisy.
        flags = tcp.flags
        if not (flags & 0x02):   # SYN bit
            return

        dst_port = tcp.dport
        service  = config.BRUTE_FORCE_PORTS.get(dst_port)
        if service is None:
            return

        src = _src_ip(packet)
        if src is None:
            return

        key   = (src, dst_port)
        count = self._win.add(key)

        if count >= config.BRUTE_FORCE_THRESHOLD:
            alerter.alert(
                alert_type = f"brute_force_{service.lower()}",
                title      = f"Brute-force on {service} from {src}",
                detail     = (
                    f"Source IP  : {src}\n"
                    f"Service    : {service} (port {dst_port})\n"
                    f"Attempts in last {config.BRUTE_FORCE_WINDOW}s: {count}\n"
                    f"Threshold  : {config.BRUTE_FORCE_THRESHOLD}"
                ),
                severity   = "CRITICAL",
            )


# ---------------------------------------------------------------------------
# 3. ARP-spoofing detector
# ---------------------------------------------------------------------------

class ARPSpoofDetector:
    """
    Detects ARP spoofing / poisoning.

    Maintains a ground-truth IP → MAC table.  Any packet that claims an
    IP address belongs to a *different* MAC than previously observed triggers
    an alert.
    """

    def __init__(self):
        self._table: Dict[str, str] = {}   # ip → mac
        self._lock  = threading.Lock()

    def check(self, packet) -> None:
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # Only inspect ARP replies (op=2) and requests (op=1)
        if arp.op not in (1, 2):
            return

        ip  = arp.psrc
        mac = arp.hwsrc.lower()

        if not ip or ip == "0.0.0.0":
            return

        with self._lock:
            known_mac = self._table.get(ip)

            if known_mac is None:
                self._table[ip] = mac
                if config.ARP_ALERT_NEW_HOSTS:
                    alerter.alert(
                        alert_type = "arp_new_host",
                        title      = f"New ARP host: {ip}",
                        detail     = f"IP: {ip}  MAC: {mac}",
                        severity   = "WARNING",
                    )
                return

            if known_mac != mac:
                alerter.alert(
                    alert_type = "arp_spoof",
                    title      = f"ARP spoofing detected for {ip}",
                    detail     = (
                        f"IP address : {ip}\n"
                        f"Known MAC  : {known_mac}\n"
                        f"Claimed MAC: {mac}\n"
                        f"Possible man-in-the-middle attack."
                    ),
                    severity   = "CRITICAL",
                )
                # Update table so we don't spam for every subsequent packet
                self._table[ip] = mac


# ---------------------------------------------------------------------------
# 4. DoS / flood detector
# ---------------------------------------------------------------------------

class DoSDetector:
    """
    Detects volumetric DoS floods.

    Triggers when a single source IP sends more than DOS_THRESHOLD packets
    within DOS_WINDOW seconds (default: 300 pkt/s).
    """

    def __init__(self):
        self._win = _CountWindow(config.DOS_WINDOW)

    def check(self, packet) -> None:
        src = _src_ip(packet)
        if src is None:
            return

        count = self._win.add(src)

        if count >= config.DOS_THRESHOLD:
            # Determine dominant protocol for the alert
            proto = "?"
            for p in ("ICMP", "UDP", "TCP", "Raw"):
                if packet.haslayer(p):
                    proto = p
                    break

            alerter.alert(
                alert_type = "dos_flood",
                title      = f"DoS flood from {src}",
                detail     = (
                    f"Source IP  : {src}\n"
                    f"Protocol   : {proto}\n"
                    f"Rate       : {count} pkt / {config.DOS_WINDOW}s\n"
                    f"Threshold  : {config.DOS_THRESHOLD}"
                ),
                severity   = "CRITICAL",
            )


# ---------------------------------------------------------------------------
# 5. DNS anomaly detector (tunneling + high-rate)
# ---------------------------------------------------------------------------

class DNSAnomalyDetector:
    """
    Detects DNS tunneling and unusually high DNS query rates.

    Checks:
      (a) Subdomain label length > DNS_LABEL_MAX_LEN
      (b) Shannon entropy of the subdomain > DNS_ENTROPY_THRESHOLD
      (c) Suspicious TLD (.tk, .xyz, …)
      (d) Query rate from one IP > DNS_RATE_THRESHOLD in DNS_RATE_WINDOW seconds
    """

    def __init__(self):
        self._rate_win = _CountWindow(config.DNS_RATE_WINDOW)

    def check(self, packet) -> None:
        if not packet.haslayer(DNS):
            return

        dns = packet[DNS]

        # Only inspect queries (qr == 0)
        if dns.qr != 0:
            return

        src = _src_ip(packet)
        if src is None:
            return

        # --- Rate check ---
        rate = self._rate_win.add(src)
        if rate >= config.DNS_RATE_THRESHOLD:
            alerter.alert(
                alert_type = "dns_high_rate",
                title      = f"High DNS query rate from {src}",
                detail     = (
                    f"Source IP  : {src}\n"
                    f"Queries in last {config.DNS_RATE_WINDOW}s: {rate}\n"
                    f"Threshold  : {config.DNS_RATE_THRESHOLD}"
                ),
                severity   = "WARNING",
            )

        # --- Per-query payload analysis ---
        if not packet.haslayer(DNSQR):
            return

        try:
            qname = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            return

        labels = qname.split(".")
        tld    = f".{labels[-1]}" if labels else ""

        # Check each label (subdomain part)
        for label in labels[:-2]:   # skip the registered domain and TLD
            label_len = len(label)
            entropy   = _shannon_entropy(label)

            reasons = []
            if label_len > config.DNS_LABEL_MAX_LEN:
                reasons.append(f"label length {label_len} > {config.DNS_LABEL_MAX_LEN}")
            if entropy > config.DNS_ENTROPY_THRESHOLD:
                reasons.append(f"entropy {entropy:.2f} > {config.DNS_ENTROPY_THRESHOLD}")

            if reasons:
                alerter.alert(
                    alert_type = "dns_tunneling",
                    title      = f"Possible DNS tunneling from {src}",
                    detail     = (
                        f"Source IP  : {src}\n"
                        f"Query      : {qname}\n"
                        f"Suspicious label: '{label}'\n"
                        f"Reason(s)  : {', '.join(reasons)}"
                    ),
                    severity   = "WARNING",
                )
                break   # one alert per packet is enough

        # Check suspicious TLD
        if tld.lower() in config.SUSPICIOUS_TLDS:
            alerter.alert(
                alert_type = "dns_suspicious_tld",
                title      = f"DNS query to suspicious TLD '{tld}' from {src}",
                detail     = (
                    f"Source IP  : {src}\n"
                    f"Query      : {qname}\n"
                    f"TLD        : {tld}"
                ),
                severity   = "WARNING",
            )


# ---------------------------------------------------------------------------
# Detector registry  (used by ids.py)
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    PortScanDetector(),
    BruteForceDetector(),
    ARPSpoofDetector(),
    DoSDetector(),
    DNSAnomalyDetector(),
]
