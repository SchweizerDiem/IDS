"""
raspberry-ids / ids.py
======================
Entry-point for the Intrusion Detection System.

Responsibilities
----------------
1. Auto-select the most active network interface (re-uses your mini-shark logic).
2. Start a Scapy sniff loop and pass every packet through all detectors.
3. Handle SIGTERM / SIGINT gracefully (for systemd compatibility).
4. Print a live packet summary to stdout (visible in journalctl).

Run manually:
    sudo ./venv/bin/python ids.py

Run as a service:
    sudo systemctl start raspberry-ids
"""

import os
import signal
import sys
import time
import threading

from scapy.all import sniff, get_if_list

import config
import alerter
from detectors import ALL_DETECTORS

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
 ____      _    ____  ____  ____  ____  ______   __  ___ ____  ____
|  _ \    / \  / ___||  _ \| __ )| ___||  _ \ \ / / |_ _|  _ \/ ___|
| |_) |  / _ \ \___ \| |_) |  _ \|___ \| |_) \ V /   | || | | \___ \
|  _ <  / ___ \ ___) |  __/| |_) |___) |  __/ | |    | || |_| |___) |
|_| \_\/_/   \_\____/|_|   |____/|____/|_|    |_|   |___|____/|____/

              Raspberry Pi IDS — starting up …
"""

# ---------------------------------------------------------------------------
# Interface selection  (borrowed & extended from your mini-shark)
# ---------------------------------------------------------------------------

def _list_interfaces():
    return sorted(get_if_list())


def _auto_select_interface(scan_time: int = 3) -> str | None:
    """Sniff briefly on each interface and return the busiest one."""
    interfaces = _list_interfaces()
    counts     = {}

    alerter.log_info(f"Probing {len(interfaces)} interface(s) for {scan_time}s each …")

    for iface in interfaces:
        try:
            pkts = sniff(iface=iface, timeout=scan_time, store=True)
            counts[iface] = len(pkts)
        except Exception:
            counts[iface] = 0

    if not counts:
        return None

    best = max(counts, key=counts.get)
    alerter.log_info(f"Interface traffic counts: {counts}")
    alerter.log_info(f"Selected interface: {best} ({counts[best]} packets sampled)")
    return best


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

_packet_count = 0
_packet_lock  = threading.Lock()


def _on_packet(packet) -> None:
    global _packet_count

    with _packet_lock:
        _packet_count += 1

    # Run every registered detector
    for detector in ALL_DETECTORS:
        try:
            detector.check(packet)
        except Exception as exc:
            alerter.log_warning(
                f"Detector {detector.__class__.__name__} raised: {exc}"
            )


# ---------------------------------------------------------------------------
# Stats printer  (runs in a background thread)
# ---------------------------------------------------------------------------

def _stats_printer(stop_event: threading.Event, interval: int = 60) -> None:
    """Print a one-line packet-count summary every `interval` seconds."""
    while not stop_event.wait(timeout=interval):
        with _packet_lock:
            count = _packet_count
        alerter.log_info(f"[Stats] Total packets processed: {count}")


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_stop_event = threading.Event()


def _handle_signal(signum, _frame) -> None:
    alerter.log_info(f"Received signal {signum} — shutting down …")
    _stop_event.set()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Only print banner when running interactively
    if sys.stdout.isatty():
        print(BANNER)

    # Root check
    if os.name == "posix" and os.geteuid() != 0:
        print("ERROR: packet capture requires root.  Run with sudo or as a service.")
        sys.exit(1)

    # Register signal handlers (SIGTERM is what systemd sends on stop)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    alerter.log_info("Raspberry Pi IDS starting …")

    # --- Choose interface ---
    iface = config.INTERFACE
    if iface is None:
        iface = _auto_select_interface(scan_time=config.INTERFACE_SCAN_TIME)

    if iface is None:
        alerter.log_critical("Could not determine a network interface.  Exiting.")
        sys.exit(1)

    alerter.log_info(f"Listening on interface: {iface}")
    alerter.log_info(
        f"Active detectors: {', '.join(d.__class__.__name__ for d in ALL_DETECTORS)}"
    )

    # --- Stats background thread ---
    stats_thread = threading.Thread(
        target=_stats_printer,
        args=(_stop_event, 60),
        daemon=True,
        name="stats-printer",
    )
    stats_thread.start()

    # --- Sniff loop ---
    try:
        sniff(
            iface  = iface,
            prn    = _on_packet,
            store  = False,                              # never buffer packets in RAM
            stop_filter = lambda _: _stop_event.is_set(),
        )
    except PermissionError:
        alerter.log_critical("Permission denied — run with sudo.")
        sys.exit(1)
    except OSError as exc:
        alerter.log_critical(f"Cannot open interface '{iface}': {exc}")
        sys.exit(1)

    alerter.log_info("IDS stopped cleanly.")


if __name__ == "__main__":
    main()
