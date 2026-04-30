"""
raspberry-ids / config.py
=========================
Edit this file to tune thresholds and set your credentials.
Sensitive values (passwords) are read from environment variables so they
never have to be hard-coded.
"""

import os

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
INTERFACE = None          # None → auto-detect most-active interface at startup
INTERFACE_SCAN_TIME = 3   # seconds spent probing each iface to find the busiest

# ---------------------------------------------------------------------------
# Port-scan detection
# ---------------------------------------------------------------------------
PORT_SCAN_WINDOW     = 5   # sliding window in seconds
PORT_SCAN_THRESHOLD  = 15  # distinct destination ports from one IP in the window

# ---------------------------------------------------------------------------
# Brute-force detection  (SSH, FTP, Telnet, RDP …)
# ---------------------------------------------------------------------------
BRUTE_FORCE_WINDOW      = 30  # seconds
BRUTE_FORCE_THRESHOLD   = 10  # connection attempts to a sensitive port

BRUTE_FORCE_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    3389: "RDP",
}

# ---------------------------------------------------------------------------
# DoS / flood detection
# ---------------------------------------------------------------------------
DOS_WINDOW     = 1    # seconds  (per-second rate)
DOS_THRESHOLD  = 300  # packets from a single source IP per second

# ---------------------------------------------------------------------------
# ARP-spoofing detection
# ---------------------------------------------------------------------------
# Any change in the IP → MAC mapping table is treated as suspicious.
# Set to True to also alert on new (first-seen) IP/MAC pairs.
ARP_ALERT_NEW_HOSTS = False

# ---------------------------------------------------------------------------
# DNS anomaly detection
# ---------------------------------------------------------------------------
DNS_LABEL_MAX_LEN       = 52   # label (subdomain part) length that triggers alert
DNS_RATE_WINDOW         = 10   # seconds
DNS_RATE_THRESHOLD      = 80   # queries from a single IP in the window
DNS_ENTROPY_THRESHOLD   = 3.8  # Shannon entropy of subdomain label (tunneling → high)

SUSPICIOUS_TLDS = {".tk", ".xyz", ".top", ".ml", ".ga", ".cf", ".gq"}

# ---------------------------------------------------------------------------
# Alerting — log file
# ---------------------------------------------------------------------------
LOG_DIR  = "/var/log/raspberry-ids"
LOG_FILE = os.path.join(LOG_DIR, "ids.log")

# ---------------------------------------------------------------------------
# Alerting — e-mail
# ---------------------------------------------------------------------------
EMAIL_ENABLED  = True

# Credentials are read from environment variables.
# Set them before starting the service (see the README / systemd unit file).
SMTP_SERVER    = "smtp.gmail.com"
SMTP_PORT      = 587
EMAIL_FROM     = os.environ.get("IDS_EMAIL_FROM",     "your_ids@gmail.com")
EMAIL_PASSWORD = os.environ.get("IDS_EMAIL_PASSWORD", "")
EMAIL_TO       = os.environ.get("IDS_EMAIL_TO",       "you@example.com")

# Minimum seconds between e-mails for the *same alert type*.
# Prevents inbox flooding during an ongoing attack.
EMAIL_COOLDOWN    = 60
EMAIL_QUEUE_SIZE  = 100  # max queued alerts before dropping
