# Raspberry Pi IDS

A lightweight Intrusion Detection System built with Scapy, designed to run
continuously on a Raspberry Pi 3 as a `systemd` service.

## Detection engines

| Engine | Detects | Threshold (default) |
|---|---|---|
| `PortScanDetector` | Nmap / port scans | ≥ 15 distinct ports in 5 s |
| `BruteForceDetector` | SSH / FTP / Telnet / RDP brute-force | ≥ 10 SYN attempts in 30 s |
| `ARPSpoofDetector` | ARP spoofing / MITM | Any IP→MAC change |
| `DoSDetector` | Volumetric flood (any protocol) | ≥ 300 pkt/s from one IP |
| `DNSAnomalyDetector` | DNS tunneling + high query rate | Label length, entropy, TLD |

## File layout

```
raspberry-ids/
├── config.py          ← tune thresholds and e-mail settings here
├── alerter.py         ← file logging + rate-limited e-mail
├── detectors.py       ← all 5 detection engines
├── ids.py             ← main entry-point / sniff loop
├── ids.service        ← systemd unit file
├── requirements.txt
└── README.md
```

## Installation on Raspberry Pi

### 1 — Copy files

```bash
sudo mkdir -p /opt/raspberry-ids
sudo cp -r ./* /opt/raspberry-ids/
```

### 2 — Create a virtual environment

```bash
cd /opt/raspberry-ids
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt
```

### 3 — Create the log directory

```bash
sudo mkdir -p /var/log/raspberry-ids
```

### 4 — Configure e-mail credentials

Create a secrets file readable only by root:

```bash
sudo mkdir -p /etc/raspberry-ids
sudo nano /etc/raspberry-ids/secrets.env
```

Paste (replacing with your actual App Password):

```
IDS_EMAIL_PASSWORD=xxxx xxxx xxxx xxxx
```

Lock it down:

```bash
sudo chmod 600 /etc/raspberry-ids/secrets.env
sudo chown root:root /etc/raspberry-ids/secrets.env
```

> **Gmail tip:** Log in at https://myaccount.google.com/apppasswords and
> generate an App Password for "Mail" on "Other device".  Use that 16-char
> password — your normal Gmail password won't work with SMTP.

### 5 — Edit the service unit file

Open `ids.service` and update:
- `WorkingDirectory` and `ExecStart` paths if you changed the install location.
- `IDS_EMAIL_FROM` (the Gmail address the IDS will send from).
- `IDS_EMAIL_TO` (where alerts should be delivered).

### 6 — Install and start the service

```bash
sudo cp /opt/raspberry-ids/ids.service /etc/systemd/system/raspberry-ids.service
sudo systemctl daemon-reload
sudo systemctl enable raspberry-ids   # auto-start on boot
sudo systemctl start raspberry-ids
```

### 7 — Check it's running

```bash
sudo systemctl status raspberry-ids
```

### 8 — Watch live logs

```bash
sudo journalctl -u raspberry-ids -f
```

Or tail the file directly:

```bash
tail -f /var/log/raspberry-ids/ids.log
```

## Tuning thresholds

All thresholds live in `config.py`.  Edit and then restart the service:

```bash
sudo nano /opt/raspberry-ids/config.py
sudo systemctl restart raspberry-ids
```

Key values to adjust for a quieter home network:

```python
PORT_SCAN_THRESHOLD   = 15   # lower = more sensitive
BRUTE_FORCE_THRESHOLD = 10
DOS_THRESHOLD         = 300  # pkt/s
DNS_RATE_THRESHOLD    = 80   # queries/10 s
EMAIL_COOLDOWN        = 60   # seconds between duplicate e-mails
```

## Running manually (for testing)

```bash
cd /opt/raspberry-ids
sudo ./venv/bin/python ids.py
```

## Stopping the service

```bash
sudo systemctl stop raspberry-ids
```
