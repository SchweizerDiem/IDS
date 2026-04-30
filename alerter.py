"""
raspberry-ids / alerter.py
==========================
Thread-safe alerting:
  • Writes structured lines to LOG_FILE.
  • Sends e-mail notifications via a background worker thread.
  • Rate-limits e-mail per alert type so a flood attack doesn't flood your inbox.
"""

import logging
import os
import queue
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

import config

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_file_logger() -> logging.Logger:
    os.makedirs(config.LOG_DIR, exist_ok=True)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(config.LOG_FILE)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()          # also echo to console
    ch.setFormatter(fmt)

    logger = logging.getLogger("raspberry-ids")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


_logger = _setup_file_logger()


# ---------------------------------------------------------------------------
# Public logging helpers
# ---------------------------------------------------------------------------

def log_info(msg: str) -> None:
    _logger.info(msg)


def log_warning(msg: str) -> None:
    _logger.warning(msg)


def log_critical(msg: str) -> None:
    _logger.critical(msg)


# ---------------------------------------------------------------------------
# E-mail worker
# ---------------------------------------------------------------------------

class _EmailWorker(threading.Thread):
    """
    Background daemon that drains an alert queue and sends e-mails.
    Per-alert-type cooldown prevents inbox flooding.
    """

    def __init__(self):
        super().__init__(daemon=True, name="email-worker")
        self._queue: queue.Queue = queue.Queue(maxsize=config.EMAIL_QUEUE_SIZE)
        self._last_sent: dict[str, float] = {}   # alert_type → timestamp
        self._lock = threading.Lock()

    def enqueue(self, alert_type: str, subject: str, body: str) -> None:
        """Non-blocking enqueue; drops silently if the queue is full."""
        try:
            self._queue.put_nowait((alert_type, subject, body))
        except queue.Full:
            _logger.warning("[Alerter] E-mail queue full — alert dropped: %s", subject)

    def run(self) -> None:
        while True:
            try:
                alert_type, subject, body = self._queue.get(timeout=5)
                self._maybe_send(alert_type, subject, body)
            except queue.Empty:
                continue
            except Exception as exc:
                _logger.error("[Alerter] E-mail worker error: %s", exc)

    def _maybe_send(self, alert_type: str, subject: str, body: str) -> None:
        now = time.time()
        with self._lock:
            last = self._last_sent.get(alert_type, 0)
            if now - last < config.EMAIL_COOLDOWN:
                _logger.debug(
                    "[Alerter] E-mail suppressed (cooldown) for type '%s'", alert_type
                )
                return
            self._last_sent[alert_type] = now

        self._send(subject, body)

    @staticmethod
    def _send(subject: str, body: str) -> None:
        if not config.EMAIL_PASSWORD:
            _logger.warning(
                "[Alerter] EMAIL_PASSWORD not set — skipping e-mail: %s", subject
            )
            return

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[IDS ALERT] {subject}"
            msg["From"]    = config.EMAIL_FROM
            msg["To"]      = config.EMAIL_TO
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.login(config.EMAIL_FROM, config.EMAIL_PASSWORD)
                smtp.sendmail(config.EMAIL_FROM, config.EMAIL_TO, msg.as_string())

            _logger.info("[Alerter] E-mail sent: %s", subject)

        except Exception as exc:
            _logger.error("[Alerter] Failed to send e-mail: %s", exc)


# ---------------------------------------------------------------------------
# Singleton worker — started once at import time
# ---------------------------------------------------------------------------
_worker = _EmailWorker()
_worker.start()


# ---------------------------------------------------------------------------
# Public alert function
# ---------------------------------------------------------------------------

def alert(
    alert_type: str,
    title: str,
    detail: str,
    severity: str = "WARNING",
) -> None:
    """
    Unified alert entry-point.

    Parameters
    ----------
    alert_type : str
        Short identifier, e.g. "port_scan", "brute_force_ssh".
        Used for e-mail cooldown grouping and log prefix.
    title : str
        One-line summary shown in the log and e-mail subject.
    detail : str
        Full detail written to the log and e-mail body.
    severity : str
        "WARNING" or "CRITICAL".
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line  = f"[{alert_type.upper()}] {title} | {detail}"

    if severity == "CRITICAL":
        log_critical(log_line)
    else:
        log_warning(log_line)

    if config.EMAIL_ENABLED:
        body = (
            f"Raspberry Pi IDS — Alert\n"
            f"{'=' * 44}\n"
            f"Time      : {timestamp}\n"
            f"Type      : {alert_type}\n"
            f"Severity  : {severity}\n"
            f"Title     : {title}\n"
            f"\nDetail:\n{detail}\n"
        )
        _worker.enqueue(alert_type, title, body)
