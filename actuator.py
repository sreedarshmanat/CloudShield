#!/usr/bin/env python3
"""
CloudShield HIDS — Actuator Module
====================================
Role: Systems Actuator — bridges threat detection (sensor) with the
      OS firewall (immediate block) and the Node.js backend (batch logging).

Design Principles:
  - Zero main-thread blocking: trigger() returns in O(1), all I/O in background.
  - Threaded batch queue: alerts collected in a bounded deque and flushed
    to the backend every 10 seconds via a single POST request.
  - Strict memory cap: deque(maxlen=50) guarantees FIFO eviction when full.
  - Cross-platform firewall: auto-detects OS and issues iptables / netsh commands.
  - Singleton pattern: one actuator per process, safe for repeated imports.

Author: Person 4 — Systems Actuator Team
"""

import platform
import subprocess
import threading
import time
import logging
import json
import requests  # pip install requests
from collections import deque
from datetime import datetime, timezone
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# Logging Configuration
# ═══════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("actuator.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("CloudShield.Actuator")


# ═══════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════
BACKEND_URL        = "http://localhost:3000/api/alert"
QUEUE_MAX_SIZE     = 50        # Hard cap on in-memory alert queue
FLUSH_INTERVAL_SEC = 10        # Seconds between batch flushes
FIREWALL_TIMEOUT   = 5         # Max seconds per firewall subprocess call
HTTP_TIMEOUT       = 8         # Max seconds per HTTP POST to backend


# ═══════════════════════════════════════════════════════════════
# 1. FirewallActuator — Cross-Platform Firewall Rule Injection
# ═══════════════════════════════════════════════════════════════
class FirewallActuator:
    """
    Detects the host OS at init time and exposes a single `block_ip()` method
    that executes the appropriate native firewall command.

    Supported platforms:
      - Linux   → iptables  (INPUT & OUTPUT chains, DROP)
      - Windows → netsh advfirewall (outbound block rule)
      - macOS   → pfctl     (table-based block)
    """

    LINUX   = "Linux"
    WINDOWS = "Windows"
    DARWIN  = "Darwin"
    UNKNOWN = "Unknown"

    def __init__(self):
        self.os_type = self._detect_os()
        logger.info("FirewallActuator initialized for OS: %s", self.os_type)

    # ── OS Detection ──────────────────────────────────────────

    @staticmethod
    def _detect_os() -> str:
        system = platform.system()
        mapping = {
            "Linux": FirewallActuator.LINUX,
            "Windows": FirewallActuator.WINDOWS,
            "Darwin": FirewallActuator.DARWIN,
        }
        return mapping.get(system, FirewallActuator.UNKNOWN)

    # ── Public API ──────────────────────────────────────────────

    def block_ip(self, target_ip: str) -> bool:
        """
        Execute firewall commands to DROP traffic to/from `target_ip`.

        Returns:
            True if the rules were applied successfully, False otherwise.
        """
        dispatcher = {
            self.LINUX:   self._block_linux,
            self.WINDOWS: self._block_windows,
            self.DARWIN:  self._block_macos,
        }
        handler = dispatcher.get(self.os_type)
        if handler is None:
            logger.warning(
                "Unsupported OS '%s' — firewall block skipped for %s",
                self.os_type, target_ip,
            )
            return False
        return handler(target_ip)

    # ── Linux (iptables) ──────────────────────────────────────

    def _block_linux(self, target_ip: str) -> bool:
        """
        Insert bi-directional iptables DROP rules (INPUT -s and OUTPUT -d)
        for the target IP to guarantee complete blocking.
        """
        comment = f"cloudshield-block-{target_ip}"
        
        # Rule 1: Drop incoming packets from the threat IP
        cmd_in = [
            "sudo", "iptables",
            "-I", "INPUT", "1",
            "-s", target_ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", comment,
        ]
        
        # Rule 2: Drop outgoing packets to the threat IP (for ping/connection tests)
        cmd_out = [
            "sudo", "iptables",
            "-I", "OUTPUT", "1",
            "-d", target_ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", comment,
        ]

        try:
            res_in = subprocess.run(cmd_in, capture_output=True, text=True, timeout=FIREWALL_TIMEOUT)
            res_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=FIREWALL_TIMEOUT)

            if res_in.returncode == 0 and res_out.returncode == 0:
                logger.info("[LINUX] Bi-directional iptables DROP applied for %s", target_ip)
                return True
            
            stderr = res_in.stderr.strip() or res_out.stderr.strip()
            if "permission" in stderr.lower() or "sudo" in stderr.lower():
                logger.error("[LINUX] Permission denied — run with sudo or configure sudoers NOPASSWD")
            else:
                logger.error("[LINUX] iptables failed: %s", stderr)
            return False

        except subprocess.TimeoutExpired:
            logger.error("[LINUX] iptables command timed out for %s", target_ip)
            return False
        except FileNotFoundError:
            logger.error("[LINUX] iptables binary not found — is iptables installed?")
            return False
        except PermissionError:
            logger.error("[LINUX] OS-level permission denied — elevate privileges")
            return False
        except Exception as exc:
            logger.error("[LINUX] Unexpected error blocking %s: %s", target_ip, exc)
            return False

    # ── Windows (netsh advfirewall) ────────────────────────────

    def _block_windows(self, target_ip: str) -> bool:
        rule_name = f"CloudShield Block {target_ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            "protocol=any",
            f"remoteip={target_ip}",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            if result.returncode == 0:
                logger.info("[WINDOWS] netsh block rule applied for %s", target_ip)
                return True
            stderr = result.stderr.strip()
            if "denied" in stderr.lower() or "administrator" in stderr.lower():
                logger.error("[WINDOWS] Access denied — run as Administrator")
            else:
                logger.error("[WINDOWS] netsh failed (rc=%d): %s", result.returncode, stderr)
            return False

        except subprocess.TimeoutExpired:
            logger.error("[WINDOWS] netsh command timed out for %s", target_ip)
            return False
        except PermissionError:
            logger.error("[WINDOWS] OS-level permission denied — run as Administrator")
            return False
        except FileNotFoundError:
            logger.error("[WINDOWS] netsh binary not found — is this a valid Windows install?")
            return False
        except Exception as exc:
            logger.error("[WINDOWS] Unexpected error blocking %s: %s", target_ip, exc)
            return False

    # ── macOS (pfctl) ─────────────────────────────────────────

    def _block_macos(self, target_ip: str) -> bool:
        add_cmd = [
            "sudo", "pfctl", "-t", "cloudshield_blocked", "-T", "add", target_ip,
        ]
        try:
            result = subprocess.run(
                add_cmd, capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            if result.returncode == 0:
                logger.info("[MACOS] pfctl table add for %s", target_ip)
                return True
            stderr = result.stderr.strip()
            logger.error("[MACOS] pfctl failed (rc=%d): %s", result.returncode, stderr)
            return False

        except subprocess.TimeoutExpired:
            logger.error("[MACOS] pfctl timed out for %s", target_ip)
            return False
        except PermissionError:
            logger.error("[MACOS] Permission denied — run with sudo")
            return False
        except FileNotFoundError:
            logger.error("[MACOS] pfctl not found — macOS packet filter unavailable")
            return False
        except Exception as exc:
            logger.error("[MACOS] Unexpected error blocking %s: %s", target_ip, exc)
            return False


# ═══════════════════════════════════════════════════════════════
# 2. AlertBatchDispatcher — Background Threaded Batch Queue
# ═══════════════════════════════════════════════════════════════
class AlertBatchDispatcher(threading.Thread):
    def __init__(self, backend_url: str = BACKEND_URL):
        super().__init__(daemon=True)
        self.backend_url = backend_url
        self._queue: deque = deque(maxlen=QUEUE_MAX_SIZE)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._dispatched = 0
        self._dropped = 0
        self.name = "AlertBatchDispatcher"
        self._log = logging.getLogger("CloudShield.Dispatcher")

        self._log.info(
            "AlertBatchDispatcher ready | backend=%s | queue_cap=%d | flush=%ds",
            backend_url, QUEUE_MAX_SIZE, FLUSH_INTERVAL_SEC,
        )

    def run(self) -> None:
        self._log.info("Dispatcher thread STARTED — entering flush loop")
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=FLUSH_INTERVAL_SEC)
            if self._stop_event.is_set():
                break
            self._flush()
        self._log.info("Dispatcher thread STOPPED")

    def stop(self) -> None:
        self._stop_event.set()
        self._flush()
        self._log.info(
            "Final dispatch stats | dispatched=%d | dropped=%d",
            self._dispatched, self._dropped,
        )

    def enqueue(self, alert: dict) -> bool:
        with self._lock:
            prev_len = len(self._queue)
            self._queue.append(alert)
            if len(self._queue) <= prev_len:
                self._dropped += 1
                return False
            return True

    def _drain_queue(self) -> list:
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        return batch

    def _requeue_failed(self, batch: list) -> None:
        requeued = 0
        evicted = 0
        with self._lock:
            for alert in batch:
                prev_len = len(self._queue)
                self._queue.append(alert)
                if len(self._queue) <= prev_len:
                    evicted += 1
                else:
                    requeued += 1
        self._dropped += evicted

    def _flush(self) -> None:
        batch = self._drain_queue()
        if not batch:
            return

        payload = {"alerts": batch}

        try:
            resp = requests.post(
                self.backend_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=HTTP_TIMEOUT,
            )

            if resp.status_code in (200, 201, 202):
                self._dispatched += len(batch)
                self._log.info(
                    "Flush OK | %d alert(s) → %s [HTTP %d] | total_sent=%d",
                    len(batch), self.backend_url, resp.status_code, self._dispatched,
                )
            else:
                self._requeue_failed(batch)

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            self._requeue_failed(batch)
        except Exception:
            self._requeue_failed(batch)

    def queue_size(self) -> int:
        with self._lock:
            return len(self._queue)

    def stats(self) -> dict:
        return {
            "queue_size": self.queue_size(),
            "queue_max": QUEUE_MAX_SIZE,
            "total_dispatched": self._dispatched,
            "total_dropped": self._dropped,
            "backend_url": self.backend_url,
        }


# ═══════════════════════════════════════════════════════════════
# 3. CloudShieldActuator — Main Facade (Singleton)
# ═══════════════════════════════════════════════════════════════
class CloudShieldActuator:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, backend_url: str = BACKEND_URL, auto_start: bool = True):
        if self._initialized:
            return
        self._initialized = True

        self.firewall   = FirewallActuator()
        self.dispatcher = AlertBatchDispatcher(backend_url=backend_url)
        self._log       = logging.getLogger("CloudShield.Actuator")

        if auto_start:
            self.dispatcher.start()
            self._log.info("CloudShieldActuator READY — dispatcher running")

    def trigger(
        self,
        threat_type: str,
        severity: str,
        details: dict,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> None:
        alert = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "threat_type": threat_type,
            "severity":    severity,
            "details":     dict(details),
            "source_ip":   source_ip,
            "target_ip":   target_ip,
        }

        self.dispatcher.enqueue(alert)

        if severity in ("critical", "high", "CRITICAL", "HIGH") and source_ip:
            threading.Thread(
                target=self._firewall_block_bg,
                args=(source_ip, threat_type),
                daemon=True,
            ).start()

    def _firewall_block_bg(self, target_ip: str, threat_type: str) -> None:
        self._log.info(
            "Firewall block initiated for %s (threat=%s)", target_ip, threat_type,
        )
        success = self.firewall.block_ip(target_ip)
        if success:
            self._log.info("Firewall block SUCCESS → %s", target_ip)
        else:
            self._log.warning("Firewall block FAILED → %s", target_ip)

    def shutdown(self) -> None:
        self._log.info("CloudShieldActuator shutting down...")
        self.dispatcher.stop()

    def get_stats(self) -> dict:
        return self.dispatcher.stats()


# ═══════════════════════════════════════════════════════════════
# 4. Global Convenience Accessor
# ═══════════════════════════════════════════════════════════════
_global_actuator: Optional[CloudShieldActuator] = None


def get_actuator() -> CloudShieldActuator:
    global _global_actuator
    if _global_actuator is None:
        _global_actuator = CloudShieldActuator(auto_start=True)
    return _global_actuator


# ═══════════════════════════════════════════════════════════════
# 5. CLI / Standalone Test Mode
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CloudShield Actuator — standalone test harness"
    )
    parser.add_argument(
        "--test-firewall", metavar="IP",
        help="Test firewall block for the given IP address",
    )
    parser.add_argument(
        "--test-alerts", type=int, default=0, metavar="N",
        help="Inject N test alerts into the batch queue",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Live dashboard of dispatcher stats (Ctrl+C to exit)",
    )
    args = parser.parse_args()

    actuator = get_actuator()

    if args.test_firewall:
        ip = args.test_firewall
        print(f"[*] Testing firewall block for {ip} ...")
        ok = actuator.firewall.block_ip(ip)
        print(f"[*] Result: {'SUCCESS' if ok else 'FAILED'}")

    if args.test_alerts > 0:
        n = args.test_alerts
        print(f"[*] Injecting {n} test alerts ...")
        for i in range(n):
            actuator.trigger(
                threat_type="test_evil_twin",
                severity="high" if i % 3 == 0 else "medium",
                details={
                    "test_run": True,
                    "seq": i,
                    "attacker_mac": f"AA:BB:CC:DD:{i:02X}:FF",
                    "ssid": f"TestNetwork-{i}",
                },
                source_ip=f"192.168.1.{100 + i}",
            )
        print(f"[*] Queue depth: {actuator.get_stats()['queue_size']}")

    if args.stats:
        try:
            while True:
                s = actuator.get_stats()
                print(
                    f"\r  queue={s['queue_size']}/{s['queue_max']}  |  "
                    f"sent={s['total_dispatched']}  |  "
                    f"dropped={s['total_dropped']}  ",
                    end="", flush=True,
                )
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    if not any([args.test_firewall, args.test_alerts, args.stats]):
        parser.print_help()

    actuator.shutdown()