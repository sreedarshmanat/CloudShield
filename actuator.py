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
      - Linux   → iptables  (OUTPUT chain, DROP)
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
        Execute a firewall command to DROP outbound traffic to `target_ip`.

        Returns:
            True if the rule was applied successfully, False otherwise.
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
        Append an iptables OUTPUT DROP rule for the target IP.

        Requires root / sudo. The rule is appended (not inserted), so
        it will be evaluated after any existing rules. For production,
        consider inserting at the top of the chain.
        """
        comment = f"cloudshield-block-{target_ip}"
        cmd = [
            "sudo", "iptables",
            "-I", "OUTPUT","1",
            "-d", target_ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", comment,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            if result.returncode == 0:
                logger.info("[LINUX] iptables DROP applied for %s", target_ip)
                return True
            stderr = result.stderr.strip()
            # Detect common privilege errors
            if "permission" in stderr.lower() or "sudo" in stderr.lower():
                logger.error("[LINUX] Permission denied — run with sudo or configure sudoers NOPASSWD")
            else:
                logger.error("[LINUX] iptables failed (rc=%d): %s", result.returncode, stderr)
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
        """
        Add a netsh advfirewall outbound block rule for the target IP.

        Requires Administrator privileges. The rule name includes the IP
        so it can be uniquely identified and removed later.
        """
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
        """
        Add the target IP to a pf(4) table called `cloudshield_blocked`.

        Requires root. The table must be referenced in a pf.conf anchor rule
        for this to take effect. For hackathon scope, we add to the table
        and log a reminder about pf.conf.
        """
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
    """
    Daemon thread that accumulates alerts in a bounded deque and flushes
    them as a single JSON batch to the Node.js backend every N seconds.

    Key properties:
      - deque(maxlen=50): When an item is appended to a full deque, the
        *oldest* item is automatically evicted (FIFO). This is our memory
        cap — no alert queue can ever exceed 50 items in RAM.
      - threading.Lock: Protects the deque for concurrent access from the
        sniffer main thread (enqueue) and this thread (drain/requeue).
      - Event.wait(): Replaces time.sleep() so the thread can be stopped
        promptly via stop().
      - Failed POSTs are re-queued; if the queue is full, oldest are dropped.
    """

    def __init__(self, backend_url: str = BACKEND_URL):
        super().__init__(daemon=True)
        self.backend_url = backend_url

        # Bounded deque — maxlen enforces automatic FIFO eviction
        self._queue: deque = deque(maxlen=QUEUE_MAX_SIZE)
        self._lock = threading.Lock()

        # Graceful shutdown signal (replaces bare time.sleep)
        self._stop_event = threading.Event()

        # Stats counters
        self._dispatched = 0
        self._dropped = 0

        self.name = "AlertBatchDispatcher"
        self._log = logging.getLogger("CloudShield.Dispatcher")

        self._log.info(
            "AlertBatchDispatcher ready | backend=%s | queue_cap=%d | flush=%ds",
            backend_url, QUEUE_MAX_SIZE, FLUSH_INTERVAL_SEC,
        )

    # ── Thread Lifecycle ────────────────────────────────────────

    def run(self) -> None:
        """Main loop: wait N seconds → drain → POST → repeat."""
        self._log.info("Dispatcher thread STARTED — entering flush loop")
        while not self._stop_event.is_set():
            # Event.wait() blocks but wakes immediately on stop() signal
            self._stop_event.wait(timeout=FLUSH_INTERVAL_SEC)
            if self._stop_event.is_set():
                break
            self._flush()
        self._log.info("Dispatcher thread STOPPED")

    def stop(self) -> None:
        """Signal stop + perform one final flush to drain remaining alerts."""
        self._stop_event.set()
        self._flush()  # Best-effort final drain
        self._log.info(
            "Final dispatch stats | dispatched=%d | dropped=%d",
            self._dispatched, self._dropped,
        )

    # ── Queue Operations ────────────────────────────────────────

    def enqueue(self, alert: dict) -> bool:
        """
        Thread-safe, non-blocking enqueue.

        Returns True if the alert was added without eviction,
        False if the queue was full and the oldest alert was
        evicted (FIFO).
        """
        with self._lock:
            prev_len = len(self._queue)
            self._queue.append(alert)       # O(1) — may evict oldest
            if len(self._queue) <= prev_len:
                # Length didn't grow → deque was full → oldest evicted
                self._dropped += 1
                self._log.debug(
                    "Queue FULL (%d/%d) — oldest alert evicted (FIFO)",
                    QUEUE_MAX_SIZE, QUEUE_MAX_SIZE,
                )
                return False
            return True

    def _drain_queue(self) -> list:
        """Atomically extract and clear all queued alerts."""
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        return batch

    def _requeue_failed(self, batch: list) -> None:
        """
        Re-insert alerts that failed to POST. If the queue is full,
        deque(maxlen) automatically drops the oldest items (FIFO).
        """
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
        if evicted:
            self._log.warning(
                "Requeue: %d requeued, %d evicted (FIFO) | cumulative_dropped=%d",
                requeued, evicted, self._dropped,
            )

    # ── HTTP Flush ─────────────────────────────────────────────

    def _flush(self) -> None:
        """Drain queue and POST as a single JSON batch."""
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
                self._log.warning(
                    "Backend HTTP %d for batch of %d alert(s) — requeuing",
                    resp.status_code, len(batch),
                )
                self._requeue_failed(batch)

        except requests.exceptions.ConnectionError:
            self._log.warning(
                "Backend OFFLINE (%s) — requeuing %d alert(s)",
                self.backend_url, len(batch),
            )
            self._requeue_failed(batch)

        except requests.exceptions.Timeout:
            self._log.warning(
                "Backend TIMEOUT — requeuing %d alert(s)", len(batch),
            )
            self._requeue_failed(batch)

        except Exception as exc:
            self._log.error("Unexpected flush error: %s — requeuing", exc)
            self._requeue_failed(batch)

    # ── Stats ──────────────────────────────────────────────────

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
    """
    Singleton facade — the ONLY class the sensor should interact with.

    Usage:
        from actuator import get_actuator
        actuator = get_actuator()
        actuator.trigger("evil_twin", "critical", {"mac": "AA:BB:CC:DD:EE:FF"})
    """

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

    # ── Public API ─────────────────────────────────────────────

    def trigger(
        self,
        threat_type: str,
        severity: str,
        details: dict,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> None:
        """
        NON-BLOCKING trigger — safe to call from the tightest sniffing loop.

        What happens:
          1. Alert dict is appended to the bounded deque  (O(1), lock-protected).
          2. If severity is critical/high AND source_ip is known, a daemon
             thread is spawned to execute the firewall block command.
          3. This method returns immediately — no I/O on the calling thread.

        Args:
            threat_type: "evil_twin", "arp_spoof", "rogue_ap", etc.
            severity:    "critical", "high", "medium", "low"
            details:     Dict with MAC, BSSID, channel, packet info, etc.
            source_ip:   Attacker IP (used for firewall blocking).
            target_ip:   Victim IP (logged but not blocked).
        """
        # Build the alert payload with a UTC ISO-8601 timestamp
        alert = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "threat_type": threat_type,
            "severity":    severity,
            "details":     dict(details),  # defensive copy
            "source_ip":   source_ip,
            "target_ip":   target_ip,
        }

        # Step 1: Enqueue for batch logging (non-blocking, O(1))
        self.dispatcher.enqueue(alert)

        # Step 2: Asynchronous firewall block (spawn daemon thread)
        # Only block for critical/high severity with a known source IP
        if severity in ("critical", "high") and source_ip:
            threading.Thread(
                target=self._firewall_block_bg,
                args=(source_ip, threat_type),
                daemon=True,
            ).start()

    # ── Internal Helpers ───────────────────────────────────────

    def _firewall_block_bg(self, target_ip: str, threat_type: str) -> None:
        """Execute firewall block in a background daemon thread."""
        self._log.info(
            "Firewall block initiated for %s (threat=%s)", target_ip, threat_type,
        )
        success = self.firewall.block_ip(target_ip)
        if success:
            self._log.info("Firewall block SUCCESS → %s", target_ip)
        else:
            self._log.warning("Firewall block FAILED → %s", target_ip)

    # ── Lifecycle ─────────────────────────────────────────────

    def shutdown(self) -> None:
        """Gracefully shut down — final flush + stats dump."""
        self._log.info("CloudShieldActuator shutting down...")
        self.dispatcher.stop()
        self._log.info("Shutdown complete. Final stats: %s", self.dispatcher.stats())

    def get_stats(self) -> dict:
        return self.dispatcher.stats()


# ═══════════════════════════════════════════════════════════════
# 4. Global Convenience Accessor
# ═══════════════════════════════════════════════════════════════
_global_actuator: Optional[CloudShieldActuator] = None


def get_actuator() -> CloudShieldActuator:
    """
    Lazy singleton accessor — safe to call from any module.
    The actuator initializes once and the dispatcher thread
    starts on the first call.
    """
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
        print("[*] Alerts will flush in ~10s. Ctrl+C to exit.")

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

    # If no flags given, just print help and exit
    if not any([args.test_firewall, args.test_alerts, args.stats]):
        parser.print_help()

    actuator.shutdown()
