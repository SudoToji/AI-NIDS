"""
⚠️  EDUCATIONAL USE ONLY — Run exclusively in isolated lab environments.
     Never use on real networks or public infrastructure.

src/backend/alert_manager.py
==============================
Alert Manager for AI-NIDS (AI-Driven Network Intrusion Detection System).

Responsibilities:
  - Receive alert dicts from HybridPredictor and store them persistently
  - Write all alerts to a SQLite database (alerts.db)
  - Keep the last 500 alerts in an in-memory deque for fast dashboard reads
  - Support IP blocking (writes to a blocked_ips table in SQLite)
  - Export all alerts to a CSV file on demand
  - Expose query methods for the Streamlit dashboard

Usage:
    manager = AlertManager(db_path="logs/alerts.db")
    manager.add_alert(prediction_dict)
    recent = manager.get_recent_alerts(n=50)
    top = manager.get_top_attackers(n=10)
    dist = manager.get_attack_distribution()
    manager.block_ip("1.2.3.4")
    manager.export_csv("logs/export.csv")
"""

# ── Standard library ──────────────────────────────────────────────────────────
import csv
import logging
import os
import sqlite3
import threading
from collections import deque, Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────
# Maximum number of alerts kept in the fast in-memory cache.
# The dashboard reads from here instead of hitting SQLite every time.
DEQUE_MAX_SIZE: int = 500

# Default path for the SQLite database file.
DEFAULT_DB_PATH: str = os.environ.get("ALERTS_DB_PATH", "logs/alerts.db")

# Configure module-level logger.
# In production code we NEVER use print(); we use logging instead.
logger = logging.getLogger(__name__)


# ── Database schema SQL ───────────────────────────────────────────────────────
# Written as constants so they are easy to read and change in one place.

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    src_ip              TEXT    NOT NULL,
    dst_ip              TEXT    NOT NULL,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            INTEGER,
    rf_label            TEXT,
    rf_confidence       REAL,
    ae_score            REAL,
    final_verdict       TEXT    NOT NULL,
    combined_confidence REAL
);
"""

CREATE_BLOCKED_IPS_TABLE = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT    NOT NULL UNIQUE,
    blocked_at TEXT    NOT NULL
);
"""

# Index speeds up common dashboard queries (filtering by verdict, sorting by time)
CREATE_INDEX_VERDICT = """
CREATE INDEX IF NOT EXISTS idx_verdict ON alerts (final_verdict);
"""
CREATE_INDEX_TIMESTAMP = """
CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts (timestamp DESC);
"""
CREATE_INDEX_SRC_IP = """
CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts (src_ip);
"""


# ── AlertManager class ────────────────────────────────────────────────────────

class AlertManager:
    """
    Central hub for storing, querying, and acting on security alerts.

    Thread-safety:
        All SQLite writes and deque mutations are protected by a single
        ``threading.Lock``. This allows the sniffer thread, the predictor
        thread, and the Streamlit dashboard thread to call any method
        concurrently without data corruption.

    Args:
        db_path (str): File path for the SQLite database.
                       Parent directories are created automatically.

    Example:
        >>> manager = AlertManager(db_path="logs/alerts.db")
        >>> manager.add_alert({
        ...     "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        ...     "src_port": 4444, "dst_port": 80, "protocol": 6,
        ...     "rf_label": "DDoS", "rf_confidence": 0.97,
        ...     "ae_anomaly_score": 0.85, "ae_is_anomaly": True,
        ...     "final_verdict": "Attack", "combined_confidence": 0.91,
        ...     "timestamp": "2025-01-01T12:00:00"
        ... })
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        """
        Initialise the AlertManager.

        Steps:
          1. Resolve and create the database directory if needed.
          2. Connect to SQLite (check_same_thread=False allows multi-thread use).
          3. Create the alerts and blocked_ips tables + indexes if they don't exist.
          4. Initialise the in-memory deque and the threading lock.
          5. Pre-load the last DEQUE_MAX_SIZE alerts from disk into the deque
             so the dashboard has data immediately after a restart.

        Args:
            db_path (str): Path to the SQLite .db file.

        Raises:
            sqlite3.Error: If the database file cannot be created or opened.
            OSError: If the directory cannot be created.
        """
        # ── 1. Resolve paths ──────────────────────────────────────────────────
        self._db_path = Path(db_path).resolve()
        # Create parent directory (e.g. "logs/") if it does not exist yet
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("AlertManager: database path → %s", self._db_path)

        # ── 2. Open SQLite connection ─────────────────────────────────────────
        # check_same_thread=False is required because multiple threads will
        # call our methods, but we protect every access with self._lock.
        try:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
            )
            # Return rows as dict-like objects so we can use row["column_name"]
            self._conn.row_factory = sqlite3.Row
            logger.info("AlertManager: SQLite connection opened.")
        except sqlite3.Error as exc:
            logger.critical("AlertManager: cannot open SQLite database: %s", exc)
            raise

        # ── 3. Create tables and indexes ──────────────────────────────────────
        self._create_schema()

        # ── 4. Thread lock + in-memory deque ─────────────────────────────────
        # The lock is used as:  with self._lock:  <do something>
        # Any code inside the 'with' block is safe from concurrent access.
        self._lock = threading.Lock()

        # deque with maxlen automatically discards the oldest item when full,
        # so we never exceed DEQUE_MAX_SIZE alerts in memory.
        self._recent_alerts: deque = deque(maxlen=DEQUE_MAX_SIZE)

        # ── 5. Pre-load recent alerts from disk ───────────────────────────────
        self._preload_from_db()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _create_schema(self) -> None:
        """
        Create SQLite tables and indexes if they do not already exist.
        Called once during __init__. Uses IF NOT EXISTS so it is idempotent
        (safe to call multiple times without errors).
        """
        try:
            with self._conn:  # acts as a transaction — auto-commits on exit
                self._conn.execute(CREATE_ALERTS_TABLE)
                self._conn.execute(CREATE_BLOCKED_IPS_TABLE)
                self._conn.execute(CREATE_INDEX_VERDICT)
                self._conn.execute(CREATE_INDEX_TIMESTAMP)
                self._conn.execute(CREATE_INDEX_SRC_IP)
            logger.info("AlertManager: schema ready.")
        except sqlite3.Error as exc:
            logger.error("AlertManager: schema creation failed: %s", exc)
            raise

    def _preload_from_db(self) -> None:
        """
        Populate the in-memory deque with the most recent alerts from SQLite.
        This ensures the dashboard shows historical data after a restart,
        rather than starting empty.
        """
        try:
            cursor = self._conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (DEQUE_MAX_SIZE,),
            )
            rows = cursor.fetchall()
            # Reverse so oldest-first order is preserved in the deque
            for row in reversed(rows):
                self._recent_alerts.append(dict(row))
            logger.info(
                "AlertManager: pre-loaded %d alert(s) from database.", len(rows)
            )
        except sqlite3.Error as exc:
            # Non-fatal — we can still run without pre-loaded data
            logger.warning("AlertManager: could not pre-load alerts: %s", exc)

    def _row_to_dict(self, alert: dict) -> dict:
        """
        Normalise an alert dict to ensure all expected keys are present.
        Missing optional fields are filled with sensible defaults.

        Args:
            alert (dict): Raw alert dict from HybridPredictor.

        Returns:
            dict: Normalised alert dict ready for DB insertion and deque storage.
        """
        now = datetime.utcnow().isoformat(timespec="seconds")
        return {
            "timestamp":           alert.get("timestamp", now),
            "src_ip":              str(alert.get("src_ip", "0.0.0.0")),
            "dst_ip":              str(alert.get("dst_ip", "0.0.0.0")),
            "src_port":            int(alert.get("src_port", 0)),
            "dst_port":            int(alert.get("dst_port", 0)),
            "protocol":            int(alert.get("protocol", 0)),
            "rf_label":            str(alert.get("rf_label", "Unknown")),
            "rf_confidence":       float(alert.get("rf_confidence", 0.0)),
            "ae_score":            float(alert.get("ae_anomaly_score", 0.0)),
            "final_verdict":       str(alert.get("final_verdict", "Unknown")),
            "combined_confidence": float(alert.get("combined_confidence", 0.0)),
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def add_alert(self, prediction: dict) -> None:
        """
        Store one alert from HybridPredictor.

        Performs two things atomically (under the lock):
          1. INSERT into SQLite alerts table (permanent record).
          2. Append to the in-memory deque (fast dashboard reads).

        The 'id' returned by SQLite is added to the alert dict so callers
        can reference it later.

        Args:
            prediction (dict): Output dict from HybridPredictor.predict().
                                Must contain at minimum: src_ip, dst_ip,
                                final_verdict.

        Raises:
            sqlite3.Error: Logged and re-raised if the INSERT fails.

        Example:
            >>> manager.add_alert({
            ...     "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
            ...     "final_verdict": "Attack", "rf_label": "DDoS",
            ...     "rf_confidence": 0.95, "ae_anomaly_score": 0.88,
            ...     "ae_is_anomaly": True, "combined_confidence": 0.91,
            ...     "timestamp": "2025-01-01T12:00:00"
            ... })
        """
        alert = self._row_to_dict(prediction)

        with self._lock:
            try:
                # --- Write to SQLite ----------------------------------------
                cursor = self._conn.execute(
                    """
                    INSERT INTO alerts
                        (timestamp, src_ip, dst_ip, src_port, dst_port,
                         protocol, rf_label, rf_confidence, ae_score,
                         final_verdict, combined_confidence)
                    VALUES
                        (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
                         :protocol, :rf_label, :rf_confidence, :ae_score,
                         :final_verdict, :combined_confidence)
                    """,
                    alert,
                )
                self._conn.commit()

                # Attach the auto-generated row ID to the alert dict
                alert["id"] = cursor.lastrowid

                # --- Write to in-memory deque --------------------------------
                self._recent_alerts.append(alert)

                logger.debug(
                    "Alert #%d stored — verdict=%s src=%s",
                    alert["id"],
                    alert["final_verdict"],
                    alert["src_ip"],
                )
            except sqlite3.Error as exc:
                logger.error("AlertManager.add_alert failed: %s", exc)
                raise

    def get_recent_alerts(self, n: int = 100) -> list[dict]:
        """
        Return the most recent N alerts from the in-memory deque.

        Reading from the deque is much faster than querying SQLite, which
        is why we maintain both storage layers.

        Args:
            n (int): Number of alerts to return (default 100, max DEQUE_MAX_SIZE).

        Returns:
            list[dict]: List of alert dicts, newest-last order.

        Example:
            >>> alerts = manager.get_recent_alerts(50)
            >>> print(alerts[-1]["final_verdict"])  # most recent
            'Attack'
        """
        # Clamp n to the actual deque size so we don't ask for more than exists
        n = min(n, DEQUE_MAX_SIZE)
        with self._lock:
            # Convert deque to list, then slice the last n items
            alerts_list = list(self._recent_alerts)
        return alerts_list[-n:]

    def get_top_attackers(self, n: int = 10) -> list[dict]:
        """
        Return the top N source IPs by alert count, excluding benign traffic.

        Queries SQLite directly so the result reflects all historical alerts,
        not just the last 500 in the deque.

        Args:
            n (int): Number of top attackers to return (default 10).

        Returns:
            list[dict]: Each item has keys: src_ip (str), alert_count (int).

        Example:
            >>> top = manager.get_top_attackers(5)
            >>> for entry in top:
            ...     print(entry["src_ip"], entry["alert_count"])
        """
        with self._lock:
            try:
                cursor = self._conn.execute(
                    """
                    SELECT   src_ip,
                             COUNT(*) AS alert_count
                    FROM     alerts
                    WHERE    final_verdict != 'Benign'
                    GROUP BY src_ip
                    ORDER BY alert_count DESC
                    LIMIT    ?
                    """,
                    (n,),
                )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as exc:
                logger.error("AlertManager.get_top_attackers failed: %s", exc)
                return []

    def get_attack_distribution(self) -> dict:
        """
        Return a count of each attack label (rf_label) seen so far.

        Used by the Streamlit dashboard to draw the donut / pie chart.

        Returns:
            dict: Mapping of label → count.
                  Example: {"DDoS": 120, "PortScan": 45, "Benign": 800}

        Example:
            >>> dist = manager.get_attack_distribution()
            >>> print(dist)
            {'DDoS': 120, 'PortScan': 45, 'Benign': 800}
        """
        with self._lock:
            try:
                cursor = self._conn.execute(
                    """
                    SELECT   rf_label,
                             COUNT(*) AS cnt
                    FROM     alerts
                    GROUP BY rf_label
                    ORDER BY cnt DESC
                    """
                )
                rows = cursor.fetchall()
                return {row["rf_label"]: row["cnt"] for row in rows}
            except sqlite3.Error as exc:
                logger.error("AlertManager.get_attack_distribution failed: %s", exc)
                return {}

    def block_ip(self, ip_address: str) -> bool:
        """
        Flag an IP address as blocked (simulated response action).

        Writes the IP to the blocked_ips table in SQLite.
        If the IP is already blocked, the operation succeeds silently
        (no duplicate entry is created).

        Args:
            ip_address (str): IPv4 or IPv6 address to block.

        Returns:
            bool: True if the IP was newly blocked, False if already blocked.

        Raises:
            ValueError: If ip_address is empty or None.

        Example:
            >>> was_new = manager.block_ip("1.2.3.4")
            >>> print(was_new)  # True the first time, False thereafter
            True
        """
        if not ip_address or not isinstance(ip_address, str):
            raise ValueError("ip_address must be a non-empty string.")

        ip_address = ip_address.strip()
        blocked_at = datetime.utcnow().isoformat(timespec="seconds")

        with self._lock:
            try:
                # INSERT OR IGNORE means: do nothing if ip_address already exists
                # (the UNIQUE constraint on ip_address prevents duplicates)
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO blocked_ips (ip_address, blocked_at)
                    VALUES (?, ?)
                    """,
                    (ip_address, blocked_at),
                )
                self._conn.commit()

                newly_blocked = cursor.rowcount > 0  # 1 if inserted, 0 if ignored
                if newly_blocked:
                    logger.info("Blocked IP: %s at %s", ip_address, blocked_at)
                else:
                    logger.info("IP %s was already blocked.", ip_address)
                return newly_blocked

            except sqlite3.Error as exc:
                logger.error("AlertManager.block_ip failed: %s", exc)
                return False

    def get_blocked_ips(self) -> list[str]:
        """
        Return all currently blocked IP addresses.

        Returns:
            list[str]: List of blocked IP address strings.

        Example:
            >>> blocked = manager.get_blocked_ips()
            >>> print(blocked)
            ['1.2.3.4', '5.6.7.8']
        """
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "SELECT ip_address FROM blocked_ips ORDER BY blocked_at DESC"
                )
                return [row["ip_address"] for row in cursor.fetchall()]
            except sqlite3.Error as exc:
                logger.error("AlertManager.get_blocked_ips failed: %s", exc)
                return []

    def export_csv(self, path: str) -> str:
        """
        Export all alerts from SQLite to a CSV file.

        The CSV contains every column from the alerts table and can be
        opened in Excel / Google Sheets for offline analysis.

        Args:
            path (str): Destination file path (e.g. "logs/export.csv").
                        Parent directory is created if it does not exist.

        Returns:
            str: Absolute path to the written CSV file.

        Raises:
            sqlite3.Error: If the database query fails.
            OSError: If the file cannot be written.

        Example:
            >>> saved_path = manager.export_csv("logs/alerts_export.csv")
            >>> print(f"Exported to {saved_path}")
        """
        output_path = Path(path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            try:
                cursor = self._conn.execute(
                    "SELECT * FROM alerts ORDER BY id ASC"
                )
                rows = cursor.fetchall()

                # csv.DictWriter needs the column names — get them from cursor
                if rows:
                    fieldnames = list(rows[0].keys())
                else:
                    # If there are no alerts yet, write an empty CSV with headers
                    fieldnames = [
                        "id", "timestamp", "src_ip", "dst_ip", "src_port",
                        "dst_port", "protocol", "rf_label", "rf_confidence",
                        "ae_score", "final_verdict", "combined_confidence",
                    ]

                with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
                    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(dict(row))

                logger.info(
                    "AlertManager: exported %d alert(s) to %s",
                    len(rows),
                    output_path,
                )
                return str(output_path)

            except sqlite3.Error as exc:
                logger.error("AlertManager.export_csv — DB error: %s", exc)
                raise
            except OSError as exc:
                logger.error("AlertManager.export_csv — file error: %s", exc)
                raise

    def close(self) -> None:
        """
        Close the SQLite connection gracefully.

        Call this when the application is shutting down (e.g. in a signal
        handler or a finally block) to ensure no data is lost.

        Example:
            >>> manager.close()
        """

        with self._lock:
            try:
                self._conn.close()
                logger.info("AlertManager: SQLite connection closed.")
            except sqlite3.Error as exc:
                logger.warning("AlertManager.close: error closing connection: %s", exc)

    def __repr__(self) -> str:
        """Human-readable representation for debugging."""
        return (
            f"AlertManager(db='{self._db_path}', "
            f"cached_alerts={len(self._recent_alerts)})"
        )
