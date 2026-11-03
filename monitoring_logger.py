"""
InteliScale Monitoring Logger
============================
وحدة مراقبة مستقلة لبرنامج InteliScale.

الاستخدام::

    from monitoring_logger import MonitoringLogger

    logger = MonitoringLogger(
        client_id="your_client_id",       # Optional: auto-derived from device_token if omitted
        device_token="your_device_token",
        api_url="https://your-site.vercel.app",
        app_version="1.0.0"
    )

    logger.start()   # يبدأ Heartbeat + Queue فى الخلفية

    logger.log("APP_START", "INFO", "تم تشغيل البرنامج")
    logger.log("DB_ERROR", "ERROR", "فشل الاتصال بقاعدة البيانات", details={"error": str(e)})

    # عند إغلاق البرنامج:
    logger.log("APP_STOP", "INFO", "تم إغلاق البرنامج")
    logger.stop()

ملاحظات الأمان:
- لا ترسل كلمات مرور أو مفاتيح أو بيانات مالية في details
- الوحدة لا تُوقف البرنامج الأصلي أبداً — جميع الأخطاء مُعالَجة داخلياً
- لا توجد secrets في هذا الملف — فقط api_url و device_token
"""

import threading
import queue
import time
import uuid
import json
import platform
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

# ─── Constants ────────────────────────────────────────────────────────────────

ALLOWED_EVENT_TYPES = {
    "APP_START", "APP_STOP", "EXCEPTION", "DB_ERROR",
    "SERIAL_CONNECT", "SERIAL_DISCONNECT", "WEIGHT_ERROR",
    "PRINT_ERROR", "INVOICE_ERROR", "LICENSE_CHECK",
    "LICENSE_OK", "LICENSE_FAIL", "HEARTBEAT", "NETWORK_ERROR", "CUSTOM"
}

ALLOWED_SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}

# Max events held in-memory queue before oldest are dropped
MAX_QUEUE_SIZE = 500

# Max events per batch sent to server
BATCH_SIZE = 20

# Interval between queue flush attempts (seconds)
FLUSH_INTERVAL = 30

# Heartbeat interval (seconds) — 5 minutes
HEARTBEAT_INTERVAL = 300

# HTTP timeout (seconds)
HTTP_TIMEOUT = 10

# Local log file for offline queue persistence
LOCAL_LOG_FILE = "monitoring_queue.jsonl"

# Sensitive field patterns — scrubbed before sending
SENSITIVE_KEYS = {"password", "secret", "key", "token", "auth", "firebase",
                  "credential", "private", "pwd", "passwd"}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_os_info() -> str:
    """Return a safe OS description string."""
    try:
        return f"{platform.system()} {platform.release()} ({platform.machine()})"
    except Exception:
        return "Unknown OS"


def _scrub(obj, depth=0):
    """Recursively remove sensitive keys from a dict/list."""
    if depth > 5:
        return "[truncated]"
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if any(s in k.lower() for s in SENSITIVE_KEYS):
                result[k] = "[REDACTED]"
            else:
                result[k] = _scrub(v, depth + 1)
        return result
    elif isinstance(obj, (list, tuple)):
        return [_scrub(i, depth + 1) for i in obj[:50]]  # limit list size
    elif isinstance(obj, str):
        return obj[:2000]
    else:
        return obj


def _make_event_id() -> str:
    """Generate a unique event ID."""
    return uuid.uuid4().hex


def _derive_client_id(device_token: str) -> str:
    """Derive a stable client_id from the device token (matches server logic)."""
    return hashlib.sha256(device_token.encode()).hexdigest()[:16]


# ─── MonitoringLogger ─────────────────────────────────────────────────────────

class MonitoringLogger:
    """
    Thread-safe monitoring logger for InteliScale.

    - Logs events locally and queues them for server delivery.
    - Background thread flushes queue every 30 seconds.
    - Heartbeat thread pings server every 5 minutes.
    - Never raises exceptions — monitoring must not crash the main app.
    """

    def __init__(
        self,
        device_token: str,
        api_url: str,
        app_version: str = "unknown",
        client_id: str = None,
        local_log_path: str = None,
        enabled: bool = True
    ):
        """
        Args:
            device_token:    موزع Token لمصادقة الجهاز مع الخادم.
            api_url:         الرابط الأساسي للموقع (مثل https://example.vercel.app).
            app_version:     إصدار البرنامج الحالي.
            client_id:       معرّف العميل (اختياري، يُحسب تلقائياً من device_token).
            local_log_path:  مسار ملف Queue المحلي (اختياري).
            enabled:         تعطيل الإرسال كاملاً للتطوير المحلي.
        """
        self._device_token = device_token.strip() if device_token else ""
        self._api_url = api_url.rstrip("/") if api_url else ""
        self._app_version = str(app_version)[:30]
        self._client_id = client_id or _derive_client_id(self._device_token)
        self._os_info = _get_os_info()
        self._enabled = enabled and bool(self._device_token) and bool(self._api_url)

        # In-memory event queue
        self._queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

        # Local file for offline persistence
        self._local_log_path = local_log_path or LOCAL_LOG_FILE

        # Internal Python logger (does NOT send to server — just local file/console)
        self._logger = logging.getLogger(f"monitoring_logger.{self._client_id}")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("[MON %(levelname)s] %(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.WARNING)  # quiet by default

        # Background threads
        self._flush_thread = None
        self._heartbeat_thread = None
        self._stop_event = threading.Event()
        self._started = False

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self):
        """Start background flush and heartbeat threads."""
        if self._started or not self._enabled:
            return
        self._started = True
        self._stop_event.clear()

        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="mon-flush",
            daemon=True
        )
        self._flush_thread.start()

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="mon-heartbeat",
            daemon=True
        )
        self._heartbeat_thread.start()

    def stop(self):
        """Signal background threads to stop and flush remaining events."""
        self._stop_event.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=15)

    def log(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: dict = None
    ):
        """
        قَيِّد حدثاً وأضفه إلى قائمة الإرسال.

        Args:
            event_type: نوع الحدث (من ALLOWED_EVENT_TYPES)
            severity:   مستوى الخطورة (INFO / WARNING / ERROR / CRITICAL)
            message:    الرسالة (max 500 chars)
            details:    تفاصيل اختيارية (dict) — لا تضع فيها Passwords أو Keys
        """
        try:
            self._enqueue(event_type, severity, message, details)
        except Exception:
            pass  # Never crash the calling code

    def log_exception(self, message: str, exc: Exception = None, details: dict = None):
        """تسجيل استثناء Python."""
        try:
            import traceback
            d = dict(details or {})
            if exc is not None:
                d["exception_type"] = type(exc).__name__
                d["traceback"] = traceback.format_exc()[:1000]
            self._enqueue("EXCEPTION", "ERROR", message, d)
        except Exception:
            pass

    def log_db_error(self, message: str, details: dict = None):
        """تسجيل خطأ قاعدة بيانات."""
        try:
            self._enqueue("DB_ERROR", "ERROR", message, details)
        except Exception:
            pass

    def log_serial(self, connected: bool, port: str = None, details: dict = None):
        """تسجيل اتصال/انقطاع ميزان RS232."""
        try:
            d = dict(details or {})
            if port:
                d["port"] = port
            event_type = "SERIAL_CONNECT" if connected else "SERIAL_DISCONNECT"
            severity = "INFO" if connected else "WARNING"
            msg = f"{'اتصال' if connected else 'انقطاع'} الميزان{' على ' + port if port else ''}"
            self._enqueue(event_type, severity, msg, d)
        except Exception:
            pass

    def log_weight_error(self, message: str, details: dict = None):
        """تسجيل خطأ قراءة الوزن."""
        try:
            self._enqueue("WEIGHT_ERROR", "ERROR", message, details)
        except Exception:
            pass

    def log_print_error(self, message: str, details: dict = None):
        """تسجيل خطأ الطباعة."""
        try:
            self._enqueue("PRINT_ERROR", "WARNING", message, details)
        except Exception:
            pass

    def log_invoice_error(self, message: str, details: dict = None):
        """تسجيل خطأ حفظ الفاتورة."""
        try:
            self._enqueue("INVOICE_ERROR", "ERROR", message, details)
        except Exception:
            pass

    def log_license(self, success: bool, message: str, details: dict = None):
        """تسجيل نتيجة التحقق من الترخيص."""
        try:
            event_type = "LICENSE_OK" if success else "LICENSE_FAIL"
            severity = "INFO" if success else "ERROR"
            self._enqueue(event_type, severity, message, details)
        except Exception:
            pass

    # ── Internal ────────────────────────────────────────────────────────────

    def _build_event(self, event_type: str, severity: str, message: str, details: dict = None) -> dict:
        """Build a validated event dict."""
        etype = event_type.upper() if event_type else "CUSTOM"
        if etype not in ALLOWED_EVENT_TYPES:
            etype = "CUSTOM"

        sev = severity.upper() if severity else "INFO"
        if sev not in ALLOWED_SEVERITIES:
            sev = "INFO"

        return {
            "event_id": _make_event_id(),
            "event_type": etype,
            "severity": sev,
            "message": str(message)[:500],
            "version": self._app_version,
            "os_info": self._os_info,
            "details": _scrub(details) if details else None,
            "timestamp": int(time.time() * 1000)  # ms
        }

    def _enqueue(self, event_type: str, severity: str, message: str, details: dict = None):
        """Add event to queue, dropping oldest if full."""
        if not self._enabled:
            return
        event = self._build_event(event_type, severity, message, details)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Drop the oldest event to make room
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                pass

        # Also write to local file for offline recovery
        self._write_local(event)

    def _write_local(self, event: dict):
        """Append event to local JSONL file (offline recovery)."""
        try:
            with open(self._local_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            # Trim file if too large (>2MB → keep last 1000 lines)
            size = os.path.getsize(self._local_log_path)
            if size > 2 * 1024 * 1024:
                self._trim_local_log()
        except Exception:
            pass

    def _trim_local_log(self):
        """Keep only the last 1000 events in the local log file."""
        try:
            with open(self._local_log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            with open(self._local_log_path, "w", encoding="utf-8") as f:
                f.writelines(lines[-1000:])
        except Exception:
            pass

    def _flush_loop(self):
        """Background thread: flush queue to server every FLUSH_INTERVAL seconds."""
        while not self._stop_event.is_set():
            try:
                self._flush_queue()
            except Exception:
                pass
            self._stop_event.wait(FLUSH_INTERVAL)

        # Final flush on stop
        try:
            self._flush_queue()
        except Exception:
            pass

    def _flush_queue(self):
        """Drain queue and send events to server in batches."""
        if self._queue.empty():
            return

        # Collect up to BATCH_SIZE events
        batch = []
        while not self._queue.empty() and len(batch) < BATCH_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break

        if not batch:
            return

        success = self._send_events(batch)
        if not success:
            # Put events back in queue (prepend)
            for event in reversed(batch):
                try:
                    self._queue.put_nowait(event)
                except queue.Full:
                    break  # Queue full — events stay in local file

    def _send_events(self, events: list) -> bool:
        """POST batch of events to /api/log-events. Returns True on success."""
        try:
            url = f"{self._api_url}/api/log-events"
            payload = json.dumps({
                "device_token": self._device_token,
                "events": events
            }).encode("utf-8")

            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", f"InteliScale/{self._app_version}")

            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                status = resp.getcode()
                return 200 <= status < 300

        except HTTPError as e:
            # 4xx errors (bad token, rate limit, etc.) — don't retry
            if 400 <= e.code < 500:
                self._logger.warning(f"Server rejected events (HTTP {e.code}) — check device_token")
                return True  # Treat as "consumed" to avoid infinite retry
            return False
        except (URLError, OSError):
            # Network not available — keep in queue
            return False
        except Exception:
            return False

    def _heartbeat_loop(self):
        """Background thread: send heartbeat every HEARTBEAT_INTERVAL seconds."""
        # Send first heartbeat shortly after start
        self._stop_event.wait(10)
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception:
                pass
            self._stop_event.wait(HEARTBEAT_INTERVAL)

    def _send_heartbeat(self):
        """POST heartbeat to /api/heartbeat."""
        try:
            url = f"{self._api_url}/api/heartbeat"
            payload = json.dumps({
                "device_token": self._device_token,
                "version": self._app_version,
                "os_info": self._os_info,
                "status": "running"
            }).encode("utf-8")

            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", f"InteliScale/{self._app_version}")

            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                resp.read()  # Consume response

        except Exception:
            pass  # Heartbeat failure is non-critical


# ─── Global Exception Hook ────────────────────────────────────────────────────

def install_global_exception_hook(logger: MonitoringLogger):
    """
    تثبيت hook لالتقاط الاستثناءات غير المعالجة تلقائياً.

    استخدامه:
        install_global_exception_hook(logger)
    """
    original_hook = sys.excepthook

    def custom_hook(exc_type, exc_value, exc_tb):
        try:
            import traceback
            tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            logger.log(
                "EXCEPTION", "CRITICAL",
                f"استثناء غير معالج: {exc_type.__name__}: {str(exc_value)[:200]}",
                details={"traceback": tb_str[:1500]}
            )
            # Flush immediately (best-effort)
            logger._flush_queue()
        except Exception:
            pass
        finally:
            original_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = custom_hook
