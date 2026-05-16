"""
Mini SIEM - Windows Event Log Agent
Thu thập Security Event Log THỰC từ máy Windows host.

Cài đặt:
    pip install pywin32 requests


Chạy với quyền Administrator:     
cd /d G:\mini-siem (đường dẫn đến thư mục mini-siem)

    python scripts/win_event_agent.py
"""

import time
import logging
import requests
from datetime import datetime

try:
    import win32evtlog
    import pywintypes
except ImportError:
    print("ERROR: pywin32 chưa cài. Chạy: pip install pywin32")
    raise SystemExit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WinAgent] %(levelname)s %(message)s",
)
logger = logging.getLogger("win-event-agent")

# ─── Config ───────────────────────────────────────────────────────
API_URL        = "http://localhost:8000"
BATCH_INTERVAL = 10          # giây
LOG_TYPE       = "Security"
SERVER         = None        # None = local machine

# ─── Event ID → (event_type, severity, description) ───────────────
EVENT_MAP = {
    4624: ("login_success", 1, "Logon Success"),
    4625: ("login_failure", 4, "Logon Failure"),
    4740: ("login_failure", 5, "Account Lockout"),
    4648: ("login_success", 2, "Explicit Credential Logon (RunAs)"),
    4647: ("login_success", 1, "User Initiated Logoff"),
    4688: ("web_access",   2,  "New Process Created"),
    4698: ("ids_alert",    3,  "Scheduled Task Created"),
    4720: ("ids_alert",    3,  "User Account Created"),
    4726: ("ids_alert",    4,  "User Account Deleted"),
    4756: ("ids_alert",    3,  "Member Added to Security Group"),
}

LOGON_TYPE_MAP = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}

# Processes đáng ngờ → nâng severity
SUSPICIOUS_PROC = {
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe",
}


def _strings(event) -> list:
    """Lấy danh sách string insert từ event một cách an toàn."""
    try:
        return list(event.StringInserts) if event.StringInserts else []
    except Exception:
        return []


def _fmt_time(event) -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_event(event) -> dict | None:
    event_id = event.EventID & 0xFFFF
    if event_id not in EVENT_MAP:
        return None

    etype, severity, desc = EVENT_MAP[event_id]
    strings = _strings(event)
    timestamp = _fmt_time(event)
    src_ip = "127.0.0.1"
    user   = "unknown"
    message = desc

    def safe(idx, default="-"):
        return strings[idx] if len(strings) > idx and strings[idx] else default

    if event_id == 4624:          # Logon Success
        user    = safe(5)
        ltype   = int(safe(8, "0")) if safe(8, "0").isdigit() else 0
        src_raw = safe(18)
        src_ip  = src_raw if src_raw not in ("-", "::1", "", "0.0.0.0") else "127.0.0.1"
        message = f"User '{user}' logon — {LOGON_TYPE_MAP.get(ltype, f'Type {ltype}')}"

    elif event_id == 4625:        # Logon Failure
        user    = safe(5)
        src_raw = safe(19)
        src_ip  = src_raw if src_raw not in ("-", "::1", "", "0.0.0.0") else "127.0.0.1"
        reason  = safe(8)
        message = f"Failed login '{user}' — {reason}"

    elif event_id == 4740:        # Account Lockout
        user    = safe(0)
        message = f"Account '{user}' locked out"

    elif event_id == 4688:        # New Process
        proc    = safe(5) or safe(0)
        creator = safe(13)
        message = f"Process: {proc} (by {creator})"
        if proc.lower() in SUSPICIOUS_PROC:
            severity  = max(severity, 4)
            etype     = "ids_alert"

    elif event_id == 4698:        # Scheduled Task Created
        task    = safe(0)
        creator = safe(4)
        message = f"Scheduled task created: {task} by {creator}"

    elif event_id in (4720, 4726):
        user    = safe(0)
        actor   = safe(4)
        message = f"{'Created' if event_id == 4720 else 'Deleted'} account '{user}' by '{actor}'"

    return {
        "event_type": etype,
        "src_ip":     src_ip,
        "severity":   severity,
        "message":    f"[WinEvent {event_id}] {message}",
        "source":     "endpoint",
        "timestamp":  timestamp,
        "user":       user,
    }


def read_new_events(handle, max_count: int = 100) -> list:
    flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    result = []
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        count  = 0
        while events and count < max_count:
            for ev in events:
                entry = parse_event(ev)
                if entry:
                    result.append(entry)
                count += 1
                if count >= max_count:
                    break
            if count >= max_count:
                break
            events = win32evtlog.ReadEventLog(handle, flags, 0)
    except Exception as e:
        logger.debug(f"ReadEventLog error: {e}")
    return result


def send_batch(batch: list):
    if not batch:
        return
    try:
        r = requests.post(f"{API_URL}/ingest/batch", json={"logs": batch}, timeout=10)
        if r.status_code == 200:
            logger.info(f"✅ Sent {len(batch)} Windows events → SIEM "
                        f"({r.json().get('rate_per_second', 0):.1f} logs/s)")
        else:
            logger.warning(f"API {r.status_code}: {r.text[:100]}")
    except requests.ConnectionError:
        logger.error(f"Cannot connect to {API_URL}. Is Docker running?")
    except Exception as e:
        logger.error(f"Send error: {e}")


def main():
    logger.info(f"Windows Event Log Agent → {API_URL}")
    logger.info("Đảm bảo chạy với quyền Administrator để đọc Security log")

    # Kiểm tra kết nối API
    try:
        r = requests.get(f"{API_URL}/health", timeout=5)
        logger.info(f"SIEM API: {r.json().get('overall', 'unknown')}")
    except Exception:
        logger.warning(f"Cannot reach {API_URL} — sẽ retry mỗi batch")

    # Lấy vị trí hiện tại để chỉ đọc event MỚI
    try:
        h = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
        last_total = win32evtlog.GetNumberOfEventLogRecords(h)
        win32evtlog.CloseEventLog(h)
        logger.info(f"Security log có {last_total} records hiện tại — chỉ đọc events mới")
    except pywintypes.error as e:
        logger.error(f"Không thể mở Security log: {e}")
        logger.error("Hãy chạy script này với quyền Administrator.")
        return

    logger.info(f"Đang giám sát — gửi batch mỗi {BATCH_INTERVAL}s")

    while True:
        time.sleep(BATCH_INTERVAL)
        try:
            h = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
            current_total = win32evtlog.GetNumberOfEventLogRecords(h)
            new_count = current_total - last_total

            if new_count > 0:
                logger.debug(f"Phát hiện {new_count} event mới")
                batch = read_new_events(h, min(new_count, 100))
                last_total = current_total
                win32evtlog.CloseEventLog(h)
                send_batch(batch)
            else:
                win32evtlog.CloseEventLog(h)

        except pywintypes.error as e:
            logger.error(f"Windows API error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
