# config.py
# ============================================================
# ENTROPY - Central Configuration
# ============================================================

from __future__ import annotations
import os
from pathlib import Path

BASE_PATH = Path(__file__).resolve().parent
BASE_DIR = str(BASE_PATH)

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_PATH / ".env")
except ImportError:
    pass

_TRUE_VALUES  = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}

def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"Invalid boolean value for {name}: {value!r} "
        f"(expected true/false, yes/no, 1/0, or on/off)"
    )

def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = default if raw is None else int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid integer value for {name}: {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{name}={value} is below the minimum of {minimum}")
    return value

def _env_float(name: str, default: float, minimum: float | None = None) -> float:
    raw = os.getenv(name)
    try:
        value = default if raw is None else float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid float value for {name}: {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{name}={value} is below the minimum of {minimum}")
    return value

def _resolve_path(value: str) -> str:
    """Resolve *value* against the repository root when it is relative."""
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return str(path.resolve())
    return str((BASE_PATH / path).resolve())

# ── Project Folders ──────────────────────────────────────────
MONITORING_DIR    = str((BASE_PATH / "monitoring").resolve())
ENTROPY_DIR       = str((BASE_PATH / "entropy").resolve())
AI_DIR            = str((BASE_PATH / "ai").resolve())
RESPONSE_DIR      = str((BASE_PATH / "response").resolve())
BLOCKCHAIN_DIR    = str((BASE_PATH / "blockchain").resolve())
DASHBOARD_DIR     = str((BASE_PATH / "dashboard").resolve())
DATA_DIR          = str((BASE_PATH / "data").resolve())
TRAINING_DATA_DIR = str((BASE_PATH / "data" / "training").resolve())
TESTING_DATA_DIR  = str((BASE_PATH / "data" / "testing").resolve())
VICTIM_USER_FILES = str((BASE_PATH / "victim_server" / "user_files").resolve())

_quarantine_raw = os.getenv("ENTROPY_QUARANTINE_DIR", "").strip()
QUARANTINE_DIR    = (str(_resolve_path(_quarantine_raw))
                     if _quarantine_raw
                     else str((BASE_PATH / "quarantine_storage").resolve()))
BACKUP_DIR        = str((BASE_PATH / "backup_storage").resolve())
REPORTS_DIR       = str((BASE_PATH / "reports").resolve())

# ── Runtime Files & Directories ──────────────────────────────
LOG_FILE = str((BASE_PATH / "logs" / "entropy_system.log").resolve())
LOG_DIR  = str(Path(LOG_FILE).parent)
DB_PATH  = str((BASE_PATH / "entropy.db").resolve())

for d in [LOG_DIR, QUARANTINE_DIR, TRAINING_DATA_DIR, TESTING_DATA_DIR, VICTIM_USER_FILES, BACKUP_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)

# ── Watch Folders ────────────────────────────────────────────
def _watch_folders() -> list[str]:
    raw = os.getenv("ENTROPY_WATCH_FOLDERS")
    if raw is None or not raw.strip():
        return [VICTIM_USER_FILES, TESTING_DATA_DIR]
    folders = [
        _resolve_path(part.strip())
        for part in raw.split(",")
        if part.strip()
    ]
    if VICTIM_USER_FILES not in folders:
        folders.append(VICTIM_USER_FILES)
    return folders

WATCH_FOLDERS = _watch_folders()

WHITELISTED_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "systemd", "init", "kthreadd",
    "code.exe", "explorer.exe"
]

DEFENDER_TOOLING_MARKERS = (
    "pipeline_runner",
    "entropy_system",
    "lab.py",
    "victim_server",
    "attacker_server/app",
    "attacker_server\\app",
    "dashboard",
    "app.py",
    "main.py",
)

EVENT_DEDUP_WINDOW_SECONDS = _env_float("EVENT_DEDUP_WINDOW_SECONDS", 1.0, minimum=0.0)
EVENT_QUEUE_SIZE           = _env_int("EVENT_QUEUE_SIZE", 10000, minimum=1)
EVENT_BATCH_SIZE           = _env_int("EVENT_BATCH_SIZE", 50, minimum=1)

ENTROPY_THRESHOLD          = _env_float("ENTROPY_THRESHOLD", 6.8, minimum=0.0)
ENTROPY_DELTA_THRESHOLD    = _env_float("ENTROPY_DELTA_THRESHOLD", 2.0, minimum=0.0)
FILES_PER_SECOND_THRESHOLD = _env_float("ENTROPY_FILES_PER_SECOND_THRESHOLD", 3.0, minimum=0.0)

CAMPAIGN_ENABLED        = _env_bool("ENTROPY_CAMPAIGN_ENABLED", True)
CAMPAIGN_WINDOW_SECONDS = _env_float("ENTROPY_CAMPAIGN_WINDOW_SECONDS", 15.0, minimum=1.0)
CAMPAIGN_MIN_FILES      = _env_int("ENTROPY_CAMPAIGN_MIN_FILES", 2, minimum=2)
SAMPLE_SIZE_BYTES       = _env_int("ENTROPY_SAMPLE_SIZE_BYTES", 65536, minimum=1)
# Exact content hashes are computed incrementally up to this limit; larger
# files retain the sampled entropy hash but are not shared as exact intel.
CONTENT_HASH_MAX_BYTES  = _env_int("ENTROPY_CONTENT_HASH_MAX_BYTES", 268435456, minimum=0)

AI_ENGINE = os.getenv("ENTROPY_AI_ENGINE", "auto").strip().lower()
BACKUP_MAX_VERSIONS_PER_FILE = _env_int("ENTROPY_BACKUP_MAX_VERSIONS", 10, minimum=1)

GANACHE_URL         = os.getenv("ENTROPY_GANACHE_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS    = os.getenv("ENTROPY_CONTRACT_ADDRESS", "0x7d5fd3ad0ffbeaAf9df76d1CF74058b5E14ddC1D").strip()
WALLET_ADDRESS      = os.getenv("ENTROPY_WALLET_ADDRESS", "0x4769fFb50b3bE30331056C2f174A0eaa64436E5d").strip()
ACCOUNT_INDEX         = _env_int("ENTROPY_ACCOUNT_INDEX", 0, minimum=0)
BLOCKCHAIN_FALLBACK = _env_bool("ENTROPY_BLOCKCHAIN_FALLBACK", True)

THREAT_EXCHANGE_DB         = str((BASE_PATH / "blockchain" / "exchange.db").resolve())
EXCHANGE_NODE_ID           = os.getenv("ENTROPY_NODE_ID", "").strip()
EXCHANGE_CONFIRM_THRESHOLD = _env_int("ENTROPY_EXCHANGE_CONFIRM_THRESHOLD", 2, minimum=2)
EXCHANGE_ENABLED           = _env_bool("ENTROPY_EXCHANGE", True)

DASHBOARD_HOST      = os.getenv("ENTROPY_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT      = _env_int("ENTROPY_DASHBOARD_PORT", 5000, minimum=1)
FLASK_HOST          = DASHBOARD_HOST
FLASK_PORT          = DASHBOARD_PORT
PUBLIC_DASHBOARD_URL= f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"

VICTIM_HOST         = os.getenv("ENTROPY_VICTIM_HOST", "127.0.0.1")
VICTIM_PORT         = _env_int("ENTROPY_VICTIM_PORT", 5001)
PUBLIC_VICTIM_URL   = f"http://{VICTIM_HOST}:{VICTIM_PORT}"

ATTACKER_HOST       = "0.0.0.0"
ATTACKER_PORT       = 8001
PUBLIC_ATTACKER_URL = f"http://127.0.0.1:{ATTACKER_PORT}"

DEBUG_MODE          = False
SECRET_KEY          = os.getenv("ENTROPY_SECRET_KEY", "entropy-local-development-only")
DRY_RUN             = _env_bool("ENTROPY_DRY_RUN", False)
CONTROL_TOKEN       = (os.getenv("ENTROPY_CONTROL_TOKEN")
                       or os.getenv("CONTROL_TOKEN")
                       or "").strip()

VAULT_USER          = os.getenv("ENTROPY_VAULT_USER", "victim_user")
VAULT_PIN           = os.getenv("ENTROPY_VAULT_PIN", "1234")
VAULT_SESSION_HOURS = _env_int("ENTROPY_VAULT_SESSION_HOURS", 8, minimum=0)

STATE_SIZE     = 10
ACTION_SIZE    = 4
LEARNING_RATE  = 0.001
GAMMA          = 0.95
EPSILON_START  = 1.0
EPSILON_END    = 0.01
EPSILON_DECAY  = 0.995
MEMORY_SIZE    = 10000
BATCH_SIZE     = 64
TARGET_UPDATE  = 10

ACTION_IGNORE               = 0
ACTION_ALERT                = 1
ACTION_TERMINATE            = 2
ACTION_TERMINATE_QUARANTINE = 3

NORMAL_ENTROPY_RANGES = {
    ".txt": (3.0, 5.5),   ".doc": (6.0, 7.5),   ".docx": (6.0, 7.5),
    ".pdf": (6.5, 7.8),   ".jpg": (7.0, 7.8),   ".jpeg": (7.0, 7.8),
    ".png": (6.5, 7.5),   ".mp4": (7.0, 7.9),   ".zip": (7.5, 8.0),
    ".exe": (5.0, 7.2),   ".py": (4.0, 6.0),    ".csv": (4.0, 6.0),
    ".xlsx": (6.0, 7.5),  ".dat": (4.0, 6.5),
}