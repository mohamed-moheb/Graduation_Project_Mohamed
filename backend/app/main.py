from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from app.blueprints import TECHNIQUE_BLUEPRINTS
import requests
import json
import os
import re
import sqlite3
import logging
import time
import hashlib as _hl
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext

# ==========================
# Logging
# ==========================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGIN", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

COLAB_API_URL = os.getenv("COLAB_API_URL", "https://unerased-oxymoronically-tabitha.ngrok-free.dev/run")

COLAB_HEADERS = {
    "ngrok-skip-browser-warning": "true",
    "Content-Type": "application/json",
}

# ==========================
# API KEYS
# ==========================
VT_API_KEY        = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "").strip()

log.info("VT_API_KEY loaded: %s",        bool(VT_API_KEY))
log.info("ABUSEIPDB_API_KEY loaded: %s", bool(ABUSEIPDB_API_KEY))
log.info("ANTHROPIC_API_KEY loaded: %s", bool(ANTHROPIC_API_KEY))
log.info("SHODAN_API_KEY loaded: %s",    bool(SHODAN_API_KEY))

# ==========================
# AUTH CONSTANTS
# ==========================
SECRET_KEY                = "attcksmith-secret-key-2024"
ALGORITHM                 = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
DB_PATH                   = os.path.join(os.path.dirname(__file__), "attcksmith.db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security    = HTTPBearer(auto_error=False)

# ==========================
# DATABASE
# ==========================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ioc_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            context TEXT,
            submitted_by TEXT NOT NULL,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result_json TEXT,
            rule_hash TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_hash TEXT UNIQUE NOT NULL,
            rule_content TEXT NOT NULL,
            technique_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            submitted_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            correlation_json TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaign_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            context TEXT,
            result_json TEXT,
            submission_id INTEGER,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    """)
    for username, password, role in [
        ("admin",    "admin123", "admin"),
        ("analyst1", "pass123",  "analyst"),
        ("analyst2", "pass123",  "analyst"),
    ]:
        if not c.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, pwd_context.hash(password), role)
            )
    conn.commit()
    conn.close()

init_db()

# ==========================
# JWT
# ==========================
def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_payload_from_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token: Optional[str] = Query(None),
):
    if credentials:
        return get_payload_from_token(credentials.credentials)
    elif token:
        return get_payload_from_token(token)
    raise HTTPException(status_code=401, detail="Authentication required")

def require_admin(payload=Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

# ==========================
# PYDANTIC MODELS
# ==========================
class LoginRequest(BaseModel):
    username: str
    password: str

class IOCCheckRequest(BaseModel):
    ioc_value: str

class IOCSaveRequest(BaseModel):
    ioc_type: str
    ioc_value: str
    context: Optional[str] = None
    result_json: str
    rule_hash: Optional[str] = None

class IOCRequest(BaseModel):
    ioc_type: str
    ioc_value: str
    context: str

class ProjectionRequest(BaseModel):
    ioc_type: str
    ioc_value: str
    context: str
    selected_apt: Optional[str] = None

class CandidatesRequest(BaseModel):
    mapped_techniques: List[str]

# ==========================
# AUTH ROUTES
# ==========================
@app.post("/auth/login")
async def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    conn.close()
    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"username": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer",
            "username": user["username"], "role": user["role"]}

# ==========================
# SUBMISSION ROUTES
# ==========================
@app.get("/submissions/all")
async def get_all_submissions(payload=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, ioc_type, ioc_value, context, submitted_by,
               submitted_at, result_json, rule_hash
        FROM ioc_submissions ORDER BY submitted_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/submissions/mine")
async def get_my_submissions(payload=Depends(verify_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM ioc_submissions WHERE submitted_by = ? ORDER BY submitted_at DESC",
        (payload["username"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/submissions/stats")
async def get_stats(payload=Depends(verify_token)):
    conn = get_db()

    def count_apts(rows):
        count = 0
        for r in rows:
            try:
                d = json.loads(r["result_json"])
            # Check all keys where APT data may be stored
                if (d.get("apt_projection") or
                    d.get("apts") or
                    d.get("apt_groups") or
                # apt_projections is the actual key used by save-apt-projection endpoint
                    (d.get("apt_projections") and len(d["apt_projections"]) > 0)):
                    count += 1
            except Exception:
                pass
        return count

    def count_rules(rows):
        count = 0
        for r in rows:
            try:
                d = json.loads(r["result_json"])
                count += len(d.get("candidate_rules") or [])
                count += len(d.get("predicted_rules") or [])
            except Exception:
                pass
        return count

    if payload["role"] == "admin":
        total       = conn.execute("SELECT COUNT(*) as c FROM ioc_submissions").fetchone()["c"]
        analysts    = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='analyst'").fetchone()["c"]
        type_counts = conn.execute("SELECT ioc_type, COUNT(*) as count FROM ioc_submissions GROUP BY ioc_type").fetchall()
        daily       = conn.execute("""
            SELECT DATE(submitted_at) as date, COUNT(*) as count
            FROM ioc_submissions
            WHERE submitted_at >= DATE('now', '-7 days')
            GROUP BY DATE(submitted_at) ORDER BY date ASC
        """).fetchall()
        all_subs_rows = conn.execute(
            "SELECT result_json FROM ioc_submissions WHERE result_json IS NOT NULL"
        ).fetchall()
        apt_count   = count_apts(all_subs_rows)
        rules_count = count_rules(all_subs_rows)
        total_campaigns = conn.execute("SELECT COUNT(*) as c FROM campaigns").fetchone()["c"]
        conn.close()
        return {"total_submissions": total, "total_analysts": analysts,
                "rules_generated": rules_count, "apts_detected": apt_count,
                "total_campaigns": total_campaigns,
                "ioc_type_counts": [dict(r) for r in type_counts],
                "daily_submissions": [dict(r) for r in daily]}
    else:
        username    = payload["username"]
        total       = conn.execute(
            "SELECT COUNT(*) as c FROM ioc_submissions WHERE submitted_by = ?", (username,)
        ).fetchone()["c"]

        type_counts = conn.execute(
            "SELECT ioc_type, COUNT(*) as count FROM ioc_submissions WHERE submitted_by = ? GROUP BY ioc_type",
            (username,)
        ).fetchall()

        user_subs = conn.execute(
            "SELECT result_json FROM ioc_submissions WHERE submitted_by = ? AND result_json IS NOT NULL",
            (username,)
        ).fetchall()

        apt_count = count_apts(user_subs)
        rules_count = count_rules(user_subs)

        total_campaigns = conn.execute(
            "SELECT COUNT(*) as c FROM campaigns WHERE submitted_by = ?", (username,)
        ).fetchone()["c"]

        conn.close()
        return {
            "total_submissions": total,
            "rules_generated": rules_count,
            "apts_detected": apt_count,
            "total_campaigns": total_campaigns,
            "ioc_type_counts": [dict(r) for r in type_counts]
        }

@app.post("/submissions/check")
async def check_submission(req: IOCCheckRequest, payload=Depends(verify_token)):
    conn = get_db()

    # Check if same analyst already submitted this IOC
    own = conn.execute(
        """
        SELECT * FROM ioc_submissions
        WHERE ioc_value = ? AND submitted_by = ?
        ORDER BY submitted_at DESC LIMIT 1
        """,
        (req.ioc_value, payload["username"])
    ).fetchone()

    if own:
        conn.close()
        return {"exists": True, "own": True, "submission": dict(own)}

    # Check if a different analyst submitted this IOC
    other = conn.execute(
        """
        SELECT * FROM ioc_submissions
        WHERE ioc_value = ?
        ORDER BY submitted_at DESC LIMIT 1
        """,
        (req.ioc_value,)
    ).fetchone()

    conn.close()

    if other:
        return {"exists": True, "own": False, "submission": dict(other)}

    return {"exists": False, "own": False, "submission": None}

@app.post("/submissions/save")
async def save_submission(req: IOCSaveRequest, payload=Depends(verify_token)):
    conn = get_db()

    # Deduplicate: same IOC value saved by same user in the last 60 seconds
    recent = conn.execute("""
        SELECT id FROM ioc_submissions
        WHERE ioc_value = ? AND submitted_by = ?
        AND submitted_at >= datetime('now', '-60 seconds')
    """, (req.ioc_value, payload["username"])).fetchone()

    if recent:
        conn.close()
        return {"id": recent["id"], "message": "Already saved (deduplicated)"}

    cursor = conn.execute("""
        INSERT INTO ioc_submissions (ioc_type, ioc_value, context, submitted_by, result_json, rule_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (req.ioc_type, req.ioc_value, req.context, payload["username"], req.result_json, req.rule_hash))

    submission_id = cursor.lastrowid

    if req.rule_hash:
        try:
            result       = json.loads(req.result_json)
            rule_content = result.get("detection_rules") or result.get("candidate_rules", "")
            if isinstance(rule_content, (dict, list)):
                rule_content = json.dumps(rule_content)

            techniques   = result.get("techniques", [])
            technique_id = ""

            if techniques and isinstance(techniques[0], dict):
                technique_id = techniques[0].get("id", "")
            elif techniques and isinstance(techniques[0], str):
                technique_id = techniques[0]

            conn.execute(
                "INSERT OR IGNORE INTO rules (rule_hash, rule_content, technique_id) VALUES (?, ?, ?)",
                (req.rule_hash, str(rule_content), technique_id)
            )
        except Exception:
            pass

    conn.commit()
    conn.close()
    return {"id": submission_id, "message": "Saved successfully"}
@app.delete("/submissions/{submission_id}")
async def delete_submission(submission_id: int, payload=Depends(require_admin)):
    conn = get_db()
    sub = conn.execute(
        "SELECT rule_hash FROM ioc_submissions WHERE id = ?", (submission_id,)
    ).fetchone()
    result = conn.execute(
        "DELETE FROM ioc_submissions WHERE id = ?", (submission_id,)
    )
    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Submission not found")
    if sub and sub["rule_hash"]:
        other = conn.execute(
            "SELECT id FROM ioc_submissions WHERE rule_hash = ?",
            (sub["rule_hash"],)
        ).fetchone()
        if not other:
            conn.execute(
                "DELETE FROM rules WHERE rule_hash = ?", (sub["rule_hash"],)
            )
    conn.commit()
    conn.close()
    return {"message": "Deleted successfully"}

class AptProjectionSaveRequest(BaseModel):
    submission_id: int
    apt_projection_result: dict

@app.post("/submissions/save-apt-projection")
async def save_apt_projection(req: AptProjectionSaveRequest, payload=Depends(verify_token)):
    conn = get_db()
    row = conn.execute(
        "SELECT result_json FROM ioc_submissions WHERE id = ?",
        (req.submission_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Submission not found")
    try:
        existing = json.loads(row["result_json"] or "{}")
    except Exception:
        existing = {}

    projections = existing.get("apt_projections", [])
    apt_name = (req.apt_projection_result.get("selected_apt") or {}).get("apt_name", "")
    projections = [
        p for p in projections
        if not (p.get("analyst") == payload["username"] and
                (p.get("selected_apt") or {}).get("apt_name", "") == apt_name)
    ]
    projections.append({
        "analyst":                   payload["username"],
        "projected_at":              now_iso(),
        "selected_apt":              req.apt_projection_result.get("selected_apt"),
        "predicted_next_step":       req.apt_projection_result.get("predicted_next_step"),
        "predicted_rules":           req.apt_projection_result.get("predicted_rules", []),
        "candidate_next_techniques": req.apt_projection_result.get("candidate_next_techniques", []),
    })
    existing["apt_projections"] = projections
    conn.execute(
        "UPDATE ioc_submissions SET result_json = ? WHERE id = ?",
        (json.dumps(existing), req.submission_id)
    )
    conn.commit()
    conn.close()
    return {"message": "APT projection saved"}

# ==========================
# Helpers
# ==========================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_ioc_type(ioc_type: str) -> str:
    t = (ioc_type or "").strip().lower()
    if t in {"hash", "filehash", "file_hash"}:           return "file_hash"
    if t in {"ip", "ip_address", "ipaddress"}:           return "ip"
    if t in {"domain", "fqdn"}:                          return "domain"
    if t in {"url", "uri", "link"}:                      return "url"
    if t in {"email", "email_address", "mail"}:          return "email"
    if t in {"process", "process_command", "command"}:   return "process_command"
    if t in {"registry", "registry_key", "regkey"}:      return "registry_key"
    return t

def is_valid_ip(ip: str) -> bool:
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip or ""):
        return False
    parts = ip.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ==========================
# RISK SCORING SYSTEM
# ==========================
# ============================================================
# TECHNIQUE SEVERITY SCORES
# Based on MITRE ATT&CK technique impact level
# Scale: 0-100
# ============================================================
TECHNIQUE_SEVERITY: Dict[str, int] = {
    # Impact — highest severity
    "T1486": 100,  # Ransomware
    "T1485": 100,  # Data Destruction
    "T1561": 100,  # Disk Wipe
    "T1561.001": 100,
    "T1561.002": 100,
    "T1495": 95,   # Firmware Corruption
    "T1529": 90,   # System Shutdown/Reboot
    "T1491": 85,   # Defacement
    "T1491.001": 85,
    "T1491.002": 85,
    "T1490": 90,   # Inhibit System Recovery
    "T1489": 80,   # Service Stop
    "T1499": 75,   # Endpoint DoS
    "T1498": 75,   # Network DoS
    "T1496": 70,   # Resource Hijacking

    # Credential Access — very high severity
    "T1003":     95,  # OS Credential Dumping
    "T1003.001": 95,  # LSASS Memory
    "T1003.002": 90,  # SAM
    "T1003.003": 95,  # NTDS
    "T1003.004": 90,  # LSA Secrets
    "T1003.005": 85,  # Cached Domain Creds
    "T1003.006": 95,  # DCSync
    "T1558.001": 95,  # Golden Ticket
    "T1558.002": 90,  # Silver Ticket
    "T1558.003": 85,  # Kerberoasting
    "T1558.004": 85,  # AS-REP Roasting
    "T1557.001": 85,  # LLMNR Poisoning
    "T1552.001": 80,  # Credentials in Files
    "T1552.002": 80,  # Credentials in Registry
    "T1539":     75,  # Steal Web Session Cookie
    "T1555.003": 75,  # Browser Credentials
    "T1056.001": 70,  # Keylogging

    # Lateral Movement — high severity
    "T1021.001": 80,  # RDP
    "T1021.002": 80,  # SMB
    "T1021.003": 80,  # DCOM
    "T1021.004": 75,  # SSH
    "T1021.006": 75,  # WinRM
    "T1550.002": 90,  # Pass the Hash
    "T1550.003": 90,  # Pass the Ticket
    "T1210":     85,  # Exploit Remote Services
    "T1534":     70,  # Internal Spearphishing
    "T1570":     75,  # Lateral Tool Transfer
    "T1563.002": 80,  # RDP Session Hijacking

    # Exfiltration — high severity
    "T1041":     80,  # Exfil over C2
    "T1048":     80,  # Exfil over Alt Protocol
    "T1048.001": 80,
    "T1048.002": 80,
    "T1048.003": 80,
    "T1567":     75,  # Exfil to Web Service
    "T1567.002": 75,  # Cloud Storage Exfil
    "T1537":     75,  # Transfer to Cloud

    # Privilege Escalation — high severity
    "T1068":     85,  # Exploit for PrivEsc
    "T1548.002": 80,  # UAC Bypass
    "T1055":     80,  # Process Injection
    "T1055.001": 80,
    "T1055.012": 80,  # Process Hollowing
    "T1134.001": 75,  # Token Impersonation
    "T1134.002": 75,

    # C2 — medium-high severity
    "T1071.001": 65,  # Web Protocols C2
    "T1071.004": 65,  # DNS C2
    "T1573":     70,  # Encrypted Channel
    "T1573.001": 70,
    "T1573.002": 70,
    "T1090.003": 65,  # Tor proxy
    "T1095":     65,  # Non-standard protocol
    "T1571":     60,  # Non-standard port
    "T1572":     65,  # Protocol Tunneling

    # Defense Evasion — medium severity
    "T1562.001": 65,  # Disable Security Tools
    "T1562.002": 60,  # Disable Event Logging
    "T1070.001": 65,  # Clear Event Logs
    "T1027":     55,  # Obfuscated Files
    "T1218.005": 60,  # Mshta
    "T1218.010": 60,  # Regsvr32
    "T1218.011": 60,  # Rundll32
    "T1548":     70,  # Abuse Elevation Control
    "T1140":     55,  # Deobfuscate
    "T1036":     55,  # Masquerading
    "T1553.004": 60,  # Root Certificate

    # Persistence — medium severity
    "T1547.001": 60,  # Registry Run Keys
    "T1543.003": 65,  # Windows Service
    "T1546.003": 70,  # WMI Event Subscription
    "T1546.008": 65,  # Accessibility Features
    "T1505.003": 85,  # Web Shell
    "T1574.001": 60,  # DLL Hijacking
    "T1197":     55,  # BITS Jobs

    # Execution — medium severity
    "T1059.001": 60,  # PowerShell
    "T1059.003": 55,  # CMD
    "T1059.005": 55,  # VBScript
    "T1047":     65,  # WMI
    "T1053.005": 60,  # Scheduled Task
    "T1204.002": 55,  # Malicious File
    "T1106":     60,  # Native API

    # Discovery — lower severity
    "T1082":     30,  # System Info
    "T1083":     25,  # File Discovery
    "T1057":     30,  # Process Discovery
    "T1046":     35,  # Network Scan
    "T1087.001": 35,  # Local Account Enum
    "T1087.002": 40,  # Domain Account Enum
    "T1069.001": 35,  # Local Groups
    "T1069.002": 40,  # Domain Groups
    "T1018":     30,  # Remote System Discovery
    "T1016":     25,  # Network Config Discovery
    "T1033":     20,  # Current User Discovery
    "T1518.001": 35,  # Security Software Discovery
    "T1482":     45,  # Domain Trust Discovery

    # Initial Access — varies
    "T1190":     75,  # Exploit Public App
    "T1566.001": 60,  # Spearphishing Attachment
    "T1566.002": 60,  # Spearphishing Link
    "T1078":     70,  # Valid Accounts
    "T1133":     65,  # External Remote Services
    "T1189":     65,  # Drive-by Compromise
    "T1195.002": 80,  # Supply Chain

    # Reconnaissance — low severity
    "T1595":     20,  # Active Scanning
    "T1592":     20,  # Gather Victim Host Info
    "T1589":     20,  # Gather Victim Identity
    "T1590":     20,  # Gather Victim Network Info
    "T1598":     25,  # Phishing for Info
}

# Default severity for unmapped techniques by tactic
TACTIC_DEFAULT_SEVERITY: Dict[str, int] = {
    "impact":               85,
    "exfiltration":         75,
    "lateral-movement":     70,
    "credential-access":    75,
    "privilege-escalation": 65,
    "command-and-control":  60,
    "collection":           55,
    "defense-evasion":      55,
    "persistence":          55,
    "execution":            50,
    "discovery":            30,
    "initial-access":       55,
    "resource-development": 15,
    "reconnaissance":       15,
}

# Kill chain stage scores (max stage reached → score)
TACTIC_KILL_CHAIN_SCORE: Dict[str, int] = {
    "reconnaissance":       10,
    "resource-development": 10,
    "initial-access":       30,
    "execution":            50,
    "persistence":          55,
    "privilege-escalation": 65,
    "defense-evasion":      60,
    "credential-access":    75,
    "discovery":            45,
    "lateral-movement":     80,
    "collection":           70,
    "command-and-control":  75,
    "exfiltration":         90,
    "impact":              100,
}


def get_technique_severity(tid: str, tactics: List[str]) -> int:
    """
    Return severity score for a technique.
    Checks exact match first, then base technique, then tactic default.
    """
    tid_upper = tid.strip().upper()

    # Exact match
    if tid_upper in TECHNIQUE_SEVERITY:
        return TECHNIQUE_SEVERITY[tid_upper]

    # Base technique (strip sub-technique)
    base = tid_upper.split(".")[0]
    if base in TECHNIQUE_SEVERITY:
        return TECHNIQUE_SEVERITY[base]

    # Tactic default
    for tactic in (tactics or []):
        if tactic.lower() in TACTIC_DEFAULT_SEVERITY:
            return TACTIC_DEFAULT_SEVERITY[tactic.lower()]

    return 40  # fallback medium


def compute_technique_severity_score(techniques: List[Dict[str, Any]]) -> float:
    """
    Returns the MAX severity across all mapped techniques.
    One critical technique makes the whole assessment critical.
    """
    if not techniques:
        return 0.0
    scores = []
    for tech in techniques:
        tid    = (tech.get("id") or "").strip().upper()
        tactics = tech.get("tactics") or []
        if tid:
            scores.append(get_technique_severity(tid, tactics))
    return float(max(scores)) if scores else 0.0


def compute_kill_chain_score(techniques: List[Dict[str, Any]]) -> float:
    """
    Returns score based on the furthest kill chain stage reached
    across all mapped techniques.
    """
    if not techniques:
        return 0.0

    max_score = 0.0
    for tech in techniques:
        tid = (tech.get("id") or "").strip().upper()
        # Use tactics from technique object if present
        tactic_list = tech.get("tactics") or []
        # Also check TECHNIQUE_TO_TACTICS global
        if not tactic_list and tid in TECHNIQUE_TO_TACTICS:
            tactic_list = TECHNIQUE_TO_TACTICS[tid]

        for tactic in tactic_list:
            score = TACTIC_KILL_CHAIN_SCORE.get(tactic.lower(), 0)
            if score > max_score:
                max_score = score

    return max_score


def compute_reputation_score(
    enrichment: Optional[Dict[str, Any]],
    ioc_type: str
) -> float:
    """
    Compute external reputation score from enrichment sources.
    Weighted by IOC type relevance.
    """
    if not enrichment or not isinstance(enrichment, dict):
        return 0.0

    rep = enrichment.get("reputation", {}) or {}
    clf = enrichment.get("classification", {}) or {}
    inf = enrichment.get("infrastructure", {}) or {}

    vt    = float(rep.get("virustotal_score", 0) or 0)
    abuse = float(rep.get("abuse_confidence",  0) or 0)

    # Shodan risk signals
    shodan_score = 0.0
    if clf.get("vulns"):
        shodan_score = 100.0
    elif any(p in (inf.get("open_ports") or []) for p in [23, 445, 3389, 4444, 5900]):
        shodan_score = 60.0

    # URLScan
    urlscan_hits = float(clf.get("urlscan_hits",      0) or 0)
    urlscan_mal  = float(clf.get("urlscan_malicious", 0) or 0)
    urlscan_score = clamp((urlscan_mal / urlscan_hits) * 100) if urlscan_hits > 0 else 0.0

    # MalwareBazaar
    mb_score = 100.0 if clf.get("malwarebazaar_name") else 0.0

    # Weighted by IOC type
    if ioc_type == "ip":
        return clamp(0.40*vt + 0.30*abuse + 0.20*shodan_score + 0.10*urlscan_score)
    elif ioc_type == "domain":
        return clamp(0.50*vt + 0.30*urlscan_score + 0.20*abuse)
    elif ioc_type == "url":
        return clamp(0.50*vt + 0.50*urlscan_score)
    elif ioc_type == "file_hash":
        return clamp(0.60*vt + 0.40*mb_score)
    elif ioc_type in ("process_command", "registry_key"):
        # No external intel for these — rely on behavior flags
        risk = float(enrichment.get("risk_score", 0) or 0)
        return clamp(risk)
    else:
        return clamp(vt)


def compute_risk_score(
    techniques: List[Dict[str, Any]],
    enrichment: Optional[Dict[str, Any]],
    ioc_type: str,
) -> Dict[str, Any]:
    """
    Compute final risk score from three components:
      - Reputation score  (35%) — external intel
      - Technique severity (40%) — what techniques were mapped
      - Kill chain position (25%) — how far along the attack

    Returns risk_score (0-100), risk_level, and component breakdown.
    """
    reputation_score  = compute_reputation_score(enrichment, ioc_type)
    technique_score   = compute_technique_severity_score(techniques)
    kill_chain_score  = compute_kill_chain_score(techniques)

    # If no techniques mapped, fall back to reputation only
    if not techniques:
        final_score = reputation_score
    else:
        final_score = clamp(
            0.35 * reputation_score +
            0.40 * technique_score  +
            0.25 * kill_chain_score
        )

    # Boost: if enrichment already flags as high risk, don't let techniques drag it down
    enrich_risk = float((enrichment or {}).get("risk_score", 0) or 0)
    if enrich_risk >= 85 and final_score < 65:
        final_score = clamp(final_score * 0.5 + enrich_risk * 0.5)

    final_score = round(final_score, 1)
    level       = risk_level(int(final_score))

    return {
        "risk_score": final_score,
        "risk_level": level,
        "risk_components": {
            "reputation":      round(reputation_score, 1),
            "technique":       round(technique_score,  1),
            "kill_chain":      round(kill_chain_score, 1),
            "technique_count": len(techniques),
            "max_technique":   _get_max_severity_technique(techniques),
            "furthest_tactic": _get_furthest_tactic(techniques),
        }
    }


def _get_max_severity_technique(techniques: List[Dict[str, Any]]) -> str:
    """Return the technique ID with the highest severity."""
    if not techniques:
        return "—"
    best_tid   = "—"
    best_score = -1
    for tech in techniques:
        tid    = (tech.get("id") or "").strip().upper()
        tactics = tech.get("tactics") or []
        score  = get_technique_severity(tid, tactics)
        if score > best_score:
            best_score = score
            best_tid   = tid
    return best_tid


def _get_furthest_tactic(techniques: List[Dict[str, Any]]) -> str:
    """Return the tactic name at the furthest kill chain stage."""
    if not techniques:
        return "—"
    best_tactic = "—"
    best_score  = -1
    for tech in techniques:
        tactic_list = tech.get("tactics") or []
        tid = (tech.get("id") or "").strip().upper()
        if not tactic_list and tid in TECHNIQUE_TO_TACTICS:
            tactic_list = TECHNIQUE_TO_TACTICS[tid]
        for tactic in tactic_list:
            score = TACTIC_KILL_CHAIN_SCORE.get(tactic.lower(), 0)
            if score > best_score:
                best_score  = score
                best_tactic = tactic
    return best_tactic

def clamp(x: float, lo=0.0, hi=100.0) -> float:
    return max(lo, min(hi, x))

def risk_level(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 65: return "High"
    if score >= 40: return "Medium"
    if score > 0:   return "Low"
    return "Clean"

# ==========================
# INPUT VALIDATION
# ==========================
VALID_IOC_TYPES = {"ip", "domain", "url", "file_hash", "email", "process_command", "registry_key"}

def validate_ioc_request(ioc_type: str, ioc_value: str):
    if not ioc_value or not ioc_value.strip():
        raise HTTPException(status_code=422, detail="ioc_value must not be empty")
    if ioc_type not in VALID_IOC_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown ioc_type '{ioc_type}'. Must be one of: {sorted(VALID_IOC_TYPES)}")

# ==========================
# WAZUH RULE BUILDING HELPERS
# ==========================
LOGSOURCE_TO_PARENT_SID: Dict[tuple, int] = {
    ("windows", "process_creation"):   61600,
    ("windows", "network_connection"): 61603,
    ("windows", "dns_query"):          61500,
    ("windows", "registry_event"):     61613,
    ("windows", "file_event"):         61602,
    ("windows", "proxy"):              62000,
}

ALLOWED_WAZUH_FIELDS = {
    "win.eventdata.destinationIp", "win.eventdata.sourceIp",
    "win.eventdata.destinationPort", "win.eventdata.queryName",
    "win.eventdata.url", "win.eventdata.hashes",
    "win.eventdata.commandLine", "win.eventdata.image",
    "win.eventdata.parentImage", "win.eventdata.targetObject",
    "win.eventdata.details", "win.eventdata.user",
    "win.eventdata.targetFilename",
}

ALLOWED_OPS = {"equals", "contains", "startswith", "endswith"}

def build_mitre_block(mitre_ids: List[str]) -> str:
    if not mitre_ids: return ""
    lines = ["<mitre>"]
    for mid in mitre_ids:
        lines.append(f"  <id>{mid}</id>")
    lines.append("</mitre>")
    return "\n".join(lines)

def build_field_xml(field: str, modifier: str, value: str) -> Optional[str]:
    if not field: return None
    v = str(value)
    if modifier in ("contains", "endswith", "startswith"):
        vv = re.escape(v)
        if modifier == "contains":   pattern = f".*{vv}.*"
        elif modifier == "endswith": pattern = f"{vv}$"
        else:                        pattern = f"^{vv}"
        return f'<field name="{field}" type="pcre2">(?i){pattern}</field>'
    return f'<field name="{field}">{v}</field>'

def risk_score_to_wazuh_level(risk_score: int) -> int:
    if risk_score >= 85: return 15
    if risk_score >= 65: return 13
    if risk_score >= 40: return 10
    if risk_score > 0:   return 7
    return 5

# ==========================
# ANTHROPIC FALLBACK
# ==========================
ANTHROPIC_MITRE_SYSTEM = """
You are a senior SOC / DFIR analyst specializing in MITRE ATT&CK mapping.
Map the given IOC to MITRE ATT&CK techniques based strictly on observable behavior.

Rules:
- Only propose techniques directly supported by the context
- Each technique MUST have a specific behavioral justification
- Technique IDs must be real ATT&CK IDs in format Txxxx or Txxxx.xxx
- Output MUST be valid JSON only — no explanation, no markdown, no preamble
- If the context does not support any technique, return an empty techniques list
""".strip()

ANTHROPIC_PROJECTION_SYSTEM = """
You are a senior Threat Intelligence analyst.
Determine the MOST LIKELY next MITRE ATT&CK technique based on the detected
techniques, selected APT group, and observed context.

CRITICAL RULES:
- You MUST choose ONLY from the CANDIDATE_NEXT_TECHNIQUES list provided
- Copy the technique ID EXACTLY as written in the list
- Output MUST be valid JSON only — no explanation, no markdown
""".strip()

def _call_anthropic(system: str, user: str, max_tokens: int = 512) -> Optional[str]:
    if not ANTHROPIC_API_KEY:
        log.warning("Anthropic fallback requested but ANTHROPIC_API_KEY not set")
        return None
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]},
            timeout=60,
        )
        if resp.status_code == 200:
            content = resp.json().get("content", [])
            return content[0].get("text", "") if content else None
        log.error("Anthropic API returned %s: %s", resp.status_code, resp.text[:300])
        return None
    except Exception as e:
        log.error("Anthropic API call failed: %s", str(e))
        return None

def _safe_json_extract(raw: str) -> Optional[Dict]:
    if not raw: return None
    try:
        start = raw.find("{"); end = raw.rfind("}") + 1
        if start == -1 or end == 0: return None
        return json.loads(raw[start:end])
    except Exception:
        return None

def _mitre_fallback(ioc_type: str, ioc_value: str, context: str) -> Optional[Dict]:
    user_msg = f"""IOC Type: {ioc_type}
IOC: {ioc_value}
Context: {context}

Respond ONLY with valid JSON:
{{
  "ioc_type": "{ioc_type}",
  "ioc": "{ioc_value}",
  "techniques": [
    {{
      "id": "Txxxx.xxx",
      "reason": "Specific behavioral justification tied to the context"
    }}
  ]
}}"""
    raw = _call_anthropic(ANTHROPIC_MITRE_SYSTEM, user_msg, max_tokens=512)
    parsed = _safe_json_extract(raw)
    if not parsed:
        log.error("Anthropic fallback: failed to parse JSON from response")
        return None
    techniques = parsed.get("techniques", [])
    return {"status": "success", "source": "anthropic_fallback", "ioc_type": ioc_type,
            "ioc_value": ioc_value, "context": context, "techniques": techniques,
            "validated_techniques": [t["id"] for t in techniques if t.get("id")],
            "candidate_rules": [],
            "note": "MITRE mapping via Anthropic fallback — Colab was unreachable. Detection rules were not generated; restart Colab to get full output."}

def _projection_fallback(mapped_techniques, candidate_apts, candidate_next_techniques, context, enrichment) -> Dict:
    user_msg = f"""DETECTED TECHNIQUES: {mapped_techniques}
CANDIDATE APT GROUPS: {candidate_apts}
CANDIDATE_NEXT_TECHNIQUES (choose ONLY from this list): {candidate_next_techniques[:30]}
CONTEXT: {context}
ENRICHMENT: {enrichment or 'None'}

Select the SINGLE most probable next technique and respond ONLY with valid JSON:
{{
  "predicted_next_technique": {{
    "id": "Txxxx.xxx",
    "name": "Technique Name",
    "tactic": "MITRE Tactic",
    "why_this_is_next": "Clear logical progression explanation"
  }},
  "confidence": {{
    "score": 0,
    "level": "High | Medium | Low",
    "justification": "Why this confidence level"
  }}
}}"""
    raw = _call_anthropic(ANTHROPIC_PROJECTION_SYSTEM, user_msg, max_tokens=400)
    parsed = _safe_json_extract(raw)
    if not parsed:
        return {"error": "Both Colab and Anthropic fallback failed for projection"}
    parsed["source"] = "anthropic_fallback"
    return parsed

# ==========================
# Primary technique selection
# ==========================
def determine_primary_technique(techniques, candidate_rules):
    rule_count_map: Dict[str, int] = {}
    for rule in candidate_rules or []:
        mitre_field = rule.get("mitre")
        extracted_ids: List[str] = []
        if isinstance(mitre_field, list):
            for m in mitre_field:
                if isinstance(m, str) and "attack.t" in m.lower():
                    extracted_ids.append(m.replace("attack.", "").upper())
        elif isinstance(mitre_field, str):
            m = mitre_field.strip()
            if "attack.t" in m.lower():
                extracted_ids.append(m.replace("attack.", "").upper())
        for tid in extracted_ids:
            rule_count_map[tid] = rule_count_map.get(tid, 0) + 1
    for tech in techniques or []:
        tid = (tech.get("id") or "").strip().upper()
        tech["rule_count"] = rule_count_map.get(tid, 0)
    if not techniques: return None
    return sorted(techniques, key=lambda x: x.get("rule_count", 0), reverse=True)[0]

# ==========================
# Confidence scoring
# ==========================
TECH_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

TYPICAL_TACTICS_BY_IOC = {
    "ip":              {"command-and-control", "exfiltration", "discovery", "reconnaissance"},
    "domain":          {"command-and-control", "exfiltration", "reconnaissance"},
    "url":             {"command-and-control", "initial-access", "exfiltration"},
    "file_hash":       {"execution", "persistence", "defense-evasion", "credential-access", "command-and-control"},
    "email":           {"initial-access", "reconnaissance"},
    "process_command": {"execution", "defense-evasion", "persistence", "credential-access", "discovery", "command-and-control"},
    "registry_key":    {"persistence", "defense-evasion"},
}

GENERIC_REASON_PATTERNS = [
    r"justification based on observable behavior",
    r"\baligns with\b",
    r"\bfalls under\b",
    r"\btypically achieved\b",
]

def structure_score(data):
    return 100.0 if ("techniques" in data and isinstance(data.get("techniques"), list)) else 0.0

def technique_format_score(techniques):
    if not techniques: return 0.0
    good = sum(1 for t in techniques if TECH_ID_RE.match((t.get("id") or "").strip()))
    return (good / len(techniques)) * 100.0

def reasoning_quality_score(techniques):
    if not techniques: return 0.0
    def score_reason(text):
        if not text: return 0.0
        t = text.strip().lower()
        for pat in GENERIC_REASON_PATTERNS:
            if re.search(pat, t): return 40.0
        words = len(re.findall(r"\w+", t))
        if words >= 18: return 100.0
        if words >= 10: return 75.0
        if words >= 5:  return 50.0
        return 25.0
    return sum(score_reason(t.get("reason") or "") for t in techniques) / len(techniques)

def ioc_alignment_score(ioc_type, techniques):
    if not techniques: return 0.0
    allowed = TYPICAL_TACTICS_BY_IOC.get(ioc_type, set())
    if not allowed: return 70.0
    aligned = sum(1 for t in techniques if any(str(x).lower() in allowed for x in (t.get("tactics") or [])))
    return (aligned / len(techniques)) * 100.0

def compute_confidence_metrics(data, enrichment, ioc_type):
    techniques = data.get("techniques", []) or []
    validated  = data.get("validated_techniques", []) or []
    rules      = data.get("candidate_rules", []) or []
    s_struct = structure_score(data); s_fmt = technique_format_score(techniques)
    s_reason = reasoning_quality_score(techniques); s_align = ioc_alignment_score(ioc_type, techniques)
    model_reliability = min(0.25*s_struct + 0.25*s_fmt + 0.25*s_reason + 0.25*s_align, 92.0)
    if not techniques:                              rag_validation = 0.0
    elif len(validated) == len(techniques):         rag_validation = 100.0
    else:                                           rag_validation = (len(validated) / len(techniques)) * 100.0
    external = 0.0; external_detail = {}
    if enrichment and isinstance(enrichment, dict):
        rep = enrichment.get("reputation", {}) or {}; clf = enrichment.get("classification", {}) or {}
        vt = float(rep.get("virustotal_score", 0) or 0); abuse = float(rep.get("abuse_confidence", 0) or 0)
        shodan_score = 100.0 if clf.get("vulns") else (60.0 if any(p in (enrichment.get("infrastructure", {}) or {}).get("open_ports", []) for p in [23, 445, 3389, 4444, 5900]) else 0.0)
        urlscan_hits = float(clf.get("urlscan_hits", 0) or 0); urlscan_mal = float(clf.get("urlscan_malicious", 0) or 0)
        urlscan_score = clamp((urlscan_mal / urlscan_hits) * 100) if urlscan_hits > 0 else 0.0
        mb_score = 100.0 if clf.get("malwarebazaar_name") else 0.0
        external_detail = {"virustotal": round(vt, 1), "abuseipdb": round(abuse, 1), "shodan": round(shodan_score, 1), "urlscan": round(urlscan_score, 1), "malwarebazaar": round(mb_score, 1)}
        if ioc_type == "ip":          external = 0.40*vt + 0.30*abuse + 0.20*shodan_score + 0.10*urlscan_score
        elif ioc_type == "domain":    external = 0.50*vt + 0.30*urlscan_score + 0.20*abuse
        elif ioc_type == "url":       external = 0.50*vt + 0.50*urlscan_score
        elif ioc_type == "file_hash": external = 0.60*vt + 0.40*mb_score
        else:                         external = vt
        external = clamp(external)
    rule_count = len(rules)
    detection_strength = 0.0 if rule_count==0 else (15.0 if rule_count==1 else (35.0 if rule_count<=3 else (65.0 if rule_count<=6 else 90.0)))
    overall = clamp(0.25*model_reliability + 0.30*rag_validation + 0.25*external + 0.20*detection_strength)
    return {"model_reliability": round(model_reliability, 1), "rag_validation": round(clamp(rag_validation), 1),
            "external_intel_agreement": round(clamp(external), 1), "detection_strength": round(detection_strength, 1),
            "overall_threat_confidence": round(overall, 1),
            "explain": {"structure": round(s_struct, 1), "technique_format": round(s_fmt, 1),
                        "reasoning_quality": round(s_reason, 1), "ioc_alignment": round(s_align, 1),
                        "validated_techniques": len(validated), "returned_techniques": len(techniques),
                        "rules_generated": rule_count, "external_sources": external_detail}}

# ==========================
# ENRICHMENT ROUTER
# ==========================
@app.post("/api/ioc/enrich")
def enrich_ioc(req: IOCRequest):
    ioc_type = normalize_ioc_type(req.ioc_type)
    val = (req.ioc_value or "").strip()
    validate_ioc_request(ioc_type, val)
    try:
        if ioc_type == "ip":              return enrich_ip(val)
        if ioc_type == "domain":          return enrich_domain(val)
        if ioc_type == "url":             return enrich_url(val)
        if ioc_type == "file_hash":       return enrich_hash(val)
        if ioc_type == "email":           return enrich_email(val)
        if ioc_type == "process_command": return enrich_process(val)
        if ioc_type == "registry_key":    return enrich_registry(val)
        return {"status": "unsupported", "ioc_type": ioc_type, "ioc_value": val,
                "message": f"No enrichment available for type {ioc_type}", "enriched_at": now_iso()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# HEALTH CHECK
# ==========================
@app.get("/health")
def health():
    colab_ok = False
    try:
        r = requests.get(COLAB_API_URL.replace("/run", "/"), headers=COLAB_HEADERS, timeout=5)
        colab_ok = r.status_code < 500
    except Exception:
        pass
    return {"status": "ok", "colab_reachable": colab_ok, "anthropic_fallback": bool(ANTHROPIC_API_KEY),
            "enrichment_vt": bool(VT_API_KEY), "enrichment_abuseipdb": bool(ABUSEIPDB_API_KEY),
            "enrichment_shodan": bool(SHODAN_API_KEY), "enrichment_urlscan": True,
            "enrichment_malwarebazaar": True, "checked_at": now_iso()}

# ==========================
# SUBMIT IOC
# ==========================
@app.post("/api/ioc/submit")
def submit_ioc(req: IOCRequest):
    ioc_type = normalize_ioc_type(req.ioc_type)
    validate_ioc_request(ioc_type, req.ioc_value)
    log.info("IOC submit — type=%s value=%s", ioc_type, req.ioc_value)

    data = None
    colab_ok = False

    try:
        _pre_risk = 0
        if ioc_type == "process_command":
            _pre_risk = enrich_process(req.ioc_value).get("risk_score", 0)
        elif ioc_type == "registry_key":
            _pre_risk = enrich_registry(req.ioc_value).get("risk_score", 0)

        response = requests.post(
            COLAB_API_URL,
            json={
                "ioc_type": ioc_type,
                "ioc_value": req.ioc_value,
                "context": req.context,
                "risk_score": _pre_risk
            },
            headers=COLAB_HEADERS,
            timeout=180,
        )

        log.info("Colab responded — status=%s", response.status_code)

        if response.status_code == 200:
            raw_text = response.text
            start = raw_text.find("{")
            end = raw_text.rfind("}") + 1

            if start != -1 and end > 0:
                data = json.loads(raw_text[start:end])
                colab_ok = True
            else:
                log.warning("Colab returned 200 but no JSON — falling back")
        else:
            log.warning("Colab returned status %s — falling back", response.status_code)

    except requests.RequestException as e:
        log.warning("Colab unreachable: %s — trying Anthropic fallback", str(e))

    if not colab_ok:
        log.info("Using Anthropic API fallback for MITRE mapping")
        data = _mitre_fallback(ioc_type, req.ioc_value, req.context)
        if not data:
            raise HTTPException(
                status_code=502,
                detail="Both Colab and Anthropic fallback failed. Check ANTHROPIC_API_KEY env var and Colab tunnel."
            )

    if "techniques" not in data or not isinstance(data.get("techniques"), list):
        validated = data.get("validated_techniques", [])
        data["techniques"] = (
            [{"id": tid, "reason": None} for tid in validated]
            if isinstance(validated, list) else []
        )

    data.setdefault("ioc_type", ioc_type)
    data.setdefault("ioc_value", req.ioc_value)
    data.setdefault("context", req.context)

    enrichment_data: Optional[Dict[str, Any]] = None
    try:
        enrichment_data = {
            "ip": enrich_ip,
            "domain": enrich_domain,
            "url": enrich_url,
            "file_hash": enrich_hash,
            "email": enrich_email,
            "process_command": enrich_process,
            "registry_key": enrich_registry,
        }.get(ioc_type, lambda v: None)(req.ioc_value)
    except Exception as e:
        enrichment_data = {
            "status": "error",
            "message": str(e),
            "enriched_at": now_iso()
        }

    data["enrichment"] = enrichment_data

    primary = determine_primary_technique(
        data.get("techniques", []),
        data.get("candidate_rules", [])
    )
    if primary:
        tactics = primary.get("tactics") or []
        data["primary_technique"] = {
            "id": primary.get("id"),
            "name": primary.get("name"),
            "tactics": tactics,
            "rule_count": primary.get("rule_count", 0)
        }
        data["primary_tactic"] = tactics[0] if tactics else None

    data["confidence_metrics"] = compute_confidence_metrics(data, enrichment_data, ioc_type)

    # Code 1 risk scoring
    risk_result = compute_risk_score(
        techniques=data.get("techniques", []) or [],
        enrichment=enrichment_data,
        ioc_type=ioc_type,
    )
    data["risk_score"] = risk_result["risk_score"]
    data["risk_level"] = risk_result["risk_level"]
    data["risk_components"] = risk_result["risk_components"]

    log.info(
        "Risk — score=%.1f level=%s technique=%s tactic=%s",
        risk_result["risk_score"],
        risk_result["risk_level"],
        risk_result["risk_components"]["max_technique"],
        risk_result["risk_components"]["furthest_tactic"],
    )

    # Context-derived blueprint rules from code 2
    risk_score_val = data.get("risk_score", 0) or 0
    wazuh_level = risk_score_to_wazuh_level(int(risk_score_val))

    existing_rules = data.get("candidate_rules", []) or []

    def _conditions_key(conditions):
        return frozenset((f, v) for f, _, v in conditions)

    existing_rule_ids = {
        r.get("rule_id")
        for r in existing_rules
        if r.get("rule_id") is not None
    }

    existing_cond_keys = set()
    for r in existing_rules:
        xml = r.get("wazuh_xml", "") or ""
        pairs = re.findall(r'<field name="([^"]+)"[^>]*>([^<]+)<', xml)
        if pairs:
            existing_cond_keys.add(frozenset(pairs))

    context_rules = []

    # Build full technique list: mapped technique + any blueprint sub-techniques
    mapped_tids = set()
    for tech in data.get("techniques", []):
        if isinstance(tech, str):
            tid = tech.strip().upper()
        else:
            tid = (tech.get("id") or "").strip().upper()

        if not tid or not re.match(r"^T\d{4}(\.\d{3})?$", tid):
            continue

        mapped_tids.add(tid)

        if "." not in tid:
            for blueprint_tid in TECHNIQUE_BLUEPRINTS:
                if blueprint_tid.startswith(tid + "."):
                    mapped_tids.add(blueprint_tid)

    for tid in sorted(mapped_tids):
        for i, bp in enumerate(TECHNIQUE_BLUEPRINTS.get(tid, [])):
            logsource = bp.get("logsource")
            conditions = bp.get("conditions", [])
            parent_sid = LOGSOURCE_TO_PARENT_SID.get(logsource) if logsource else None

            if not parent_sid or not conditions:
                continue

            safe_conditions = [
                (field, op, value)
                for field, op, value in conditions
                if field in ALLOWED_WAZUH_FIELDS and op in ALLOWED_OPS
            ]
            if not safe_conditions:
                continue

            # Deduplicate by condition fingerprint
            cond_key = _conditions_key(safe_conditions)
            if cond_key in existing_cond_keys:
                continue

            # Deduplicate by generated rule id
            raw = f"context_blueprint:{tid}:{i}:{ioc_type}"
            rule_id = 200000 + (int(_hl.sha256(raw.encode()).hexdigest(), 16) % 90000)

            if rule_id in existing_rule_ids:
                continue

            field_blocks = [
                fxml
                for fxml in [build_field_xml(f, o, v) for f, o, v in safe_conditions]
                if fxml
            ]
            if not field_blocks:
                continue

            fields_xml = "\n    ".join(field_blocks)
            mitre_xml = build_mitre_block([tid])
            level = max(1, min(15, wazuh_level))

            wazuh_xml = (
                f'<group name="windows,attack,context">\n'
                f'  <rule id="{rule_id}" level="{level}">\n'
                f'    <decoded_as>json</decoded_as>\n'
                f'    {fields_xml}\n'
                f'    <description>[CONTEXT] {tid} - {bp["name"]}</description>\n'
                f'    {mitre_xml}\n'
                f'  </rule>\n'
                f'</group>'
            )

            context_rules.append({
                "candidate_type": "context_blueprint",
                "rule_id": rule_id,
                "technique_id": tid,
                "description": bp["name"],
                "mitre": [tid],
                "wazuh_xml": wazuh_xml,
                "wazuh_level": level,
            })

            existing_rule_ids.add(rule_id)
            existing_cond_keys.add(cond_key)

    data["candidate_rules"] = existing_rules + context_rules

    log.info(
        "Rules — Colab: %d, Context blueprints: %d, Total: %d",
        len(existing_rules),
        len(context_rules),
        len(existing_rules) + len(context_rules),
    )

    return data

# ==========================
# ENRICHMENT IMPLEMENTATIONS
# ==========================
def enrich_ip(ip: str) -> Dict[str, Any]:
    if not is_valid_ip(ip):
        return {"status": "error", "ioc_type": "ip", "ioc_value": ip, "message": "Invalid IP format", "enriched_at": now_iso()}
    result = {"status": "success", "ioc_type": "ip", "ioc_value": ip, "reputation": {}, "infrastructure": {},
              "classification": {}, "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    if VT_API_KEY:
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_API_KEY}, timeout=30)
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total    = detected + stats.get("harmless", 0) + stats.get("undetected", 0)
                result["reputation"]["virustotal_score"] = int((detected/total)*100) if total else 0
                result["reputation"]["detection_ratio"]  = f"{detected}/{total}" if total else "0/0"
                result["infrastructure"]["asn"]     = attrs.get("asn")
                result["infrastructure"]["country"] = attrs.get("country")
                result["classification"]["tags"]    = attrs.get("tags", [])
                result["classification"]["whois"]   = attrs.get("whois")
                if "tor" in " ".join(map(str, attrs.get("tags", []) or [])).lower():
                    result["risk_factors"].append("Tor-related tag in VirusTotal")
        except Exception as e:
            result.setdefault("sources", {})["virustotal"] = f"error: {e}"
    else:
        result.setdefault("sources", {})["virustotal"] = "api_key_missing"
    if ABUSEIPDB_API_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=30)
            if r.status_code == 200:
                d = r.json().get("data", {})
                abuse_score = int(d.get("abuseConfidenceScore", 0) or 0)
                result["reputation"]["abuse_confidence"] = abuse_score
                result["infrastructure"]["isp"] = d.get("isp")
                if abuse_score >= 60: result["risk_factors"].append("High AbuseIPDB confidence score")
        except Exception as e:
            result.setdefault("sources", {})["abuseipdb"] = f"error: {e}"
    else:
        result.setdefault("sources", {})["abuseipdb"] = "api_key_missing"
    if SHODAN_API_KEY:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": SHODAN_API_KEY}, timeout=30)
            if r.status_code == 200:
                d = r.json()
                open_ports = d.get("ports", []); vulns = list(d.get("vulns", {}).keys())
                result["infrastructure"]["open_ports"] = open_ports
                result["infrastructure"]["hostnames"]  = d.get("hostnames", [])
                result["classification"]["vulns"]      = vulns
                flagged = {22, 23, 445, 3389, 4444, 5900} & set(open_ports)
                if flagged: result["risk_factors"].append(f"High-risk ports open: {sorted(flagged)}")
                if vulns:   result["risk_factors"].append(f"Known CVEs on host: {vulns[:3]}")
            elif r.status_code == 404:
                result.setdefault("sources", {})["shodan"] = "no_data"
        except Exception as e:
            result.setdefault("sources", {})["shodan"] = f"error: {e}"
    else:
        result.setdefault("sources", {})["shodan"] = "api_key_missing"
    vt_score   = float(result["reputation"].get("virustotal_score", 0) or 0)
    abuse      = float(result["reputation"].get("abuse_confidence", 0) or 0)
    vuln_bonus = 15.0 if result["classification"].get("vulns") else 0.0
    result["risk_score"] = int(clamp(vt_score * 0.55 + abuse * 0.30 + vuln_bonus))
    result["risk_level"]  = risk_level(result["risk_score"])
    return result

def enrich_domain(domain: str) -> Dict[str, Any]:
    result = {"status": "success", "ioc_type": "domain", "ioc_value": domain, "reputation": {},
              "infrastructure": {}, "classification": {}, "risk_factors": [], "risk_score": 0,
              "risk_level": "Unknown", "enriched_at": now_iso()}
    if not VT_API_KEY:
        result.setdefault("sources", {})["virustotal"] = "api_key_missing"; return result
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": VT_API_KEY}, timeout=30)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total    = detected + stats.get("harmless", 0) + stats.get("undetected", 0)
            vt_score = int((detected/total)*100) if total else 0
            result["reputation"]["virustotal_score"] = vt_score
            result["reputation"]["detection_ratio"]  = f"{detected}/{total}" if total else "0/0"
            result["infrastructure"]["registrar"]    = attrs.get("registrar")
            result["infrastructure"]["categories"]   = attrs.get("categories", {})
            result["classification"]["creation_date"]    = attrs.get("creation_date")
            result["classification"]["last_dns_records"] = attrs.get("last_dns_records", [])
            if detected >= 5: result["risk_factors"].append("Multiple engine detections (domain)")
            result["risk_score"] = vt_score; result["risk_level"] = risk_level(vt_score)
        else:
            result.setdefault("sources", {})["virustotal"] = f"error_status_{r.status_code}"
    except Exception as e:
        result.setdefault("sources", {})["virustotal"] = f"error: {e}"
    try:
        r = requests.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 5},
                         headers={"Accept": "application/json"}, timeout=20)
        if r.status_code == 200:
            results_list = r.json().get("results", [])
            mal_hits = [x for x in results_list if x.get("verdicts", {}).get("overall", {}).get("malicious")]
            result["classification"]["urlscan_hits"]      = len(results_list)
            result["classification"]["urlscan_malicious"] = len(mal_hits)
            if mal_hits:
                result["risk_factors"].append(f"URLScan flagged {len(mal_hits)} malicious scan(s) for this domain")
                result["risk_score"] = min(result.get("risk_score", 0) + 20, 100)
                result["risk_level"] = risk_level(result["risk_score"])
    except Exception as e:
        result.setdefault("sources", {})["urlscan"] = f"error: {e}"
    return result

def enrich_url(url: str) -> Dict[str, Any]:
    result = {"status": "success", "ioc_type": "url", "ioc_value": url, "reputation": {},
              "classification": {}, "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    if not VT_API_KEY:
        result.setdefault("sources", {})["virustotal"] = "api_key_missing"; return result
    try:
        submit = requests.post("https://www.virustotal.com/api/v3/urls", headers={"x-apikey": VT_API_KEY}, data={"url": url}, timeout=30)
        if submit.status_code in (200, 201):
            url_id = submit.json().get("data", {}).get("id")
            if url_id:
                for attempt in range(3):
                    fetch = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=30)
                    if fetch.status_code == 200:
                        attrs = fetch.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
                        total    = detected + stats.get("harmless", 0) + stats.get("undetected", 0)
                        vt_score = int((detected/total)*100) if total else 0
                        result["reputation"]["virustotal_score"] = vt_score
                        result["reputation"]["detection_ratio"]  = f"{detected}/{total}" if total else "0/0"
                        result["classification"]["final_url"]    = attrs.get("last_final_url")
                        result["classification"]["categories"]   = attrs.get("categories", {})
                        if detected >= 3: result["risk_factors"].append("URL flagged by multiple engines")
                        result["risk_score"] = vt_score; result["risk_level"] = risk_level(vt_score); break
                    elif fetch.status_code == 404 and attempt < 2: time.sleep(2)
                    else: break
    except Exception as e:
        result.setdefault("sources", {})["virustotal"] = f"error: {e}"
    try:
        r = requests.get("https://urlscan.io/api/v1/search/", params={"q": f"page.url:{url}", "size": 3},
                         headers={"Accept": "application/json"}, timeout=20)
        if r.status_code == 200:
            results_list = r.json().get("results", [])
            mal_hits = [x for x in results_list if x.get("verdicts", {}).get("overall", {}).get("malicious")]
            result["classification"]["urlscan_hits"]      = len(results_list)
            result["classification"]["urlscan_malicious"] = len(mal_hits)
            if mal_hits:
                result["risk_factors"].append(f"URLScan flagged {len(mal_hits)} malicious scan(s) for this URL")
                result["risk_score"] = min(result.get("risk_score", 0) + 20, 100)
                result["risk_level"] = risk_level(result["risk_score"])
    except Exception as e:
        result.setdefault("sources", {})["urlscan"] = f"error: {e}"
    return result

def enrich_hash(file_hash: str) -> Dict[str, Any]:
    result = {"status": "success", "ioc_type": "file_hash", "ioc_value": file_hash, "reputation": {},
              "classification": {}, "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    if not VT_API_KEY:
        result.setdefault("sources", {})["virustotal"] = "api_key_missing"; return result
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey": VT_API_KEY}, timeout=30)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total    = detected + stats.get("harmless", 0) + stats.get("undetected", 0)
            vt_score = int((detected/total)*100) if total else 0
            result["reputation"]["virustotal_score"]                 = vt_score
            result["reputation"]["detection_ratio"]                  = f"{detected}/{total}" if total else "0/0"
            result["classification"]["type_description"]             = attrs.get("type_description")
            result["classification"]["meaningful_name"]              = attrs.get("meaningful_name")
            result["classification"]["names"]                        = attrs.get("names", [])
            result["classification"]["popular_threat_classification"]= attrs.get("popular_threat_classification", {})
            if detected >= 10: result["risk_factors"].append("High malicious detections on file hash")
            result["risk_score"] = vt_score; result["risk_level"] = risk_level(vt_score)
        else:
            result.setdefault("sources", {})["virustotal"] = f"error_status_{r.status_code}"
    except Exception as e:
        result.setdefault("sources", {})["virustotal"] = f"error: {e}"
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": file_hash}, timeout=20)
        if r.status_code == 200:
            d = r.json()
            if d.get("query_status") == "hash_found":
                data_list = d.get("data", [])
                if data_list:
                    entry = data_list[0]
                    result["classification"]["malwarebazaar_name"]   = entry.get("file_name")
                    result["classification"]["malwarebazaar_type"]   = entry.get("file_type")
                    result["classification"]["malwarebazaar_tags"]   = entry.get("tags", [])
                    result["classification"]["malwarebazaar_family"] = entry.get("signature")
                    result["risk_factors"].append("Hash confirmed in MalwareBazaar" + (f" — family: {entry.get('signature')}" if entry.get("signature") else ""))
                    result["risk_score"] = min(max(result.get("risk_score", 0), 80), 100)
                    result["risk_level"] = risk_level(result["risk_score"])
            elif d.get("query_status") == "hash_not_found":
                result.setdefault("sources", {})["malwarebazaar"] = "not_found"
    except Exception as e:
        result.setdefault("sources", {})["malwarebazaar"] = f"error: {e}"
    return result

def enrich_email(email: str) -> Dict[str, Any]:
    result = {"status": "success", "ioc_type": "email", "ioc_value": email, "classification": {},
              "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    e = (email or "").strip()
    if "@" not in e or e.count("@") != 1:
        result["status"] = "error"; result["risk_factors"].append("Invalid email format"); return result
    user, dom = e.split("@", 1)
    result["classification"]["local_part"] = user; result["classification"]["domain"] = dom
    risk = 0
    if any(x in user.lower() for x in ["admin", "support", "security", "billing", "payroll"]):
        risk += 10; result["risk_factors"].append("Impersonation-prone local part")
    if dom.lower().endswith((".zip", ".top", ".xyz", ".ru")):
        risk += 25; result["risk_factors"].append("Suspicious TLD for email domain")
    result["risk_score"] = min(risk, 100); result["risk_level"] = risk_level(result["risk_score"])
    return result

def enrich_process(command: str) -> Dict[str, Any]:
    cmd = (command or "").strip(); cmd_lower = cmd.lower()
    result = {"status": "success", "ioc_type": "process_command", "ioc_value": command,
              "behavior_flags": {}, "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    risk = 0
    if "powershell" in cmd_lower:
        result["behavior_flags"]["powershell_usage"] = True; risk += 20
    if "-enc" in cmd_lower or "base64" in cmd_lower:
        result["behavior_flags"]["encoded_execution"] = True; result["risk_factors"].append("Encoded/obfuscated execution"); risk += 40
    if "iex" in cmd_lower or "invoke-expression" in cmd_lower:
        result["behavior_flags"]["invoke_expression"] = True; result["risk_factors"].append("In-memory execution pattern (IEX)"); risk += 25
    if "mimikatz" in cmd_lower:
        result["behavior_flags"]["credential_dumping_reference"] = True; result["risk_factors"].append("Credential dumping tool reference"); risk += 50
    if "schtasks" in cmd_lower:
        result["behavior_flags"]["scheduled_task_usage"] = True; result["risk_factors"].append("Scheduled task usage (possible persistence)"); risk += 20
    result["risk_score"] = min(risk, 100); result["risk_level"] = risk_level(result["risk_score"])
    return result

def enrich_registry(key: str) -> Dict[str, Any]:
    k = (key or "").strip(); kl = k.lower()
    result = {"status": "success", "ioc_type": "registry_key", "ioc_value": key, "classification": {},
              "risk_factors": [], "risk_score": 0, "risk_level": "Unknown", "enriched_at": now_iso()}
    risk = 0
    persistence_markers = [
        r"\\software\\microsoft\\windows\\currentversion\\run",
        r"\\software\\microsoft\\windows\\currentversion\\runonce",
        r"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
        r"\\system\\currentcontrolset\\services",
    ]
    if any(re.search(p, kl) for p in persistence_markers):
        result["classification"]["category"] = "persistence"; result["risk_factors"].append("Common persistence registry location"); risk += 60
    if "\\image file execution options\\" in kl and "\\debugger" in kl:
        result["classification"]["category"] = "defense-evasion"; result["risk_factors"].append("IFEO Debugger hijack (possible persistence/defense evasion)"); risk += 80
    result["risk_score"] = min(risk, 100); result["risk_level"] = risk_level(result["risk_score"])
    return result

# ==========================
# MITRE ATT&CK ENGINE
# ==========================
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MITRE_DATA_PATH = os.path.join(BASE_DIR, "enterprise-attack.json")
APT_TO_TECHNIQUES:    Dict[str, List[str]] = {}
TECHNIQUE_TO_APTS:    Dict[str, List[str]] = {}
TECHNIQUE_TO_TACTICS: Dict[str, List[str]] = {}

def load_mitre_attack():
    global APT_TO_TECHNIQUES, TECHNIQUE_TO_APTS, TECHNIQUE_TO_TACTICS
    try:
        with open(MITRE_DATA_PATH, "r", encoding="utf-8") as f:
            attack_data = json.load(f)
        objects = attack_data.get("objects", [])
        techniques = {}; technique_tactics = {}; groups = {}; relationships = []
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        tid = ref["external_id"].upper()
                        techniques[obj["id"]] = tid
                        tacts = [ph["phase_name"].lower() for ph in obj.get("kill_chain_phases", [])
                                 if ph.get("kill_chain_name") == "mitre-attack" and ph.get("phase_name")]
                        if tacts: technique_tactics[tid] = sorted(set(tacts))
                        break
            if obj.get("type") == "intrusion-set" and not obj.get("revoked", False):
                groups[obj["id"]] = obj.get("name")
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                relationships.append(obj)
        for rel in relationships:
            src = rel.get("source_ref"); tgt = rel.get("target_ref")
            if src in groups and tgt in techniques:
                apt_name = groups[src]; technique_id = techniques[tgt]
                APT_TO_TECHNIQUES.setdefault(apt_name, []).append(technique_id)
                TECHNIQUE_TO_APTS.setdefault(technique_id, []).append(apt_name)
        TECHNIQUE_TO_TACTICS = technique_tactics
        log.info("MITRE loaded: %d APT groups, %d techniques with tactics", len(APT_TO_TECHNIQUES), len(TECHNIQUE_TO_TACTICS))
    except Exception as e:
        log.error("Failed to load MITRE dataset: %s", str(e))

load_mitre_attack()

# ==========================
# APT CANDIDATE MATCHING
# ==========================
def find_candidate_apts(mapped_techniques: List[str]) -> List[Dict[str, Any]]:
    apt_scores = {}
    for tech in mapped_techniques:
        for apt in TECHNIQUE_TO_APTS.get(tech.upper(), []):
            apt_scores[apt] = apt_scores.get(apt, 0) + 1
    return [{"apt_name": apt, "matching_techniques": score, "total_known_techniques": len(APT_TO_TECHNIQUES.get(apt, []))}
            for apt, score in sorted(apt_scores.items(), key=lambda x: x[1], reverse=True)[:5]]

# ==========================
# LLM NEXT TECHNIQUE PROJECTION
# ==========================
def predict_next_technique_with_llm(mapped_techniques, candidate_apts, candidate_next_techniques, context, enrichment):
    payload = {"current_techniques": mapped_techniques, "candidate_apts": candidate_apts,
               "candidate_next_techniques": candidate_next_techniques, "context": context, "enrichment_summary": enrichment}
    try:
        response = requests.post(COLAB_API_URL, json={"mode": "next_technique_prediction", "payload": payload},
                                 headers=COLAB_HEADERS, timeout=120)
        if response.status_code == 200:
            result = response.json()
            if "error" not in result: return result
            log.warning("Colab projection returned error — falling back: %s", result.get("error"))
        else:
            log.warning("Colab projection returned %s — falling back", response.status_code)
    except Exception as e:
        log.warning("Colab projection unreachable: %s — trying Anthropic fallback", str(e))
    log.info("Using Anthropic API fallback for attack projection")
    return _projection_fallback(mapped_techniques=mapped_techniques, candidate_apts=candidate_apts,
                                candidate_next_techniques=candidate_next_techniques, context=context, enrichment=enrichment)

# ==========================
# TACTIC PROGRESSION HELPERS
# ==========================
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
TACTIC_TO_STAGE = {t: i for i, t in enumerate(TACTIC_ORDER)}

def max_detected_stage(detected_techniques):
    stages = [TACTIC_TO_STAGE[tac] for tid in detected_techniques
              for tac in TECHNIQUE_TO_TACTICS.get(tid.upper(), []) if tac in TACTIC_TO_STAGE]
    return max(stages) if stages else -1

def filter_next_techniques(mapped_techniques, candidate_next):
    detected_set = {t.upper() for t in mapped_techniques}
    detected_families = {t.split(".")[0].upper() for t in detected_set}
    return [t.upper() for t in candidate_next
            if t.upper() not in detected_set and t.upper().split(".")[0] not in detected_families]

def filter_by_progression(detected_techniques, candidate_next, allow_same_stage=True):
    current_stage = max_detected_stage(detected_techniques)
    if current_stage < 0: return candidate_next
    min_allowed = current_stage if allow_same_stage else current_stage + 1
    return [tid for tid in candidate_next
            if not TECHNIQUE_TO_TACTICS.get(tid.upper())
            or any(TACTIC_TO_STAGE.get(t, -1) >= min_allowed for t in TECHNIQUE_TO_TACTICS.get(tid.upper(), []))]

# ==========================
# ENDPOINTS
# ==========================
@app.post("/api/ioc/apt-projection")
def apt_projection(req: ProjectionRequest):
    ioc_type      = normalize_ioc_type(req.ioc_type)
    submit_result = submit_ioc(IOCRequest(ioc_type=req.ioc_type, ioc_value=req.ioc_value, context=req.context))
    techniques     = [t.get("id") for t in submit_result.get("techniques", []) if t.get("id")]
    candidate_apts = find_candidate_apts(techniques)
    selected       = next((a for a in candidate_apts if a["apt_name"] == req.selected_apt), None)
    if not selected: return {"error": "Selected APT not found in candidates"}
    apt_name       = selected["apt_name"]
    candidate_next = [t for t in APT_TO_TECHNIQUES.get(apt_name, []) if t not in techniques]
    candidate_next = filter_next_techniques(techniques, candidate_next)
    candidate_next = filter_by_progression(techniques, candidate_next, allow_same_stage=True)
    candidate_next = candidate_next[:50]
    if not candidate_next:
        return {"error": "No viable next techniques after filtering", "mapped_techniques": techniques, "selected_apt": selected}
    next_step = predict_next_technique_with_llm(techniques, [selected], candidate_next, req.context, submit_result.get("enrichment"))
    predicted_rules = []
    try:
        pred_tech = next_step.get("predicted_next_technique", {}) if isinstance(next_step, dict) else {}
        pred_tid  = (pred_tech.get("id") or "").strip().upper()
        if pred_tid and re.match(r"^T\d{4}(\.\d{3})?$", pred_tid):
            enrichment_data = submit_result.get("enrichment") or {}
            risk_score      = int(enrichment_data.get("risk_score", 0) or 0)
            blueprint_level = max(5, risk_score_to_wazuh_level(risk_score) - 1)
            for i, bp in enumerate(TECHNIQUE_BLUEPRINTS.get(pred_tid, [])):
                logsource  = bp.get("logsource"); conditions = bp.get("conditions", [])
                parent_sid = LOGSOURCE_TO_PARENT_SID.get(logsource) if logsource else None
                if not parent_sid or not conditions: continue
                safe_conditions = [(field, op, value) for field, op, value in conditions
                                   if field in ALLOWED_WAZUH_FIELDS and op in ALLOWED_OPS and "$IOC" not in str(value)]
                if not safe_conditions: continue
                raw = f"proactive:{selected['apt_name']}:{pred_tid}:{i}"
                rule_id = 100000 + (int(_hl.sha256(raw.encode()).hexdigest(), 16) % 10000)
                field_blocks = [fxml for fxml in [build_field_xml(f, o, v) for f, o, v in safe_conditions] if fxml]
                if not field_blocks: continue
                fields_xml = "\n    ".join(field_blocks)
                mitre_xml  = build_mitre_block([pred_tid])
                level      = max(1, min(15, blueprint_level))
                wazuh_xml  = f'<group name="windows,attack,proactive">\n  <rule id="{rule_id}" level="{level}">\n    <decoded_as>json</decoded_as>\n    {fields_xml}\n    <description>[PROACTIVE] {pred_tid} - {bp["name"]} (anticipated from {selected["apt_name"]})</description>\n    {mitre_xml}\n  </rule>\n</group>'
                predicted_rules.append({"candidate_type": "proactive_blueprint", "rule_id": rule_id, "predicted_tid": pred_tid,
                                        "apt_name": selected["apt_name"], "description": bp["name"], "mitre": [pred_tid],
                                        "wazuh_xml": wazuh_xml, "wazuh_level": level,
                                        "note": f"Anticipatory rule — fires if {pred_tid} behavior observed before confirmation"})
    except Exception as e:
        log.warning("Proactive rule generation failed: %s", str(e))
    return {"ioc": {"type": ioc_type, "value": req.ioc_value}, "selected_apt": selected,
            "mapped_techniques": techniques, "candidate_next_techniques": candidate_next,
            "predicted_next_step": next_step, "predicted_rules": predicted_rules, "generated_at": now_iso()}

@app.post("/api/ioc/candidates")
def get_candidates(req: CandidatesRequest):
    return {"mapped_techniques": req.mapped_techniques, "candidate_apts": find_candidate_apts(req.mapped_techniques), "generated_at": now_iso()}

# ==========================
# CAMPAIGN MODELS
# ==========================
class CampaignIOCItem(BaseModel):
    ioc_type: str
    ioc_value: str
    context: Optional[str] = ""

class CampaignSubmitRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    iocs: List[CampaignIOCItem]

class CampaignAptProjectionSaveRequest(BaseModel):
    campaign_id: int
    campaign_ioc_id: int
    apt_projection_result: dict

# ==========================
# CAMPAIGN CORRELATION ENGINE
# ==========================
def correlate_campaign(ioc_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Cross-IOC correlation:
    - Shared techniques (appearing in 2+ IOCs)
    - Kill chain heatmap across all IOCs
    - Kill chain gaps (tactics with no coverage)
    - Best-fit APT across the full technique set
    - Combined risk score (avg + shared technique boost)
    - Unified deduplicated Wazuh rule set (detection + proactive)
    """
    # Collect all technique IDs across all IOCs
    all_techniques: Dict[str, List[int]] = {}  # tid -> list of ioc indices
    for idx, result in enumerate(ioc_results):
        for tech in result.get("techniques", []):
            if isinstance(tech, str):
                tid = tech.strip().upper()
            else:
                tid = (tech.get("id") or "").strip().upper()
            if tid and re.match(r"^T\d{4}(\.\d{3})?$", tid):
                all_techniques.setdefault(tid, []).append(idx)

    # Shared techniques: appear in >= 2 IOCs
    shared_techniques = [
        {"technique_id": tid, "ioc_indices": indices, "ioc_count": len(indices)}
        for tid, indices in all_techniques.items()
        if len(indices) >= 2
    ]
    shared_techniques.sort(key=lambda x: x["ioc_count"], reverse=True)

    # Tactic coverage heatmap
    covered_tactics: Dict[str, List[str]] = {}
    for tid in all_techniques:
        for tactic in TECHNIQUE_TO_TACTICS.get(tid, []):
            covered_tactics.setdefault(tactic, []).append(tid)

    kill_chain_map = []
    for tactic in TACTIC_ORDER:
        techniques_in_tactic = covered_tactics.get(tactic, [])
        kill_chain_map.append({
            "tactic":          tactic,
            "stage_index":     TACTIC_TO_STAGE[tactic],
            "covered":         len(techniques_in_tactic) > 0,
            "technique_count": len(techniques_in_tactic),
            "techniques":      techniques_in_tactic,
        })

    gap_tactics = [e["tactic"] for e in kill_chain_map if not e["covered"]]

    # Best-fit APT across all techniques
    all_tech_ids      = list(all_techniques.keys())
    campaign_apts     = find_candidate_apts(all_tech_ids)

    # Combined risk score
    risk_scores = [r.get("risk_score", 0) for r in ioc_results if r.get("risk_score") is not None]
    base_risk   = int(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
    shared_boost = min(20, len(shared_techniques) * 4)
    combined_risk = min(100, base_risk + shared_boost)

    # Unified deduplicated rules — detection + proactive from all IOCs
    seen_rule_ids:  set = set()
    seen_cond_keys: set = set()
    unified_rules: List[Dict] = []

    for result in ioc_results:
        # Detection / context rules
        for rule in result.get("candidate_rules", []):
            rid   = rule.get("rule_id")
            xml   = rule.get("wazuh_xml", "")
            pairs = frozenset(re.findall(r'<field name="([^"]+)"[^>]*>([^<]+)<', xml))
            if rid in seen_rule_ids or (pairs and pairs in seen_cond_keys):
                continue
            seen_rule_ids.add(rid)
            if pairs:
                seen_cond_keys.add(pairs)
            unified_rules.append(rule)

        # Proactive rules from APT projections stored per IOC
        for projection in result.get("apt_projections", []):
            for rule in projection.get("predicted_rules", []):
                rid   = rule.get("rule_id")
                xml   = rule.get("wazuh_xml", "")
                pairs = frozenset(re.findall(r'<field name="([^"]+)"[^>]*>([^<]+)<', xml))
                if rid in seen_rule_ids or (pairs and pairs in seen_cond_keys):
                    continue
                seen_rule_ids.add(rid)
                if pairs:
                    seen_cond_keys.add(pairs)
                unified_rules.append(rule)

    return {
        "total_iocs":               len(ioc_results),
        "total_unique_techniques":  len(all_techniques),
        "shared_techniques":        shared_techniques,
        "kill_chain_map":           kill_chain_map,
        "gap_tactics":              gap_tactics,
        "campaign_apt_candidates":  campaign_apts,
        "top_apt":                  campaign_apts[0] if campaign_apts else None,
        "combined_risk_score":      combined_risk,
        "combined_risk_level":      risk_level(combined_risk),
        "unified_rule_count":       len(unified_rules),
        "unified_rules":            unified_rules,
        "correlated_at":            now_iso(),
    }

# ==========================
# CAMPAIGN ENDPOINTS
# ==========================
@app.post("/api/campaign/submit")
def submit_campaign(req: CampaignSubmitRequest, payload=Depends(verify_token)):
    if not req.name or not req.name.strip():
        raise HTTPException(status_code=422, detail="Campaign name must not be empty")
    if not req.iocs:
        raise HTTPException(status_code=422, detail="Campaign must contain at least one IOC")
    if len(req.iocs) > 50:
        raise HTTPException(status_code=422, detail="Campaign cannot exceed 50 IOCs")

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO campaigns (name, description, submitted_by, status) VALUES (?, ?, ?, 'processing')",
        (req.name.strip(), req.description or "", payload["username"])
    )
    campaign_id = cursor.lastrowid
    conn.commit()

    ioc_results: List[Dict] = []
    failed_iocs: List[Dict] = []

    for item in req.iocs:
        ioc_type = normalize_ioc_type(item.ioc_type)
        try:
            validate_ioc_request(ioc_type, item.ioc_value)
            result = submit_ioc(IOCRequest(
                ioc_type=item.ioc_type,
                ioc_value=item.ioc_value,
                context=item.context or "",
            ))
            ioc_results.append(result)
            result_json_str = json.dumps(result)
            rule_hash = _hl.md5(f"{ioc_type}:{item.ioc_value}".encode()).hexdigest()

            conn.execute(
                """INSERT INTO campaign_iocs
                   (campaign_id, ioc_type, ioc_value, context, result_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (campaign_id, ioc_type, item.ioc_value,
                 item.context or "", result_json_str)
            )

            # Mirror to ioc_submissions so dashboard stats/charts pick up campaign IOCs
            conn.execute("""
                INSERT OR IGNORE INTO ioc_submissions
                (ioc_type, ioc_value, context, submitted_by, result_json, rule_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ioc_type, item.ioc_value, item.context or "",
                  payload["username"], result_json_str, rule_hash))

            conn.commit()
        except Exception as e:
            log.warning("Campaign IOC failed — %s %s: %s", item.ioc_type, item.ioc_value, str(e))
            failed_iocs.append({
                "ioc_value": item.ioc_value,
                "ioc_type":  item.ioc_type,
                "error":     str(e),
            })

    # Correlation pass
    correlation: Dict = {}
    if ioc_results:
        try:
            correlation = correlate_campaign(ioc_results)
        except Exception as e:
            log.error("Campaign correlation failed: %s", str(e))
            correlation = {"error": str(e)}

    conn.execute(
        "UPDATE campaigns SET correlation_json = ?, status = 'complete' WHERE id = ?",
        (json.dumps(correlation), campaign_id)
    )
    conn.commit()
    conn.close()

    return {
        "campaign_id":    campaign_id,
        "campaign_name":  req.name,
        "submitted_by":   payload["username"],
        "ioc_count":      len(req.iocs),
        "analyzed_count": len(ioc_results),
        "failed_iocs":    failed_iocs,
        "ioc_results":    ioc_results,
        "correlation":    correlation,
        "created_at":     now_iso(),
    }


@app.get("/api/campaign/{campaign_id}")
def get_campaign(campaign_id: int, payload=Depends(verify_token)):
    conn = get_db()
    campaign = conn.execute(
        "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not campaign:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")
    if payload["role"] != "admin" and campaign["submitted_by"] != payload["username"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    iocs = conn.execute(
        "SELECT * FROM campaign_iocs WHERE campaign_id = ? ORDER BY id ASC",
        (campaign_id,)
    ).fetchall()
    conn.close()

    ioc_list = []
    for row in iocs:
        entry = dict(row)
        try:
            entry["result_json"] = json.loads(entry["result_json"] or "{}")
        except Exception:
            pass
        ioc_list.append(entry)

    try:
        correlation = json.loads(campaign["correlation_json"] or "{}")
    except Exception:
        correlation = {}

    return {
        "campaign_id":  campaign["id"],
        "name":         campaign["name"],
        "description":  campaign["description"],
        "submitted_by": campaign["submitted_by"],
        "created_at":   campaign["created_at"],
        "status":       campaign["status"],
        "ioc_results":  ioc_list,
        "correlation":  correlation,
    }


@app.get("/api/campaigns/mine")
def get_my_campaigns(payload=Depends(verify_token)):
    conn = get_db()
    rows = conn.execute(
        """SELECT c.id as campaign_id, c.name, c.description, c.submitted_by, c.created_at, c.status,
                  COUNT(ci.id) as ioc_count, c.correlation_json
           FROM campaigns c
           LEFT JOIN campaign_iocs ci ON ci.campaign_id = c.id
           WHERE c.submitted_by = ?
           GROUP BY c.id
           ORDER BY c.created_at DESC""",
        (payload["username"],)
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        entry = dict(row)
        try:
            corr = json.loads(entry.pop("correlation_json") or "{}")
            entry["combined_risk_score"] = corr.get("combined_risk_score")
            entry["combined_risk_level"] = corr.get("combined_risk_level")
            entry["unified_rule_count"]  = corr.get("unified_rule_count")
            entry["top_apt"]             = (corr.get("top_apt") or {}).get("apt_name")
            entry["gap_tactics"]         = corr.get("gap_tactics", [])
        except Exception:
            entry.pop("correlation_json", None)
        result.append(entry)
    return result


@app.get("/api/campaigns/all")
def get_all_campaigns(payload=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute(
        """SELECT c.id as campaign_id, c.name, c.description, c.submitted_by, c.created_at, c.status,
                  COUNT(ci.id) as ioc_count, c.correlation_json
           FROM campaigns c
           LEFT JOIN campaign_iocs ci ON ci.campaign_id = c.id
           GROUP BY c.id
           ORDER BY c.created_at DESC"""
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        entry = dict(row)
        try:
            corr = json.loads(entry.pop("correlation_json") or "{}")
            entry["combined_risk_score"] = corr.get("combined_risk_score")
            entry["combined_risk_level"] = corr.get("combined_risk_level")
            entry["unified_rule_count"]  = corr.get("unified_rule_count")
            entry["top_apt"]             = (corr.get("top_apt") or {}).get("apt_name")
            entry["gap_tactics"]         = corr.get("gap_tactics", [])
        except Exception:
            entry.pop("correlation_json", None)
        result.append(entry)
    return result


@app.delete("/api/campaign/{campaign_id}")
def delete_campaign(campaign_id: int, payload=Depends(require_admin)):
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Get all IOC values + types from this campaign before deleting
    ioc_rows = conn.execute(
        "SELECT ioc_type, ioc_value FROM campaign_iocs WHERE campaign_id = ?",
        (campaign_id,)
    ).fetchall()

    # Delete campaign tables
    conn.execute("DELETE FROM campaign_iocs WHERE campaign_id = ?", (campaign_id,))
    conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))

    # Delete mirrored ioc_submissions entries
    # We identify them by matching the md5 rule_hash used during mirroring
    for row in ioc_rows:
        ioc_type  = row["ioc_type"]
        ioc_value = row["ioc_value"]

        # Check this IOC value isn't still used in another campaign
        still_needed = conn.execute(
            "SELECT id FROM campaign_iocs WHERE ioc_value = ?",
            (ioc_value,)
        ).fetchone()
        if still_needed:
            continue

        # The mirror rule_hash was: md5(f"{ioc_type}:{ioc_value}")
        mirror_hash = _hl.md5(f"{ioc_type}:{ioc_value}".encode()).hexdigest()
        conn.execute(
            "DELETE FROM ioc_submissions WHERE ioc_value = ? AND rule_hash = ?",
            (ioc_value, mirror_hash)
        )

    conn.commit()
    conn.close()
    return {"message": "Campaign deleted"}


@app.post("/api/campaigns/save-apt-projection")
async def save_campaign_apt_projection(
    req: CampaignAptProjectionSaveRequest,
    payload=Depends(verify_token)
):
    conn = get_db()
    campaign = conn.execute(
        "SELECT submitted_by FROM campaigns WHERE id = ?", (req.campaign_id,)
    ).fetchone()
    if not campaign:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")
    if payload["role"] != "admin" and campaign["submitted_by"] != payload["username"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    row = conn.execute(
        "SELECT result_json FROM campaign_iocs WHERE id = ? AND campaign_id = ?",
        (req.campaign_ioc_id, req.campaign_id)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign IOC not found")

    try:
        existing = json.loads(row["result_json"] or "{}")
    except Exception:
        existing = {}

    projections = existing.get("apt_projections", [])
    apt_name = (req.apt_projection_result.get("selected_apt") or {}).get("apt_name", "")
    projections = [
        p for p in projections
        if not (p.get("analyst") == payload["username"] and
                (p.get("selected_apt") or {}).get("apt_name", "") == apt_name)
    ]
    projections.append({
        "analyst":                   payload["username"],
        "projected_at":              now_iso(),
        "selected_apt":              req.apt_projection_result.get("selected_apt"),
        "predicted_next_step":       req.apt_projection_result.get("predicted_next_step"),
        "predicted_rules":           req.apt_projection_result.get("predicted_rules", []),
        "candidate_next_techniques": req.apt_projection_result.get("candidate_next_techniques", []),
    })
    existing["apt_projections"] = projections

    conn.execute(
        "UPDATE campaign_iocs SET result_json = ? WHERE id = ?",
        (json.dumps(existing), req.campaign_ioc_id)
    )

    # Re-correlate so unified_rules includes the new proactive rules
    ioc_rows = conn.execute(
        "SELECT result_json FROM campaign_iocs WHERE campaign_id = ? ORDER BY id ASC",
        (req.campaign_id,)
    ).fetchall()
    ioc_results_rerun = []
    for r in ioc_rows:
        try:
            ioc_results_rerun.append(json.loads(r["result_json"] or "{}"))
        except Exception:
            pass

    if ioc_results_rerun:
        try:
            new_corr = correlate_campaign(ioc_results_rerun)
            conn.execute(
                "UPDATE campaigns SET correlation_json = ? WHERE id = ?",
                (json.dumps(new_corr), req.campaign_id)
            )
        except Exception as e:
            log.warning("Re-correlation failed after APT projection: %s", str(e))

    conn.commit()
    conn.close()
    return {"message": "APT projection saved to campaign IOC"}

# ==========================
# CAMPAIGN APT PROJECTION
# ==========================
class CampaignProjectionRequest(BaseModel):
    selected_apt: str

@app.post("/api/campaign/{campaign_id}/apt-projection")
def campaign_apt_projection(
    campaign_id: int,
    req: CampaignProjectionRequest,
    payload=Depends(verify_token)
):
    conn = get_db()
    campaign = conn.execute(
        "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not campaign:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")
    if payload["role"] != "admin" and campaign["submitted_by"] != payload["username"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    ioc_rows = conn.execute(
        "SELECT result_json FROM campaign_iocs WHERE campaign_id = ? ORDER BY id ASC",
        (campaign_id,)
    ).fetchall()

    all_techniques: List[str] = []
    seen_tids: set = set()
    for row in ioc_rows:
        try:
            result = json.loads(row["result_json"] or "{}")
            for tech in result.get("techniques", []):
                tid = (tech.get("id") if isinstance(tech, dict) else tech or "").strip().upper()
                if tid and re.match(r"^T\d{4}(\.\d{3})?$", tid) and tid not in seen_tids:
                    all_techniques.append(tid)
                    seen_tids.add(tid)
        except Exception:
            pass

    if not all_techniques:
        conn.close()
        raise HTTPException(status_code=422, detail="No techniques found across campaign IOCs")

    candidate_apts = find_candidate_apts(all_techniques)
    selected = next((a for a in candidate_apts if a["apt_name"] == req.selected_apt), None)
    if not selected:
        conn.close()
        raise HTTPException(status_code=404, detail="Selected APT not found in candidates")

    candidate_next = [t for t in APT_TO_TECHNIQUES.get(req.selected_apt, []) if t not in all_techniques]
    candidate_next = filter_next_techniques(all_techniques, candidate_next)
    candidate_next = filter_by_progression(all_techniques, candidate_next, allow_same_stage=True)
    candidate_next = candidate_next[:50]

    if not candidate_next:
        conn.close()
        raise HTTPException(status_code=422, detail="No viable next techniques after filtering")

    try:
        corr = json.loads(campaign["correlation_json"] or "{}")
    except Exception:
        corr = {}

    campaign_context = (
        f"Campaign: {campaign['name']}. "
        f"Combined techniques across {len(ioc_rows)} IOCs: {', '.join(all_techniques)}. "
        f"Kill chain stages covered: {[e['tactic'] for e in corr.get('kill_chain_map', []) if e.get('covered')]}."
    )

    next_step = predict_next_technique_with_llm(
        mapped_techniques=all_techniques,
        candidate_apts=[selected],
        candidate_next_techniques=candidate_next,
        context=campaign_context,
        enrichment=None,
    )

    predicted_rules = []
    try:
        pred_tech = next_step.get("predicted_next_technique", {}) if isinstance(next_step, dict) else {}
        pred_tid  = (pred_tech.get("id") or "").strip().upper()
        if pred_tid and re.match(r"^T\d{4}(\.\d{3})?$", pred_tid):
            for i, bp in enumerate(TECHNIQUE_BLUEPRINTS.get(pred_tid, [])):
                logsource  = bp.get("logsource")
                conditions = bp.get("conditions", [])
                parent_sid = LOGSOURCE_TO_PARENT_SID.get(logsource) if logsource else None
                if not parent_sid or not conditions:
                    continue
                safe_conditions = [
                    (field, op, value) for field, op, value in conditions
                    if field in ALLOWED_WAZUH_FIELDS and op in ALLOWED_OPS and "$IOC" not in str(value)
                ]
                if not safe_conditions:
                    continue
                raw     = f"campaign_proactive:{req.selected_apt}:{pred_tid}:{i}"
                rule_id = 100000 + (int(_hl.sha256(raw.encode()).hexdigest(), 16) % 10000)
                field_blocks = [fxml for fxml in [build_field_xml(f, o, v) for f, o, v in safe_conditions] if fxml]
                if not field_blocks:
                    continue
                fields_xml = "\n    ".join(field_blocks)
                mitre_xml  = build_mitre_block([pred_tid])
                wazuh_xml  = (
                    f'<group name="windows,attack,proactive">\n'
                    f'  <rule id="{rule_id}" level="13">\n'
                    f'    <decoded_as>json</decoded_as>\n'
                    f'    {fields_xml}\n'
                    f'    <description>[CAMPAIGN-PROACTIVE] {pred_tid} - {bp["name"]} '
                    f'(anticipated from {req.selected_apt})</description>\n'
                    f'    {mitre_xml}\n'
                    f'  </rule>\n'
                    f'</group>'
                )
                predicted_rules.append({
                    "candidate_type": "campaign_proactive",
                    "rule_id":        rule_id,
                    "predicted_tid":  pred_tid,
                    "apt_name":       req.selected_apt,
                    "description":    bp["name"],
                    "mitre":          [pred_tid],
                    "wazuh_xml":      wazuh_xml,
                    "wazuh_level":    13,
                })
    except Exception as e:
        log.warning("Campaign proactive rule generation failed: %s", str(e))

    projection_entry = {
        "analyst":             payload["username"],
        "projected_at":        now_iso(),
        "selected_apt":        selected,
        "all_techniques":      all_techniques,
        "candidate_next":      candidate_next,
        "predicted_next_step": next_step,
        "predicted_rules":     predicted_rules,
    }

    corr["campaign_apt_projection"] = projection_entry
    existing_unified = corr.get("unified_rules", [])
    seen_ids = {r.get("rule_id") for r in existing_unified}
    for rule in predicted_rules:
        if rule.get("rule_id") not in seen_ids:
            existing_unified.append(rule)
            seen_ids.add(rule.get("rule_id"))
    corr["unified_rules"]      = existing_unified
    corr["unified_rule_count"] = len(existing_unified)

    conn.execute(
        "UPDATE campaigns SET correlation_json = ? WHERE id = ?",
        (json.dumps(corr), campaign_id)
    )
    conn.commit()
    conn.close()

    return {
        "campaign_id":         campaign_id,
        "selected_apt":        selected,
        "all_techniques":      all_techniques,
        "candidate_next":      candidate_next,
        "predicted_next_step": next_step,
        "predicted_rules":     predicted_rules,
        "projected_at":        now_iso(),
    }


@app.get("/api/campaign/{campaign_id}/apt-candidates")
def campaign_apt_candidates(campaign_id: int, payload=Depends(verify_token)):
    conn = get_db()
    campaign = conn.execute(
        "SELECT submitted_by FROM campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not campaign:
        conn.close()
        raise HTTPException(status_code=404, detail="Campaign not found")
    if payload["role"] != "admin" and campaign["submitted_by"] != payload["username"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    ioc_rows = conn.execute(
        "SELECT result_json FROM campaign_iocs WHERE campaign_id = ? ORDER BY id ASC",
        (campaign_id,)
    ).fetchall()
    conn.close()

    all_techniques: List[str] = []
    seen_tids: set = set()
    for row in ioc_rows:
        try:
            result = json.loads(row["result_json"] or "{}")
            for tech in result.get("techniques", []):
                tid = (tech.get("id") if isinstance(tech, dict) else tech or "").strip().upper()
                if tid and re.match(r"^T\d{4}(\.\d{3})?$", tid) and tid not in seen_tids:
                    all_techniques.append(tid)
                    seen_tids.add(tid)
        except Exception:
            pass

    return {
        "campaign_id":    campaign_id,
        "all_techniques": all_techniques,
        "candidate_apts": find_candidate_apts(all_techniques),
    }