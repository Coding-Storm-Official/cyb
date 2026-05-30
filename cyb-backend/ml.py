from __future__ import annotations
import os, json, time, hmac, uuid, queue, hashlib, logging, threading, ssl, re, sqlite3, math
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
from threading import Lock
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import SGDClassifier
try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest
    HAS_PROM = True
except ImportError:
    HAS_PROM = False
try:
    from kafka import KafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("xdr")

MITRE = {
    "T1003": {"tactics": ["Credential Access"],        "weight": 0.95},
    "T1055": {"tactics": ["Privilege Escalation"],     "weight": 0.92},
    "T1021": {"tactics": ["Lateral Movement"],         "weight": 0.81},
    "T1041": {"tactics": ["Exfiltration"],             "weight": 0.88},
    "T1489": {"tactics": ["Impact"],                   "weight": 0.84},
    "T1070": {"tactics": ["Defense Evasion"],          "weight": 0.85},
    "T1087": {"tactics": ["Discovery"],                "weight": 0.72},
    "T1059": {"tactics": ["Execution"],                "weight": 0.80},
    "T1486": {"tactics": ["Impact"],                   "weight": 0.97},
    "T1078": {"tactics": ["Privilege Escalation"],     "weight": 0.76},
    "T1547": {"tactics": ["Persistence"],              "weight": 0.82},
    "T1053": {"tactics": ["Persistence"],              "weight": 0.79},
    "T1112": {"tactics": ["Defense Evasion"],          "weight": 0.74},
    "T1074": {"tactics": ["Collection"],               "weight": 0.78},
    "T1083": {"tactics": ["Discovery"],                "weight": 0.68},
}

STAGES = {
    "Discovery": 0, "Credential Access": 1, "Privilege Escalation": 2,
    "Defense Evasion": 3, "Lateral Movement": 4, "Collection": 5,
    "Exfiltration": 6, "Persistence": 7, "Execution": 8, "Impact": 9
}

TRANSITIONS = np.array([
    [0.40, 0.18, 0.12, 0.10, 0.05, 0.05, 0.03, 0.04, 0.02, 0.01],
    [0.05, 0.42, 0.22, 0.14, 0.05, 0.04, 0.03, 0.03, 0.01, 0.01],
    [0.02, 0.07, 0.38, 0.24, 0.10, 0.07, 0.05, 0.04, 0.02, 0.01],
    [0.01, 0.04, 0.09, 0.42, 0.15, 0.12, 0.10, 0.04, 0.02, 0.01],
    [0.01, 0.03, 0.05, 0.08, 0.44, 0.18, 0.12, 0.05, 0.03, 0.01],
    [0.01, 0.02, 0.03, 0.06, 0.08, 0.42, 0.28, 0.05, 0.03, 0.02],
    [0.01, 0.01, 0.02, 0.04, 0.06, 0.10, 0.54, 0.08, 0.08, 0.06],
    [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.58, 0.08, 0.05],
    [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.05, 0.55, 0.12],
    [0.01, 0.01, 0.01, 0.02, 0.02, 0.03, 0.05, 0.04, 0.06, 0.75],
])

FEATURES = [
    "proc_rate_1m", "proc_rate_5m", "cmd_entropy_avg", "cmd_avg_len",
    "recon_count", "encoded_ps", "service_mods", "log_clear", "lsass_hits",
    "uac_hits", "lateral_spread", "rare_parent_child", "unsigned_ratio",
    "suspicious_dns", "outbound_volume", "inbound_volume", "priv_chain",
    "time_cos", "file_write_rate_1m", "file_write_rate_5m", "file_rename_rate_5m",
    "file_delete_rate_5m", "encrypt_ext_hits", "entropy_spike_count",
    "access_denied_rate_5m", "dir_traversal_count", "unique_dirs_accessed",
    "traversal_velocity", "net_unique_destinations", "net_bytes_out_mb",
    "integrity_jump_hits", "persistence_hits", "registry_tamper_hits",
    "scheduled_task_hits", "wmi_persistence_hits", "shadow_delete_hits",
    "net_user_recon_hits", "mass_delete_hits", "exfil_staging_hits",
]

RANSOM_EXTENSIONS = re.compile(
    r'\.(locked|encrypted|enc|crypt|crypted|zepto|cerber|locky|wncry|wnry|wcry|ryuk|maze|'
    r'revil|sodinokibi|darkside|conti|hive|blackcat|alphv|lockbit|bad|pays|ecc|ezz|exx|'
    r'micro|ttt|xyz|zzz|aaa|abc|pzdc|good|btc|fun|gws|kraken|darkness|nochance|dec|'
    r'legion|xtbl|cbf|vault|vvv|xxx|yyy|breaking_bad|da_vinci_code)\b',
    re.I
)

RULES = [
    {
        "id": "SIG-001", "mitre": "T1003", "severity": 10,
        "patterns": [re.compile(r'lsass|mimikatz|sekurlsa|comsvcs|wce\.exe|fgdump|pwdump|gsecdump|laZagne|procdump.+lsass', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-002", "mitre": "T1070", "severity": 8,
        "patterns": [re.compile(r'wevtutil.+(cl|clear-log)|Clear-EventLog|Remove-EventLog', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-003", "mitre": "T1489", "severity": 9,
        "patterns": [re.compile(r'sc(\.exe)?\s+stop', re.I), re.compile(r'WinDefend|MsMpSvc|wdnissvc|SecurityHealthService', re.I)],
        "require_all": True
    },
    {
        "id": "SIG-004", "mitre": "T1021", "severity": 7,
        "patterns": [re.compile(r'psexec|wmiexec|wmic\s+/node|winrm|Enter-PSSession|smbexec|atexec|dcomexec', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-005", "mitre": "T1486", "severity": 10,
        "patterns": [RANSOM_EXTENSIONS],
        "require_all": False
    },
    {
        "id": "SIG-006", "mitre": "T1059", "severity": 8,
        "patterns": [re.compile(r'powershell.+(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{30,})|IEX\s*\(|Invoke-Expression|DownloadString|WebClient', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-007", "mitre": "T1547", "severity": 8,
        "patterns": [re.compile(r'reg\s+add.+(Run|RunOnce|Winlogon|CurrentVersion\\Windows|CurrentVersion\\Policies\\Explorer\\Run)', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-008", "mitre": "T1053", "severity": 8,
        "patterns": [re.compile(r'schtasks(\.exe)?\s+/(create|change|run)|at\.exe\s+\d+|Register-ScheduledTask', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-009", "mitre": "T1112", "severity": 7,
        "patterns": [re.compile(r'reg\s+(add|delete|import)|regedit|regsvr32.+/s.+/u|mshta.+vbscript', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-010", "mitre": "T1078", "severity": 9,
        "patterns": [re.compile(r'whoami\s+/priv|net\s+user|net\s+localgroup|net1\s+user|net1\s+localgroup|nltest\s+/domain_trusts|dsquery|ldapsearch', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-011", "mitre": "T1055", "severity": 10,
        "patterns": [re.compile(r'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|RtlCreateUserThread|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-012", "mitre": "T1486", "severity": 10,
        "patterns": [re.compile(r'vssadmin\s+delete|wmic\s+shadowcopy\s+delete|bcdedit\s+/set.+recoveryenabled\s+no|wbadmin\s+delete|diskshadow.*delete\s+shadows', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-013", "mitre": "T1041", "severity": 8,
        "patterns": [re.compile(r'certutil.+-urlcache|-split.*http|bitsadmin.+transfer|Invoke-WebRequest|curl.+-o\s|wget.+-O\s|net\s+use\s+\\\\.+/user', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-014", "mitre": "T1083", "severity": 5,
        "patterns": [re.compile(r'(dir|ls|find|tree)\s+(\/s|/b|-r|-la|/a).*(Documents|Desktop|AppData|Users|ProgramData|temp)', re.I)],
        "require_all": False
    },
    {
        "id": "SIG-015", "mitre": "T1074", "severity": 7,
        "patterns": [re.compile(r'(copy|xcopy|robocopy|rar|7z|zip|tar).+(\\temp\\|\\appdata\\|\\programdata\\|\\windows\\temp\\)', re.I)],
        "require_all": False
    },
]

if HAS_PROM:
    EVENTS_CTR  = Counter("xdr_events_total",       "Total telemetry events parsed")
    ALERTS_CTR  = Counter("xdr_alerts_total",        "Total security alerts published")
    IOCS_CTR    = Counter("xdr_ioc_hits_total",      "Total IOC matches")
    LATENCY_H   = Histogram("xdr_latency_seconds",   "Processing cycle latency")
    QUEUE_G     = Gauge("xdr_queue_depth",            "Current queue fill depth")
    DRIFT_CTR   = Counter("xdr_drift_retrain_total", "Model retrains due to drift")
    RANSOM_CTR  = Counter("xdr_ransomware_signals",  "Ransomware behavior detections")
    INSIDER_CTR = Counter("xdr_insider_signals",     "Insider threat behavior detections")
    PRIVESC_CTR = Counter("xdr_privesc_signals",     "Privilege escalation detections")

@dataclass
class IOC:
    ioc_type: str
    value: str
    severity: int
    source: str

@dataclass
class Alert:
    incident_id: str
    host_id: str
    user_id: str
    score: float
    threat: str
    rules: List[str]
    mitre: List[str]
    iocs: List[str]
    next_stage: str
    confidence: float
    actions: List[str]
    behavior_tags: List[str]
    integrity_jump: bool
    ts: float = field(default_factory=time.time)
    def dump(self):
        return asdict(self)

class RBAC:
    def __init__(self):
        self.roles = {
            "viewer":   {"read"},
            "analyst":  {"read", "fp"},
            "senior":   {"read", "fp", "retrain", "ioc"},
            "admin":    {"read", "fp", "retrain", "ioc", "users", "purge"}
        }
        self.users: Dict[str, dict] = {}
    def add(self, user: str, role: str) -> str:
        key = uuid.uuid4().hex
        self.users[key] = {"user": user, "role": role}
        return key
    def verify(self, key: str, perm: str) -> dict:
        u = self.users.get(key)
        if not u:
            raise PermissionError("invalid key")
        if perm not in self.roles.get(u["role"], set()):
            raise PermissionError("permission denied")
        return u

class RedisCache:
    def __init__(self):
        self.mem: Dict = {}
        self.client = None
        if HAS_REDIS:
            try:
                self.client = redis.Redis(
                    host=os.getenv("REDIS_HOST", "127.0.0.1"),
                    port=int(os.getenv("REDIS_PORT", "6379")),
                    password=os.getenv("REDIS_PASS"),
                    decode_responses=True,
                    socket_timeout=2
                )
                self.client.ping()
            except Exception:
                self.client = None
    def get(self, k: str) -> Optional[str]:
        if self.client:
            try:
                return self.client.get(k)
            except Exception:
                pass
        return self.mem.get(k)
    def set(self, k: str, v: str, ex: Optional[int] = None):
        if self.client:
            try:
                self.client.set(k, v, ex=ex)
                return
            except Exception:
                pass
        self.mem[k] = v
    def sismember(self, k: str, v: str) -> bool:
        if self.client:
            try:
                return bool(self.client.sismember(k, v))
            except Exception:
                pass
        return v in self.mem.get(k, set())
    def sadd(self, k: str, v: str):
        if self.client:
            try:
                self.client.sadd(k, v)
                return
            except Exception:
                pass
        if k not in self.mem:
            self.mem[k] = set()
        self.mem[k].add(v)

class Persistence:
    def __init__(self, path="xdr.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = Lock()
        with self.conn:
            self.conn.execute(
                "create table if not exists alerts "
                "(id text primary key, payload text, ts real, threat text, score real)"
            )
            self.conn.execute(
                "create table if not exists telemetry (sig text primary key, ts real)"
            )
            self.conn.execute(
                "create index if not exists idx_alerts_ts on alerts(ts)"
            )
            self.conn.execute(
                "create index if not exists idx_alerts_threat on alerts(threat)"
            )
    def store_alert(self, alert: dict):
        with self.lock:
            self.conn.execute(
                "insert or replace into alerts values(?,?,?,?,?)",
                (alert["incident_id"], json.dumps(alert), time.time(),
                 alert.get("threat", ""), alert.get("score", 0.0))
            )
            self.conn.commit()
    def seen(self, sig: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "select 1 from telemetry where sig=?", (sig,)
            ).fetchone() is not None
    def mark(self, sig: str):
        with self.lock:
            self.conn.execute(
                "insert or replace into telemetry values(?,?)", (sig, time.time())
            )
            self.conn.commit()
    def query_alerts(self, threat: str = None, since: float = 0.0) -> List[dict]:
        with self.lock:
            if threat:
                rows = self.conn.execute(
                    "select payload from alerts where threat=? and ts>? order by ts desc limit 1000",
                    (threat, since)
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "select payload from alerts where ts>? order by ts desc limit 1000",
                    (since,)
                ).fetchall()
            return [json.loads(r[0]) for r in rows]

class ThreatIntel:
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.lock = Lock()
        self.ctx = ssl.create_default_context()
    def load_local(self, path="iocs.json"):
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            with self.lock:
                for x in data:
                    self.iocs[x["value"].lower()] = IOC(**x)
            logger.info(f"[Intel] Loaded {len(self.iocs)} IOCs from local bundle.")
    def poll(self, url: str):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "XDR/2.0"})
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as r:
                data = json.loads(r.read().decode())
            with self.lock:
                for x in (data if isinstance(data, list) else data.get("urls", [])):
                    val = x.get("value", x.get("url", "")).lower()
                    if val:
                        self.iocs[val] = IOC(
                            ioc_type=x.get("ioc_type", "url"),
                            value=val,
                            severity=x.get("severity", 5),
                            source=x.get("source", "remote")
                        )
        except Exception as e:
            logger.warning(f"[Intel] Poll error: {e}")
    def lookup(self, val: str) -> Optional[IOC]:
        with self.lock:
            return self.iocs.get(val.lower())

class Webhook:
    def __init__(self):
        self.url = os.getenv("WEBHOOK_URL", "")
        self.ctx = ssl.create_default_context()
        self._tokens = 120.0
        self._last = time.monotonic()
        self._lock = Lock()
    def _consume(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(120.0, self._tokens + (now - self._last) * 2.0)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False
    def send(self, payload: dict) -> bool:
        if not self.url or not self._consume():
            return False
        data = json.dumps(payload).encode()
        token = os.getenv("WEBHOOK_TOKEN", "")
        headers = {"Content-Type": "application/json", "User-Agent": "XDR/2.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for i in range(3):
            try:
                req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, context=self.ctx, timeout=10):
                    return True
            except Exception:
                time.sleep(2 ** i)
        return False

class KafkaBus:
    def __init__(self):
        self.local: queue.Queue = queue.Queue(maxsize=50000)
        self.prod = None
        if HAS_KAFKA:
            try:
                self.prod = KafkaProducer(
                    bootstrap_servers=os.getenv("KAFKA", "127.0.0.1:9092").split(","),
                    value_serializer=lambda x: json.dumps(x).encode(),
                    acks="all", retries=5, linger_ms=5
                )
            except Exception:
                self.prod = None
    def publish(self, data: dict):
        if self.prod:
            try:
                self.prod.send("xdr-alerts", data)
                return
            except Exception:
                pass
        try:
            self.local.put_nowait(data)
        except queue.Full:
            pass

class PSI:
    def __init__(self, base: np.ndarray):
        self.edges: List[np.ndarray] = []
        self.ref: List[np.ndarray] = []
        for i in range(base.shape[1]):
            e = np.histogram_bin_edges(base[:, i], bins=10)
            h, _ = np.histogram(base[:, i], bins=e)
            h = np.where(h == 0, 1e-6, h / h.sum())
            self.edges.append(e)
            self.ref.append(h)
    def score(self, cur: np.ndarray) -> float:
        vals = []
        for i in range(min(cur.shape[1], len(self.ref))):
            h, _ = np.histogram(cur[:, i], bins=self.edges[i])
            h = np.where(h == 0, 1e-6, h / max(h.sum(), 1))
            vals.append(float(np.sum((h - self.ref[i]) * np.log(h / self.ref[i]))))
        return float(np.mean(vals)) if vals else 0.0

class DetectionPipeline:
    def __init__(self):
        self.scaler = StandardScaler()
        self.iso    = IsolationForest(contamination=0.02, random_state=42, n_jobs=-1)
        self.rf     = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
        self.gbm    = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        self.mlp    = MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500, random_state=42)
        self.sgd    = SGDClassifier(loss="modified_huber", random_state=42)
        self.ready  = False
        self.lock   = Lock()
    def fit(self, benign: np.ndarray, malicious: np.ndarray):
        X = np.vstack([benign, malicious])
        y = np.array([0] * len(benign) + [1] * len(malicious))
        with self.lock:
            Xs = self.scaler.fit_transform(X)
            self.iso.fit(Xs)
            self.rf.fit(Xs, y)
            self.gbm.fit(Xs, y)
            self.mlp.fit(Xs, y)
            self.sgd.fit(Xs, y)
            self.ready = True
    def score(self, vec: np.ndarray) -> float:
        with self.lock:
            if not self.ready:
                return 0.0
            xs = self.scaler.transform(vec.reshape(1, -1))
            iso_s = float(abs(self.iso.decision_function(xs)[0])) * 100.0
            rf_s  = float(self.rf.predict_proba(xs)[0][1])  * 100.0
            gbm_s = float(self.gbm.predict_proba(xs)[0][1]) * 100.0
            mlp_s = float(self.mlp.predict_proba(xs)[0][1]) * 100.0
            sgd_s = float(self.sgd.predict_proba(xs)[0][1]) * 100.0
            return min((iso_s * 0.15) + (rf_s * 0.30) + (gbm_s * 0.25) + (mlp_s * 0.20) + (sgd_s * 0.10), 100.0)

_RANSOM_EXT_SET = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".zepto", ".cerber",
    ".locky", ".wncry", ".wnry", ".wcry", ".ryuk", ".maze", ".revil", ".sodinokibi",
    ".darkside", ".conti", ".hive", ".blackcat", ".alphv", ".lockbit", ".bad",
    ".pays", ".ecc", ".ezz", ".exx", ".micro", ".ttt", ".xyz", ".zzz", ".aaa",
    ".pzdc", ".btc", ".fun", ".xtbl", ".cbf", ".vault", ".vvv", ".xxx", ".yyy",
}

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())

def _has_ransom_extension(path: str) -> bool:
    if not path:
        return False
    ext = os.path.splitext(path.lower())[1]
    return ext in _RANSOM_EXT_SET or bool(RANSOM_EXTENSIONS.search(path))

def _extract_directory(path: str) -> str:
    if not path:
        return ""
    return os.path.dirname(path.replace("\\", "/")).lower()

class Engine:
    THRESHOLD = 65
    N_FEATURES = len(FEATURES)
    _UAC_BYPASS = re.compile(
        r'fodhelper|eventvwr|computerdefaults|sdclt|cmstp|slui|'
        r'bypassuac|bypassuacbyrunas|akagi|uacme|'
        r'HKCU\\Software\\Classes\\ms-settings|HKCU\\Software\\Classes\\exefile',
        re.I
    )
    _PERSIST_SCHTASK = re.compile(
        r'schtasks(\.exe)?\s+/(create|change)|Register-ScheduledTask|at\.exe', re.I
    )
    _PERSIST_REG = re.compile(
        r'reg\s+add.+(\\Run\\|\\RunOnce\\|\\Winlogon\\|\\CurrentVersion\\Windows|'
        r'\\Policies\\Explorer\\Run|\\Services\\|\\CurrentControlSet)',
        re.I
    )
    _PERSIST_WMI = re.compile(
        r'WMI.*(subscription|EventFilter|EventConsumer|CommandLineEventConsumer)|'
        r'New-WMIEvent|Register-WmiEvent',
        re.I
    )
    _PERSIST_STARTUP = re.compile(
        r'(Startup|start\s+menu.*startup|shell:startup).*\.(exe|bat|cmd|vbs|js|lnk|ps1)', re.I
    )
    _SHADOW_DELETE = re.compile(
        r'vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|'
        r'bcdedit.+recoveryenabled.+no|wbadmin\s+delete\s+catalog|'
        r'diskshadow.*delete\s+shadows',
        re.I
    )
    _EXFIL_STAGE = re.compile(
        r'(compress|archive|rar|7z|zip).+(documents|desktop|appdata|programdata)|'
        r'net\s+use\s+\\\\.+/user|copy.+\\\\.+\\[a-z]\$',
        re.I
    )
    _INTEGRITY_JUMP = re.compile(
        r'token.*elevation|CreateProcessWithToken|ImpersonateLoggedOnUser|'
        r'AdjustTokenPrivileges|SetTokenInformation|privilege.*enabled|'
        r'integrity.*level.*(system|high)|mandatory\s+label.*system',
        re.I
    )
    _RECON_EXTENDED = re.compile(
        r'whoami(\s+/priv|/groups|/all)?|systeminfo|nltest\s+/|'
        r'net\s+(user|localgroup|group|accounts|share|session|view)|'
        r'net1\s+(user|localgroup|group)|dsquery|ldapsearch|'
        r'klist\s+tickets|Get-ADUser|Get-ADGroup|Get-ADComputer|'
        r'gpresult|cmdkey\s+/list',
        re.I
    )
    _LSASS_EXTENDED = re.compile(
        r'lsass|mimikatz|sekurlsa|procdump.*(lsass|pid)|'
        r'comsvcs.*MiniDump|wce\.exe|fgdump|pwdump|gsecdump|'
        r'LaZagne|Out-Minidump|Invoke-Mimikatz|DumpCreds|'
        r'PROCESS_VM_READ|NtReadVirtualMemory',
        re.I
    )
    _NET_SUSPICIOUS = re.compile(
        r'duckdns|ngrok|pastebin|githubusercontent|temp\.sh|'
        r'0\.0\.0\.0/0|raw\.githubusercontent|transfer\.sh|'
        r'file\.io|anonfiles|mega\.nz|gofile\.io',
        re.I
    )
    _LATERAL = re.compile(
        r'psexec|wmiexec|wmic\s+/node|winrm|Enter-PSSession|'
        r'smbexec|atexec|dcomexec|Invoke-WMIMethod|evil-winrm|'
        r'net\s+use\s+\\\\.+\\ipc\$',
        re.I
    )

    def __init__(self):
        self.queue      = queue.Queue(maxsize=200000)
        self.db         = Persistence()
        self.intel      = ThreatIntel()
        self.webhook    = Webhook()
        self.kafka      = KafkaBus()
        self.rbac       = RBAC()
        self.cache      = RedisCache()
        self.pipeline   = DetectionPipeline()
        self.buffers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.fp: set    = set()
        self.fp_lock    = Lock()
        self.running    = False
        self.secret     = os.getenv("XDR_SECRET", "DefaultFallbackSecret-2026").encode()
        self.psi: Optional[PSI] = None
        self.workers: List[threading.Thread] = []
        self.baseline: List[np.ndarray] = []
        self.attack: List[np.ndarray]   = []
        self.retrain_lock = Lock()

    def sign(self, body: dict) -> str:
        return hmac.new(self.secret, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    def verify(self, data: dict) -> bool:
        sig = data.get("signature", "")
        payload = {k: v for k, v in data.items() if k != "signature"}
        return hmac.compare_digest(sig, self.sign(payload))

    def features(self, host: str, events: list) -> np.ndarray:
        now = time.time()
        buf = self.buffers[host]
        for e in events:
            buf.append((now, e))
        window_5m = [(ts, e) for ts, e in buf if now - ts <= 300]
        window_1m = [(ts, e) for ts, e in window_5m if now - ts <= 60]
        proc1 = proc5 = recon = encoded = svc = logs = lsass = uac = 0
        lateral = rare = unsigned = dns = priv_chain = 0
        integrity_jump = persist = reg_tamper = sched_task = wmi_persist = shadow_del = 0
        net_recon = mass_del = exfil_stage = 0
        outb = inb = 0.0
        lens: List[int] = []
        ents: List[float] = []
        file_writes_1m: int = 0
        file_writes_5m: int = 0
        file_renames_5m: int = 0
        file_deletes_5m: int = 0
        encrypt_ext_hits: int = 0
        entropy_spikes: int = 0
        access_denied_5m: int = 0
        dirs_accessed: set = set()
        file_opens_5m: int = 0
        dir_traversals_5m: int = 0
        net_destinations: set = set()
        net_bytes_out: float = 0.0

        for ts, e in window_5m:
            et  = e.get("event_type", "")
            cmd = e.get("command_line", "")
            lo  = cmd.lower() if cmd else ""

            if et == "process_spawn":
                proc5 += 1
                if ts >= now - 60:
                    proc1 += 1
                if cmd:
                    lens.append(len(cmd))
                    ents.append(_shannon_entropy(cmd))
                    if self._RECON_EXTENDED.search(cmd):
                        recon += 1
                    if "net user" in lo or "net localgroup" in lo or "nltest" in lo:
                        net_recon += 1
                    if "-enc" in lo or "-encodedcommand" in lo or "iex" in lo:
                        encoded += 1
                    if re.search(r'sc(\.exe)?\s+stop|net\s+stop', cmd, re.I):
                        svc += 1
                    if "wevtutil" in lo or "clear-eventlog" in lo:
                        logs += 1
                    if self._LSASS_EXTENDED.search(cmd):
                        lsass += 1
                    if self._UAC_BYPASS.search(cmd):
                        uac += 1
                    if self._LATERAL.search(cmd):
                        lateral += 1
                    if "unsigned" in lo or "unverified" in lo:
                        unsigned += 1
                    if self._NET_SUSPICIOUS.search(cmd):
                        dns += 1
                    if "temp" in lo and "system32" in lo:
                        rare += 1
                    if self._SHADOW_DELETE.search(cmd):
                        shadow_del += 1
                    if self._PERSIST_REG.search(cmd):
                        reg_tamper += 1
                        persist += 1
                    if self._PERSIST_SCHTASK.search(cmd):
                        sched_task += 1
                        persist += 1
                    if self._PERSIST_WMI.search(cmd):
                        wmi_persist += 1
                        persist += 1
                    if self._PERSIST_STARTUP.search(cmd):
                        persist += 1
                    if self._INTEGRITY_JUMP.search(cmd):
                        integrity_jump += 1
                    if self._EXFIL_STAGE.search(cmd):
                        exfil_stage += 1
                    if re.search(r'del\s+/[sfq]|rmdir\s+/s|Remove-Item\s+-Recurse', cmd, re.I):
                        mass_del += 1

            elif et in ("file_write", "file_create"):
                path = e.get("path", "") or e.get("file_path", "")
                file_writes_5m += 1
                if ts >= now - 60:
                    file_writes_1m += 1
                if path:
                    d = _extract_directory(path)
                    if d:
                        dirs_accessed.add(d)
                    if _has_ransom_extension(path):
                        encrypt_ext_hits += 1
                    content = e.get("content_sample", "")
                    if content and _shannon_entropy(content) > 7.2:
                        entropy_spikes += 1

            elif et in ("file_rename", "file_move"):
                file_renames_5m += 1
                new_path = e.get("new_path", "") or e.get("target_path", "")
                if new_path and _has_ransom_extension(new_path):
                    encrypt_ext_hits += 1

            elif et == "file_delete":
                file_deletes_5m += 1
                if file_deletes_5m > 50:
                    mass_del += 1

            elif et in ("file_open", "file_read"):
                file_opens_5m += 1
                path = e.get("path", "")
                if path:
                    d = _extract_directory(path)
                    if d:
                        dirs_accessed.add(d)

            elif et == "access_denied":
                access_denied_5m += 1

            elif et == "directory_traversal":
                dir_traversals_5m += 1

            elif et in ("network_connection", "network_flow", "dns_query"):
                dst = e.get("destination", "") or e.get("remote_address", "") or e.get("query", "")
                if dst:
                    net_destinations.add(dst.lower())
                    if self._NET_SUSPICIOUS.search(dst):
                        dns += 1
                bytes_out = float(e.get("bytes_sent", e.get("bytes_out", 0)) or 0)
                bytes_in  = float(e.get("bytes_recv", e.get("bytes_in", 0)) or 0)
                net_bytes_out += bytes_out
                outb += bytes_out
                inb  += bytes_in

            elif et == "token_elevation":
                integrity_jump += 1

            elif et == "registry_write":
                key = e.get("registry_key", "")
                if key and self._PERSIST_REG.search(key):
                    reg_tamper += 1
                    persist += 1

        if svc > 0 and logs > 0:
            priv_chain = 1
        if shadow_del > 0 and encrypt_ext_hits > 0:
            priv_chain = max(priv_chain, 2)
        dir_velocity = float(len(dirs_accessed)) / 300.0
        traversal_count = dir_traversals_5m + file_opens_5m // 10

        return np.array([
            proc1        / 60.0,
            proc5        / 300.0,
            float(np.mean(ents)) if ents else 0.0,
            float(np.mean(lens)) if lens else 0.0,
            float(recon),
            float(encoded),
            float(svc),
            float(logs),
            float(lsass),
            float(uac),
            float(lateral),
            float(rare),
            float(unsigned),
            float(dns),
            outb / 1e6,
            inb  / 1e6,
            float(priv_chain),
            float(np.cos(2 * np.pi * (now % 86400) / 86400)),
            file_writes_1m / 60.0,
            file_writes_5m / 300.0,
            file_renames_5m / 300.0,
            file_deletes_5m / 300.0,
            float(encrypt_ext_hits),
            float(entropy_spikes),
            access_denied_5m / 300.0,
            float(traversal_count),
            float(len(dirs_accessed)),
            dir_velocity,
            float(len(net_destinations)),
            net_bytes_out / 1e6,
            float(integrity_jump),
            float(persist),
            float(reg_tamper),
            float(sched_task),
            float(wmi_persist),
            float(shadow_del),
            float(net_recon),
            float(mass_del),
            float(exfil_stage),
        ], dtype=np.float64)

    def rules(self, events: list) -> Tuple[List[str], List[str]]:
        cmd_text = " ".join(e.get("command_line", "") for e in events)
        path_text = " ".join(
            (e.get("path", "") or e.get("new_path", "") or e.get("target_path", ""))
            for e in events
        )
        full_text = cmd_text + " " + path_text
        triggered: List[str] = []
        mitre: List[str] = []
        for rule in RULES:
            if rule.get("require_all", False):
                hit = all(p.search(full_text) for p in rule["patterns"])
            else:
                hit = any(p.search(full_text) for p in rule["patterns"])
            if hit:
                triggered.append(rule["id"])
                if rule["mitre"] not in mitre:
                    mitre.append(rule["mitre"])
        return triggered, mitre

    def _classify_behavior(self, vec: np.ndarray, mitre: list) -> List[str]:
        tags: List[str] = []
        fw5   = vec[FEATURES.index("file_write_rate_5m")]   * 300
        frn5  = vec[FEATURES.index("file_rename_rate_5m")]  * 300
        fdel5 = vec[FEATURES.index("file_delete_rate_5m")]  * 300
        ext   = vec[FEATURES.index("encrypt_ext_hits")]
        ent   = vec[FEATURES.index("entropy_spike_count")]
        shad  = vec[FEATURES.index("shadow_delete_hits")]
        if fw5 > 100 and (ext > 0 or ent > 5 or frn5 > 50):
            tags.append("RANSOMWARE")
            if HAS_PROM:
                RANSOM_CTR.inc()
        if fw5 > 100 and fdel5 > 50 and vec[FEATURES.index("net_bytes_out_mb")] > 10:
            tags.append("INSIDER_THREAT")
            if HAS_PROM:
                INSIDER_CTR.inc()
        acc_denied = vec[FEATURES.index("access_denied_rate_5m")] * 300
        dirs       = vec[FEATURES.index("unique_dirs_accessed")]
        trav_vel   = vec[FEATURES.index("traversal_velocity")]
        if acc_denied > 30 or dirs > 80 or trav_vel > 0.5:
            tags.append("INSIDER_RECON")
            if HAS_PROM:
                INSIDER_CTR.inc()
        if vec[FEATURES.index("lsass_hits")] > 0 or vec[FEATURES.index("uac_hits")] > 0:
            tags.append("PRIVILEGE_ESCALATION")
            if HAS_PROM:
                PRIVESC_CTR.inc()
        if vec[FEATURES.index("integrity_jump_hits")] > 0:
            tags.append("INTEGRITY_LEVEL_JUMP")
            if HAS_PROM:
                PRIVESC_CTR.inc()
        if vec[FEATURES.index("persistence_hits")] > 0:
            tags.append("PERSISTENCE_ESTABLISHED")
        if vec[FEATURES.index("lateral_spread")] > 0:
            tags.append("LATERAL_MOVEMENT")
        if shad > 0:
            tags.append("SHADOW_COPY_DELETION")
        if vec[FEATURES.index("exfil_staging_hits")] > 0:
            tags.append("EXFIL_STAGING")
        if "T1041" in mitre or vec[FEATURES.index("net_bytes_out_mb")] > 50:
            tags.append("DATA_EXFILTRATION")
        return tags

    def predict_stage(self, mitre: list) -> Tuple[str, float]:
        stages: List[int] = []
        for m in mitre:
            for t in MITRE.get(m, {}).get("tactics", []):
                if t in STAGES:
                    stages.append(STAGES[t])
        if not stages:
            return "Unknown", 0.0
        idx = max(set(stages), key=stages.count)
        row = TRANSITIONS[min(idx, len(TRANSITIONS) - 1)]
        nxt = int(np.argmax(row))
        rev = {v: k for k, v in STAGES.items()}
        return rev.get(nxt, "Unknown"), float(row[nxt])

    def scan_iocs(self, events: list) -> list:
        hits: List[str] = []
        for e in events:
            for k in ("command_line", "remote_address", "url", "file_hash", "dns_query", "destination"):
                val = e.get(k, "")
                if val:
                    h = self.intel.lookup(val)
                    if h:
                        hits.append(f"{h.ioc_type}:{h.value}")
                        if HAS_PROM:
                            IOCS_CTR.inc()
        return hits

    def retrain(self):
        with self.retrain_lock:
            if len(self.baseline) < 200 or len(self.attack) < 50:
                return
            benign    = np.array(self.baseline[-2000:])
            malicious = np.array(self.attack[-500:])
            self.pipeline.fit(benign, malicious)
            self.psi = PSI(benign)
            if HAS_PROM:
                DRIFT_CTR.inc()
            logger.info("[ML] Models retrained on updated baseline.")

    def bootstrap(self):
        rng = np.random.default_rng(42)
        n   = self.N_FEATURES
        benign    = [rng.normal(0, 0.2, n).clip(0) for _ in range(800)]
        malicious = []
        for _ in range(300):
            row = rng.normal(0, 0.3, n).clip(0)
            row[FEATURES.index("lsass_hits")]           = rng.choice([0, 1, 2, 3])
            row[FEATURES.index("service_mods")]         = rng.choice([0, 1, 2])
            row[FEATURES.index("log_clear")]            = rng.choice([0, 1])
            row[FEATURES.index("proc_rate_5m")]        += rng.uniform(0.5, 2.0)
            row[FEATURES.index("file_write_rate_5m")]  += rng.uniform(0.2, 1.5)
            row[FEATURES.index("encrypt_ext_hits")]     = rng.choice([0, 0, 1, 5, 20])
            row[FEATURES.index("entropy_spike_count")] = rng.choice([0, 0, 1, 3])
            row[FEATURES.index("shadow_delete_hits")]   = rng.choice([0, 0, 0, 1])
            row[FEATURES.index("access_denied_rate_5m")] += rng.uniform(0, 0.3)
            row[FEATURES.index("unique_dirs_accessed")] += rng.uniform(0, 50)
            row[FEATURES.index("integrity_jump_hits")] = rng.choice([0, 0, 1])
            row[FEATURES.index("persistence_hits")]     = rng.choice([0, 0, 1, 2])
            malicious.append(row)
        self.baseline.extend(benign)
        self.attack.extend(malicious)
        self.pipeline.fit(np.array(benign), np.array(malicious))
        self.psi = PSI(np.array(benign))
        logger.info("[ML] Bootstrap complete — 5-model ensemble ready.")

    def ingest(self, raw: str):
        try:
            self.queue.put(raw, timeout=1)
        except queue.Full:
            logger.error("[Ingest] Queue full — dropping payload.")

    def _worker(self):
        while self.running:
            try:
                raw = self.queue.get(timeout=1)
            except queue.Empty:
                continue
            start = time.time()
            try:
                data = json.loads(raw)
                if not self.verify(data):
                    continue
                sig = data.get("signature", "")
                if self.db.seen(sig):
                    continue
                self.db.mark(sig)
                host   = data.get("host_id", "unknown")
                user   = data.get("user_id", "unknown")
                events = data.get("events", [])
                with self.fp_lock:
                    if user in self.fp:
                        continue
                vec   = self.features(host, events)
                score = self.pipeline.score(vec)
                if score < 35:
                    self.baseline.append(vec)
                elif score > 60:
                    self.attack.append(vec)
                if self.psi and len(self.baseline) > 500 and len(self.baseline) % 200 == 0:
                    recent = np.array(self.baseline[-400:])
                    if self.psi.score(recent) > 0.25:
                        threading.Thread(target=self.retrain, daemon=True).start()
                if score < self.THRESHOLD:
                    continue
                triggered_rules, mitre = self.rules(events)
                iocs       = self.scan_iocs(events)
                stage, cf  = self.predict_stage(mitre)
                tags       = self._classify_behavior(vec, mitre)
                integ_jump = vec[FEATURES.index("integrity_jump_hits")] > 0
                actions: List[str] = []
                if score > 90 or "RANSOMWARE" in tags:
                    actions.extend(["ISOLATE_HOST", "BLOCK_EGRESS", "SNAPSHOT_MEMORY",
                                    "DISABLE_TOKENS", "DEPLOY_DECEPTION_CREDS"])
                elif score > 80 or "PRIVILEGE_ESCALATION" in tags or "INSIDER_THREAT" in tags:
                    actions.extend(["INCREASE_SAMPLING", "SANDBOX_PROCESS",
                                    "NOTIFY_SOC", "DEPLOY_HONEYTOKENS"])
                elif score > 65:
                    actions.extend(["WATCHLIST", "ALERT_ANALYST"])
                threat = "CRITICAL" if score > 90 else "HIGH" if score > 75 else "MEDIUM"
                alert = Alert(
                    incident_id=f"INC-{uuid.uuid4().hex[:10].upper()}",
                    host_id=host, user_id=user, score=round(score, 2),
                    threat=threat, rules=triggered_rules, mitre=mitre,
                    iocs=iocs, next_stage=stage, confidence=round(cf, 3),
                    actions=actions, behavior_tags=tags, integrity_jump=integ_jump,
                )
                payload = alert.dump()
                self.db.store_alert(payload)
                self.kafka.publish(payload)
                self.webhook.send(payload)
                if HAS_PROM:
                    ALERTS_CTR.inc()
            except Exception as e:
                logger.error(f"[Worker] Error: {e}")
            finally:
                if HAS_PROM:
                    LATENCY_H.observe(time.time() - start)
                    QUEUE_G.set(self.queue.qsize())
                    EVENTS_CTR.inc()
                self.queue.task_done()

    def start(self, n: int = 4):
        self.intel.load_local()
        self.bootstrap()
        self.running = True
        for _ in range(n):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.workers.append(t)
        logger.info(f"[Engine] {n} worker threads started.")

    def stop(self):
        self.running = False
        for t in self.workers:
            t.join(timeout=2)
        logger.info("[Engine] Stopped.")

    def metrics(self) -> str:
        if HAS_PROM:
            return generate_latest().decode()
        return "prometheus_client not installed"

if __name__ == "__main__":
    import sys
    engine = Engine()
    engine.start(n=4)
    body = {
        "host_id": "dc-prod-01",
        "user_id": "svc-backup",
        "events": [
            {"event_type": "process_spawn", "command_line": "whoami /priv"},
            {"event_type": "process_spawn", "command_line": "net user /domain"},
            {"event_type": "process_spawn", "command_line": "net localgroup administrators"},
            {"event_type": "process_spawn", "command_line": "sc.exe stop WinDefend"},
            {"event_type": "process_spawn", "command_line": "wevtutil.exe cl System"},
            {"event_type": "process_spawn", "command_line": "procdump.exe -ma lsass.exe c:\\temp\\lsass.dmp"},
            {"event_type": "process_spawn", "command_line": "psexec \\\\dc-02 cmd.exe"},
            {"event_type": "process_spawn", "command_line": "vssadmin delete shadows /all /quiet"},
            {"event_type": "process_spawn", "command_line": "schtasks /create /tn backdoor /tr c:\\temp\\evil.exe /sc onlogon"},
            {"event_type": "process_spawn", "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d c:\\temp\\evil.exe"},
            {"event_type": "file_write",    "path": "C:\\Users\\admin\\Documents\\report.docx.locked", "content_sample": "\xff\xfe" + "A" * 200},
            {"event_type": "file_write",    "path": "C:\\Users\\admin\\Desktop\\budget.xlsx.ryuk"},
            {"event_type": "file_rename",   "new_path": "C:\\data\\payroll.xlsx.conti"},
            {"event_type": "file_delete",   "path": "C:\\backup\\full_backup.bak"},
            {"event_type": "access_denied", "path": "C:\\Windows\\System32\\config\\SAM"},
            {"event_type": "access_denied", "path": "C:\\Users\\CEO\\Documents\\sensitive.pdf"},
            {"event_type": "directory_traversal", "path": "C:\\Users"},
            {"event_type": "network_flow",  "destination": "185.220.101.10", "bytes_sent": 52428800, "bytes_recv": 1024},
            {"event_type": "network_flow",  "destination": "duckdns.org", "bytes_sent": 1024, "bytes_recv": 512},
            {"event_type": "token_elevation", "integrity_level": "System", "previous_level": "Medium"},
        ],
    }
    body["signature"] = engine.sign(body)
    engine.ingest(json.dumps(body))
    time.sleep(3)
    print("=== QUEUED ALERTS ===")
    for a in engine.db.query_alerts(since=time.time() - 60):
        print(json.dumps(a, indent=2))
    engine.stop()