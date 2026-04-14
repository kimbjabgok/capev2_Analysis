"""분석 엔진 — 커스텀 시그니처 + YARA + 화이트노이즈 필터"""

# ══════════════════════════════════════════════════════════════
# signatures (CMR 커스텀 시그니처 탐지)
# ══════════════════════════════════════════════════════════════
import re
from typing import List, Dict, Any

TAG = "[CMR]"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

LOLBINS = {
    "powershell", "cmd", "bitsadmin", "certutil", "mshta",
    "rundll32", "regsvr32", "wscript", "cscript",
}

DOWNLOAD_HINTS = [
    r"http://", r"https://", r"hxxp",
    r"invoke-webrequest", r"\biwr\b", r"\bwget\b", r"\bcurl\b",
    r"downloadstring", r"new-object net\.webclient",
    r"start-bitstransfer",
    r"-enc\b", r"-encodedcommand", r"frombase64string",
    r"certutil\s+-urlcache\s+-split\s+-f",
    r"bitsadmin\s+/transfer",
    r"\|\s*iex",
]

DROP_PATHS = [
    r"\\temp\\", r"\\appdata\\roaming\\", r"\\appdata\\local\\",
    r"\\programdata\\", r"\\users\\public\\", r"\\downloads\\",
]

BONUS_EXT = {".exe", ".dll", ".ps1", ".js", ".vbs", ".bat", ".cmd", ".scr"}

PERSIST_REGISTRY = [
    r"\\software\\microsoft\\windows\\currentversion\\run",
    r"\\software\\microsoft\\windows\\currentversion\\runonce",
    r"\\system\\currentcontrolset\\services\\",
    r"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
]

PERSIST_WMI = [
    "__eventfilter", "__eventconsumer", "__filtertoconsumerbinding",
    "commandlineeventconsumer", "activescripteventconsumer",
]

PERSIST_CMDS = [
    r"schtasks\s+/create", r"sc\s+create", r"reg\s+add",
]

PERSIST_STARTUP = r"\\microsoft\\windows\\start menu\\programs\\startup\\"

PERSIST_EXT = {".exe", ".dll", ".lnk", ".vbs", ".js", ".bat", ".cmd", ".ps1"}

SENSITIVE_BROWSER = [
    r"\\google\\chrome\\user data\\default\\login data",
    r"\\google\\chrome\\user data\\default\\cookies",
    r"\\google\\chrome\\user data\\default\\web data",
    r"\\google\\chrome\\user data\\local state",
    r"\\microsoft\\edge\\user data\\local state",
    r"\\bravesoftware\\brave-browser\\user data\\local state",
]

SENSITIVE_WALLET = [
    r"\\exodus\\", r"\\electrum\\", r"wallet\.dat",
]


def _search(patterns: list, text: str) -> List[str]:
    hits = []
    tl = text.lower()
    for p in patterns:
        if re.search(p, tl):
            hits.append(p)
    return hits


def _flatten_behavior(report_data: dict) -> List[str]:
    texts = []
    behavior = report_data.get("behavior", {})
    for proc in behavior.get("processes", []):
        for call in proc.get("calls", []):
            texts.append(call.get("api", ""))
            for arg in call.get("arguments", []):
                if isinstance(arg, dict):
                    texts.append(str(arg.get("value", "")))
                else:
                    texts.append(str(arg))
    for proc in behavior.get("processes", []):
        texts.append(proc.get("command_line", ""))
    return texts


def _collect_evidence(texts: list, patterns: list, label: str) -> List[str]:
    ev = []
    for t in texts:
        hits = _search(patterns, t)
        if hits:
            snippet = t[:120].replace("\n", " ")
            ev.append(f"{label}: {snippet}")
    return list(dict.fromkeys(ev))[:20]


def detect_download_exec(report_data: dict) -> Dict[str, Any] | None:
    texts = _flatten_behavior(report_data)
    strings = report_data.get("strings", [])
    if isinstance(strings, list):
        texts += strings

    evidence_lolbin = _collect_evidence(texts, [rf"\b{b}\b" for b in LOLBINS], "LOLBin")
    evidence_dl     = _collect_evidence(texts, DOWNLOAD_HINTS, "DL-hint")
    evidence_drop   = _collect_evidence(texts, DROP_PATHS, "DropPath")

    score = 0
    if evidence_lolbin: score += 2
    if evidence_dl:     score += 3
    if evidence_drop:   score += 1

    all_text = " ".join(texts).lower()
    for ext in BONUS_EXT:
        if ext in all_text:
            score += 1
            break

    if score < 3:
        return None

    severity = "medium" if score < 5 else "high" if score < 7 else "critical"
    return {
        "name":        f"{TAG} Download/Exec Chain",
        "description": "LOLBin을 이용한 다운로드-실행 체인이 탐지되었습니다.",
        "severity":    severity,
        "score":       score,
        "evidence":    evidence_lolbin + evidence_dl + evidence_drop,
        "ttp":         ["T1059", "T1105", "T1218"],
        "custom":      True,
    }


def detect_persistence(report_data: dict) -> Dict[str, Any] | None:
    texts = _flatten_behavior(report_data)

    ev_reg  = _collect_evidence(texts, PERSIST_REGISTRY, "Registry")
    ev_wmi  = _collect_evidence(texts, PERSIST_WMI, "WMI")
    ev_cmd  = _collect_evidence(texts, PERSIST_CMDS, "Command")
    ev_stup = _collect_evidence(texts, [PERSIST_STARTUP], "Startup")

    score = 0
    if ev_reg:  score += 3
    if ev_wmi:  score += 3
    if ev_cmd:  score += 2
    if ev_stup: score += 2

    all_text = " ".join(texts).lower()
    for ext in PERSIST_EXT:
        if ext in all_text:
            score += 1
            break

    if score < 2:
        return None

    severity = "low" if score < 3 else "medium" if score < 5 else "high"
    return {
        "name":        f"{TAG} Persistence Installed",
        "description": "재부팅/로그인 후에도 유지되는 지속성 메커니즘이 탐지되었습니다.",
        "severity":    severity,
        "score":       score,
        "evidence":    ev_reg + ev_wmi + ev_cmd + ev_stup,
        "ttp":         ["T1547", "T1053", "T1543", "T1546"],
        "custom":      True,
    }


def detect_sensitive_access(report_data: dict) -> Dict[str, Any] | None:
    texts = _flatten_behavior(report_data)

    ev_browser = _collect_evidence(texts, SENSITIVE_BROWSER, "Browser")
    ev_wallet  = _collect_evidence(texts, SENSITIVE_WALLET, "Wallet")

    score = len(ev_browser) * 2 + len(ev_wallet) * 3

    if score < 2:
        return None

    severity = "high" if score < 6 else "critical"
    return {
        "name":        f"{TAG} Sensitive Data Access",
        "description": "브라우저 자격증명 또는 암호화폐 지갑에 접근이 탐지되었습니다.",
        "severity":    severity,
        "score":       score,
        "evidence":    ev_browser + ev_wallet,
        "ttp":         ["T1555", "T1539", "T1552"],
        "custom":      True,
    }


def run_all(report_data: dict) -> List[Dict[str, Any]]:
    results = []
    for fn in (detect_download_exec, detect_persistence, detect_sensitive_access):
        r = fn(report_data)
        if r:
            results.append(r)
    return results


# ══════════════════════════════════════════════════════════════
# yara_engine
# ══════════════════════════════════════════════════════════════
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "yara_rules"

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def _compile_rules():
    if not YARA_AVAILABLE:
        return None
    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return None
    filepaths = {f.stem: str(f) for f in rule_files}
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as e:
        print(f"[YARA] compile error: {e}")
        return None


_rules = None


def get_rules():
    global _rules
    if _rules is None:
        _rules = _compile_rules()
    return _rules


def scan_data(data: bytes) -> list:
    rules = get_rules()
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data)
        return [{"rule": m.rule, "tags": list(m.tags), "strings": [
            {"offset": s.instances[0].offset if s.instances else 0,
             "identifier": s.identifier,
             "data": s.instances[0].matched_data[:64].hex() if s.instances else ""}
            for s in m.strings
        ]} for m in matches]
    except Exception as e:
        print(f"[YARA] scan error: {e}")
        return []


def scan_file(path: str) -> list:
    rules = get_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(path)
        return [{"rule": m.rule, "tags": list(m.tags)} for m in matches]
    except Exception as e:
        print(f"[YARA] file scan error: {e}")
        return []


def scan_report_payloads(report_data: dict) -> list:
    results = []
    for payload in report_data.get("CAPE", {}).get("payloads", []):
        raw = payload.get("data", b"")
        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="replace")
        matches = scan_data(raw)
        if matches:
            results.append({
                "sha256":  payload.get("sha256", ""),
                "matches": matches,
            })
    return results


# ══════════════════════════════════════════════════════════════
# whitenoise (정상 Windows OS 행위 필터링)
# ══════════════════════════════════════════════════════════════
import json as _json

_DEFAULT_FILTER_FILE = Path(__file__).parent.parent / "whitenoise_filter.json"


def load_filter(path=None) -> dict:
    p = Path(path) if path else _DEFAULT_FILTER_FILE
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return _json.load(f)
    return {"processes": [], "api_calls": [], "registry_keys": [], "signature_names": []}


def filter_api_calls(calls: list, wn: dict) -> list:
    blocked_apis  = {a.lower() for a in wn.get("api_calls", [])}
    blocked_procs = {p.lower() for p in wn.get("processes", [])}
    result = []
    for c in calls:
        if c.get("api", "").lower() in blocked_apis:
            continue
        if c.get("process", "").lower() in blocked_procs:
            continue
        result.append(c)
    return result


def filter_signatures(sigs: list, wn: dict) -> list:
    blocked = {s.lower() for s in wn.get("signature_names", [])}
    return [s for s in sigs if s.get("name", "").lower() not in blocked]


def filter_registry_keys(keys: list, wn: dict) -> list:
    blocked = [p.lower() for p in wn.get("registry_keys", [])]
    result = []
    for k in keys:
        key_lower = k.lower()
        if not any(key_lower.startswith(b) for b in blocked):
            result.append(k)
    return result
