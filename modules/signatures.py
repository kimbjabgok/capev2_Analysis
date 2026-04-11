"""커스텀 시그니처 탐지 엔진 — [CMR] 태그"""
import re
from typing import List, Dict, Any

TAG = "[CMR]"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── 공통 패턴 목록 ────────────────────────────────────────────

#Windows에 원래 설치된 정상 도구인데 악성코드가 악용하는 것들
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
    """패턴 목록 중 매칭된 것을 반환"""
    hits = []
    tl = text.lower()
    for p in patterns:
        if re.search(p, tl):
            hits.append(p)
    return hits


def _flatten_behavior(report_data: dict) -> List[str]:
    """behavior 섹션에서 문자열 덩어리 추출"""
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
    # also include strings/cmdlines from processes
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
    return list(dict.fromkeys(ev))[:20]  # deduplicate, max 20


# ── 시그니처 1: Download/Exec ─────────────────────────────────
#지속성이란 재부팅해도 악성코드가 살아남는 것. 방법마다 점수가 다름. LOLBin은 2점, 다운로드 힌트는 3점, 드롭 경로는 1점. 확장자 보너스는 1점.
def detect_download_exec(report_data: dict) -> Dict[str, Any] | None:
    texts = _flatten_behavior(report_data)
    # also check strings from file info
    strings = report_data.get("strings", [])
    if isinstance(strings, list):
        texts += strings

    evidence_lolbin  = _collect_evidence(texts, [rf"\b{b}\b" for b in LOLBINS], "LOLBin")
    evidence_dl      = _collect_evidence(texts, DOWNLOAD_HINTS, "DL-hint")
    evidence_drop    = _collect_evidence(texts, DROP_PATHS, "DropPath")

    # 점수 계산
    score = 0
    if evidence_lolbin:  score += 2
    if evidence_dl:      score += 3
    if evidence_drop:    score += 1

    # 확장자 보너스
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


# ── 시그니처 2: Persistence ───────────────────────────────────
def detect_persistence(report_data: dict) -> Dict[str, Any] | None:
    texts = _flatten_behavior(report_data)

    ev_reg  = _collect_evidence(texts, PERSIST_REGISTRY, "Registry")
    ev_wmi  = _collect_evidence(texts, PERSIST_WMI, "WMI")
    ev_cmd  = _collect_evidence(texts, PERSIST_CMDS, "Command")
    ev_stup = _collect_evidence(texts, [PERSIST_STARTUP], "Startup")

    score = 0
    if ev_reg:   score += 3
    if ev_wmi:   score += 3
    if ev_cmd:   score += 2
    if ev_stup:  score += 2

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


# ── 시그니처 3: Sensitive Access ──────────────────────────────
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
