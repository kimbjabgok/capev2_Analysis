"""VirusTotal API 연동 (무료 키: 분당 4회)"""
import time
import threading
import requests

VT_BASE = "https://www.virustotal.com/api/v3"
_lock = threading.Lock()
_call_times: list = []
MAX_PER_MIN = 4


def _rate_check() -> bool:
    """True면 호출 가능, False면 한도 초과"""
    now = time.time()
    with _lock:
        # 1분 이전 기록 삭제
        while _call_times and now - _call_times[0] > 60:
            _call_times.pop(0)
        if len(_call_times) >= MAX_PER_MIN:
            return False
        _call_times.append(now)
        return True


def lookup_hash(sha256: str, api_key: str) -> dict:
    """sha256으로 파일 조회 → {positives, total, link, error}"""
    if not api_key or not sha256:
        return {"error": "API key or hash missing"}
    if not _rate_check():
        return {"error": "rate_limit", "message": "VirusTotal 분당 요청 한도(4회) 초과"}

    headers = {"x-apikey": api_key}
    try:
        r = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=15)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "positives": positives,
                "total":     total,
                "link":      f"https://www.virustotal.com/gui/file/{sha256}",
                "family":    attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
            }
        elif r.status_code == 404:
            return {"error": "not_found", "message": "VT에 해당 해시 없음"}
        elif r.status_code == 401:
            return {"error": "auth", "message": "API 키 오류"}
        else:
            return {"error": str(r.status_code), "message": r.text[:200]}
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def remaining_calls() -> int:
    now = time.time()
    with _lock:
        recent = [t for t in _call_times if now - t <= 60]
        return max(0, MAX_PER_MIN - len(recent))
