"""외부 서비스 연동 — VirusTotal API + Groq AI 분석"""

# ══════════════════════════════════════════════════════════════
# vt_api (VirusTotal, 무료 키: 분당 4회)
# ══════════════════════════════════════════════════════════════
import time
import threading
import requests

VT_BASE = "https://www.virustotal.com/api/v3"
_lock = threading.Lock()
_call_times: list = []
MAX_PER_MIN = 4


def _rate_check() -> bool:
    now = time.time()
    with _lock:
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


# ══════════════════════════════════════════════════════════════
# ai_analysis (Groq — llama-3.3-70b-versatile)
# ══════════════════════════════════════════════════════════════
import json

GROQ_MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """당신은 악성코드 분석 전문가입니다.
CAPEv2 샌드박스 분석 결과를 한국어로 분석하여 다음 형식으로 보고서를 작성하세요:

## 위협 요약
## 악성 행위 분석
## 네트워크 활동
## 지속성 및 회피
## 권고사항
"""


def _build_user_message(summary: dict) -> str:
    return f"""다음은 CAPEv2 악성코드 분석 결과입니다. 한국어로 상세 분석 보고서를 작성해주세요.

```json
{json.dumps(summary, ensure_ascii=False, indent=2)[:8000]}
```
"""


def analyze(summary: dict, api_key: str) -> str:
    if not api_key:
        return "[오류] Groq API 키가 없습니다."
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    body = {
        "model": GROQ_MODEL,
        "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_message(summary)},
        ],
    }
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers, json=body, timeout=60
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        return f"[오류] HTTP {r.status_code}: {r.text[:300]}"
    except Exception as e:
        return f"[오류] {e}"
