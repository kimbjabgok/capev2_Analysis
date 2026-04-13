"""AI 분석 리포트 — Claude / Gemini API"""
import json
import requests

CLAUDE_MODEL = "claude-sonnet-4-6"
GEMINI_MODEL = "gemini-2.0-flash"

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


# ── Claude ────────────────────────────────────────────────────
def analyze_claude(summary: dict, api_key: str) -> str:
    if not api_key:
        return "[오류] Claude API 키가 없습니다."
    headers = {
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    body = {
        "model":      CLAUDE_MODEL,
        "max_tokens": 2048,
        "system":     SYSTEM_PROMPT,
        "messages":   [{"role": "user", "content": _build_user_message(summary)}],
    }
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers, json=body, timeout=60
        )
        if r.status_code == 200:
            return r.json()["content"][0]["text"]
        return f"[오류] HTTP {r.status_code}: {r.text[:300]}"
    except Exception as e:
        return f"[오류] {e}"


# ── Gemini ────────────────────────────────────────────────────
def analyze_gemini(summary: dict, api_key: str) -> str:
    if not api_key:
        return "[오류] Gemini API 키가 없습니다."
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={api_key}"
    )
    body = {
        "contents": [{
            "parts": [{"text": SYSTEM_PROMPT + "\n\n" + _build_user_message(summary)}]
        }],
        "generationConfig": {"maxOutputTokens": 2048},
    }
    try:
        r = requests.post(url, json=body, timeout=60)
        if r.status_code == 200:
            candidates = r.json().get("candidates", [])
            if candidates:
                return candidates[0]["content"]["parts"][0]["text"]
            return "[오류] 응답 없음"
        return f"[오류] HTTP {r.status_code}: {r.text[:300]}"
    except Exception as e:
        return f"[오류] {e}"


def analyze(summary: dict, provider: str, api_key: str) -> str:
    if provider.lower() == "gemini":
        return analyze_gemini(summary, api_key)
    return analyze_claude(summary, api_key)
