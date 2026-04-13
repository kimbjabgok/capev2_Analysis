"""AI 분석 리포트 — Groq"""
import json
import requests

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
