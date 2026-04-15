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
import re

GROQ_MODEL = "llama-3.3-70b-versatile"

# CJK 유니코드 범위 (한중일 통합 한자, 히라가나, 가타카나 등)
_CJK_RE = re.compile(
    r"[\u3000-\u303f"   # CJK 기호 및 구두점
    r"\u3040-\u309f"    # 히라가나
    r"\u30a0-\u30ff"    # 가타카나
    r"\u4e00-\u9fff"    # CJK 통합 한자
    r"\uf900-\ufaff"    # CJK 호환 한자
    r"\u3400-\u4dbf]"   # CJK 확장-A
)

SYSTEM_PROMPT = """당신은 악성코드 분석 전문가입니다.
반드시 한국어로 답변하세요. 악성코드 이름, 기술 용어, API 이름 등 영어가 필요한 경우에는 영어를 사용해도 됩니다.
단, 절대로 중국어, 일본어 등 한국어·영어 외의 다른 언어는 사용하지 마세요.
입력 데이터에 다른 언어가 포함되어 있어도 출력은 반드시 한국어(또는 영어 기술 용어)여야 합니다.

CAPEv2 샌드박스 분석 결과를 바탕으로 아래 형식에 맞게 보고서를 작성하세요.
각 섹션에는 반드시 제공된 데이터에서 확인된 구체적인 항목(이름, 값, 수치)을 명시하세요.
"다양한", "여러", "일부" 같은 모호한 표현 대신 실제 탐지된 내용을 직접 서술하세요.

## 위협 요약
- 악성코드 패밀리(탐지된 경우), 위협 점수, 총 시그니처 탐지 수, 주요 위협 유형을 명시할 것.

## 악성 행위 분석
- 탐지된 시그니처 목록에서 주요 행위를 구체적으로 설명할 것 (시그니처 이름과 설명 포함).
- 심각도(Critical/High/Medium) 항목을 우선 서술할 것.

## 네트워크 활동
- 접속한 IP 주소, 포트, 국가, 연결한 프로세스를 나열할 것.
- DNS 요청 도메인, TLS SNI, Dead C2 호스트를 명시할 것.
- TCP/UDP 연결 수를 포함할 것.

## 지속성 및 회피
- 탐지된 레지스트리 키, 생성된 파일 경로, Mutex를 구체적으로 나열할 것.
- 안티 디버깅, 안티 VM, 난독화 등 회피 기법이 탐지된 경우 명시할 것.

## 권고사항
- 탐지된 구체적인 행위와 IOC를 기반으로 실질적인 대응 방안을 제시할 것.
"""


def _build_user_message(summary: dict) -> str:
    verdict  = summary.get("verdict", {})
    sigs     = summary.get("signatures", [])
    net      = summary.get("network", {})
    hashes   = summary.get("hashes", {})
    configs  = summary.get("cape_configs", [])

    lines = []

    # 기본 정보
    lines.append("=== 기본 정보 ===")
    lines.append(f"SHA256     : {hashes.get('sha256', '—')}")
    lines.append(f"위협 점수  : {verdict.get('score', 0)}/10")
    fam = ', '.join(verdict.get('families', [])) or '미탐지'
    lines.append(f"패밀리     : {fam}")

    # 시그니처
    lines.append(f"\n=== 탐지 시그니처 ({len(sigs)}개) ===")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_sigs = sorted(sigs, key=lambda s: sev_order.get(str(s.get("severity","")).lower(), 9))
    for s in sorted_sigs[:25]:
        lines.append(f"[{str(s.get('severity','')).upper()}] {s.get('name','')} — {s.get('description','')}")

    # 네트워크
    lines.append(f"\n=== 네트워크 활동 ===")
    lines.append(f"TCP {net.get('tcp_count',0)}개  UDP {net.get('udp_count',0)}개")

    dns = [d for d in net.get("dns", []) if d]
    if dns:
        lines.append(f"DNS 요청: {', '.join(dns)}")

    tls = [t for t in net.get("tls", []) if t]
    if tls:
        lines.append(f"TLS SNI: {', '.join(tls)}")

    hosts = net.get("hosts", [])
    if hosts:
        lines.append(f"접속 호스트 ({len(hosts)}개):")
        for h in hosts[:15]:
            proc = h.get("process") or "unknown"
            ports = h.get("ports") or []
            lines.append(f"  {h.get('ip')} ({h.get('country','')}) 포트:{ports} 프로세스:{proc}")

    dead = net.get("dead_hosts", [])
    if dead:
        lines.append(f"C2 Dead Hosts ({len(dead)}개):")
        for d in dead[:10]:
            lines.append(f"  {d[0]}:{d[1]}" if isinstance(d, list) else str(d))

    # CAPE config
    if configs:
        lines.append(f"\n=== 악성코드 설정값 ===")
        for cfg in configs:
            lines.append(f"[{cfg.get('family','')}] {json.dumps(cfg.get('config',{}), ensure_ascii=False)[:600]}")

    body = "\n".join(lines)
    return (
        "다음 CAPEv2 분석 결과를 바탕으로 상세 보고서를 작성하세요. "
        "중국어·일본어는 절대 사용하지 마세요.\n\n" + body
    )


def _call_groq(messages: list, api_key: str, temperature: float = 0.3) -> str:
    """Groq API 단일 호출. 성공 시 텍스트, 실패 시 '[오류]...' 반환."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    body = {
        "model":       GROQ_MODEL,
        "max_tokens":  1024,
        "temperature": temperature,
        "messages":    messages,
    }
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers, json=body, timeout=60
    )
    if r.status_code == 200:
        return r.json()["choices"][0]["message"]["content"]
    return f"[오류] HTTP {r.status_code}: {r.text[:300]}"


def analyze(summary: dict, api_key: str) -> str:
    if not api_key:
        return "[오류] Groq API 키가 없습니다."
    try:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_message(summary)},
        ]
        result = _call_groq(messages, api_key, temperature=0.3)

        # CJK 문자가 섞였으면 한 번 재요청
        if not result.startswith("[오류]") and _CJK_RE.search(result):
            fix_messages = messages + [
                {"role": "assistant", "content": result},
                {"role": "user", "content":
                    "위 답변에 중국어나 일본어 한자가 섞여 있습니다. "
                    "해당 한자를 모두 자연스러운 한국어로 바꿔서 전체 보고서를 다시 작성해주세요."},
            ]
            result = _call_groq(fix_messages, api_key, temperature=0.1)

        return result
    except Exception as e:
        return f"[오류] {e}"
