"""Discord 웹훅 알림 — High 이상 심각도 탐지 시"""
import requests
import json
from datetime import datetime

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_THRESHOLD = 3  # high


def _build_embed(report_summary: dict, triggered_sigs: list) -> dict:
    score = report_summary.get("verdict", {}).get("score", 0)
    sha256 = report_summary.get("hashes", {}).get("sha256", "N/A")
    families = ", ".join(report_summary.get("verdict", {}).get("families", [])) or "Unknown"

    fields = []
    for sig in triggered_sigs:
        sev = sig.get("severity", "").upper()
        name = sig.get("name", "")
        fields.append({
            "name":   f"[{sev}] {name}",
            "value":  sig.get("description", "")[:256],
            "inline": False,
        })

    color = 0xFF0000 if any(
        SEVERITY_ORDER.get(s.get("severity", ""), 0) >= 4 for s in triggered_sigs
    ) else 0xFF6600

    return {
        "title":       f"CAPEv2 Alert — Score {score}",
        "description": f"**Family:** {families}\n**SHA256:** `{sha256}`",
        "color":       color,
        "fields":      fields[:25],
        "footer":      {"text": f"CAPEv2 Report Analyzer • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
    }


def send_alert(webhook_url: str, report_summary: dict, all_signatures: list) -> dict:
    """High 이상 시그니처만 필터링 후 Discord 전송"""
    if not webhook_url:
        return {"error": "No webhook URL"}

    triggered = [
        s for s in all_signatures
        if SEVERITY_ORDER.get(s.get("severity", "").lower(), 0) >= ALERT_THRESHOLD
    ]
    if not triggered:
        return {"skipped": "No High+ signatures"}

    embed = _build_embed(report_summary, triggered)
    payload = {"embeds": [embed], "username": "CAPEv2 Analyzer"}

    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.status_code in (200, 204):
            return {"success": True, "count": len(triggered)}
        return {"error": str(r.status_code), "message": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}
