"""Whitenoise filter — 정상 Windows OS 행위 필터링"""
import json
from pathlib import Path

_DEFAULT_FILTER_FILE = Path(__file__).parent.parent / "whitenoise_filter.json"


def load_filter(path=None) -> dict:
    p = Path(path) if path else _DEFAULT_FILTER_FILE
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"processes": [], "api_calls": [], "registry_keys": []}


def filter_api_calls(calls: list, wn: dict) -> list:
    blocked_apis   = {a.lower() for a in wn.get("api_calls", [])}
    blocked_procs  = {p.lower() for p in wn.get("processes", [])}
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
