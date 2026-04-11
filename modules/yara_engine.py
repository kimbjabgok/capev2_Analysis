"""YARA 룰 적용 엔진"""
from pathlib import Path
import tempfile, os

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
    """바이트 데이터에 YARA 룰 적용 → 매치 목록"""
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
    """CAPE 페이로드 데이터에 룰 적용"""
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
