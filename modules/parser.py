"""CAPEv2 report.json parser"""
import json
from pathlib import Path


def load_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


class ReportParser:
    def __init__(self, data: dict):
        self.raw = data
        self._custom_sigs: list = []

    def set_custom_sigs(self, sigs: list):
        """CMR 커스텀 시그니처를 주입 — parser 외부에서 생성된 시그니처를 통합"""
        self._custom_sigs = list(sigs)

    # ── 기본 정보 ──────────────────────────────────────────────
    def get_info(self) -> dict:
        return self.raw.get("info", {})

    def get_target(self) -> dict:
        return self.raw.get("target", {})

    def get_file_info(self) -> dict:
        target = self.get_target()
        return target.get("file", {})

    def get_hashes(self) -> dict:
        fi = self.get_file_info()
        return {
            "md5":    fi.get("md5", ""),
            "sha1":   fi.get("sha1", ""),
            "sha256": fi.get("sha256", ""),
            "sha512": fi.get("sha512", ""),
            "ssdeep": fi.get("ssdeep", ""),
        }

    def get_verdict(self) -> dict:
        """score + malware family"""
        # malscore (top-level) 우선, 없으면 info.score fallback
        score = self.raw.get("malscore", self.get_info().get("score", 0))

        # 정적 지표 점수 — 동적 분석 유무와 무관하게 항상 합산
        static = 0
        sev_pts = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
        for sig in self.get_signatures():
            sev = sig.get("severity", "")
            if isinstance(sev, int):
                sev = self._SEV_MAP.get(sev, "low")
            static += sev_pts.get(str(sev).lower(), 0)
        # YARA 매치마다 +2 (최대 +6)
        static += min(len(self.get_yara_matches()) * 2, 6)
        # CAPE 추출 config → 악성코드 확정 수준
        if self.get_cape_configs():
            static += 3
        score = min(score + static, 10)

        cape = self.raw.get("CAPE", {})
        families = []
        for payload in cape.get("payloads", []):
            for tag in payload.get("cape_yara", []):
                families.append(tag.get("name", ""))
        # signatures의 families 필드도 수집
        for sig in self.get_signatures():
            for fam in sig.get("families", []):
                if fam:
                    families.append(fam)
        return {"score": score, "families": list(set(families))}

    # ── PE ────────────────────────────────────────────────────
    def get_pe(self) -> dict:
        fi = self.get_file_info()
        return fi.get("pe", {})

    def get_pe_sections(self) -> list:
        return self.get_pe().get("sections", [])

    def get_pe_imports(self) -> list:
        imports = self.get_pe().get("imports", [])
        # dict 형태 {"DLL": {"dll":..., "imports":[...]}} → list 변환
        if isinstance(imports, dict):
            return list(imports.values())
        return imports

    _SUSPICIOUS_APIS = frozenset({
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "CreateRemoteThread", "NtCreateThreadEx", "WriteProcessMemory", "ReadProcessMemory",
        "OpenProcess", "NtOpenProcess", "SetWindowsHookEx", "GetAsyncKeyState",
        "URLDownloadToFile", "InternetOpen", "InternetConnect",
        "WinExec", "ShellExecute", "ShellExecuteEx",
        "RegSetValue", "RegCreateKey", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    })

    def get_suspicious_imports(self) -> list:
        """PE imports 중 의심 API 필터링"""
        result = []
        for imp in self.get_pe_imports():
            hits = [fn.get("name", "") for fn in imp.get("imports", [])
                    if fn.get("name", "") in self._SUSPICIOUS_APIS]
            if hits:
                result.append({"dll": imp.get("dll", ""), "functions": hits})
        return result

    # ── YARA ──────────────────────────────────────────────────
    def get_yara_matches(self) -> list:
        return self.raw.get("target", {}).get("file", {}).get("yara", [])

    # ── Signatures ────────────────────────────────────────────
    _SEV_MAP = {1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical"}

    def get_signatures(self) -> list:
        sigs = self.raw.get("signatures", [])
        # severity가 int로 오는 경우 문자열로 변환
        for s in sigs:
            sev = s.get("severity")
            if isinstance(sev, int):
                s["severity"] = self._SEV_MAP.get(sev, "low")
        return sigs + self._custom_sigs

    # ── ATT&CK ────────────────────────────────────────────────

    # 네트워크/C2 전용 TTP — PE 구조 시그니처와 매핑되면 오탐
    _NETWORK_TTPS = frozenset({
        "T1071", "T1095", "T1571", "T1573", "T1008",
        "T1090", "T1219", "T1102",
    })
    # PE 정적 구조 시그니처 이름에 포함되는 키워드
    _PE_STATIC_HINTS = (
        "pe_overlay", "pe_anomaly", "pe_header",
        "pe_section", "pe_import", "pe_corrupt",
        "contains_pe",
    )

    def _is_valid_ttp_pair(self, technique_id: str, sig_name: str) -> bool:
        """알려진 잘못된 TTP↔시그니처 조합을 거른다."""
        tid_base = technique_id.split(".")[0].upper()
        sig_lower = sig_name.lower()
        if tid_base in self._NETWORK_TTPS:
            if any(hint in sig_lower for hint in self._PE_STATIC_HINTS):
                return False
        return True

    def get_ttps(self) -> list:
        # signatures 이름 → description 매핑
        sig_map = {s.get("name", ""): s.get("description", "") for s in self.get_signatures()}

        ttps = []
        # (technique_id, sig_name) 쌍 기준으로 중복 제거
        # technique_id 단독 중복 제거는 올바른 매핑을 버리는 버그 원인
        seen: set = set()

        # 방식 1: top-level ttps 배열 {"signature":..., "ttps":[...]}
        for entry in self.raw.get("ttps", []):
            sig_name = entry.get("signature", "")
            desc = sig_map.get(sig_name, "")
            for tid in entry.get("ttps", []):
                if not self._is_valid_ttp_pair(tid, sig_name):
                    continue
                key = (tid, sig_name)
                if key not in seen:
                    seen.add(key)
                    ttps.append({
                        "technique_id": tid,
                        "signature":    sig_name,
                        "description":  desc,
                    })

        # 방식 2: signatures 내부 ttp 키 (이전 CAPEv2 포맷 호환)
        for sig in self.get_signatures():
            sig_name = sig.get("name", "")
            for tid in sig.get("ttp", []):
                if not self._is_valid_ttp_pair(tid, sig_name):
                    continue
                key = (tid, sig_name)
                if key not in seen:
                    seen.add(key)
                    ttps.append({
                        "technique_id": tid,
                        "signature":    sig_name,
                        "description":  sig.get("description", ""),
                    })

        return ttps

    # ── Network ───────────────────────────────────────────────
    def get_network(self) -> dict:
        return self.raw.get("network", {})

    def get_suricata(self) -> list:
        return self.raw.get("suricata", {}).get("alerts", [])

    def get_dns(self) -> list:
        return self.get_network().get("dns", [])

    def get_http(self) -> list:
        return self.get_network().get("http", [])

    def get_tls(self) -> list:
        return self.get_network().get("tls", [])

    def get_ssh(self) -> list:
        return self.get_network().get("ssh", [])

    def get_network_files(self) -> list:
        return self.get_network().get("files", [])

    def get_network_iocs(self) -> dict:
        domains = list(dict.fromkeys(
            d.get("request", "") for d in self.get_dns() if d.get("request")
        ))
        urls = list(dict.fromkeys(
            h.get("uri", "") for h in self.get_http() if h.get("uri")
        ))
        ips, seen = [], set()
        for dns in self.get_dns():
            for ans in dns.get("answers", []):
                ip = ans.get("data", "")
                if ip and ip not in seen:
                    seen.add(ip); ips.append(ip)
        return {"domains": domains[:50], "ips": ips[:50], "urls": urls[:50]}

    # ── Behavior ──────────────────────────────────────────────
    def get_processes(self) -> list:
        behavior = self.raw.get("behavior", {})
        return behavior.get("processes", [])

    def get_api_calls(self, max_per_process: int = 1000) -> list:
        """Returns flat list: {pid, process_name, api, category, args}"""
        result = []
        for proc in self.get_processes():
            pid  = proc.get("pid", "")
            name = proc.get("process_name", proc.get("module_path", ""))
            count = 0
            for call in proc.get("calls", []):
                if count >= max_per_process:
                    break
                result.append({
                    "pid":     pid,
                    "process": name,
                    "api":     call.get("api", ""),
                    "category":call.get("category", ""),
                    "args":    str(call.get("arguments", "")),
                })
                count += 1
        return result

    @staticmethod
    def _extract_arg(args, *names) -> str:
        if isinstance(args, list):
            for arg in args:
                if isinstance(arg, dict) and arg.get("name", "").lower() in names:
                    return str(arg.get("pretty_value") or arg.get("value", ""))
        elif isinstance(args, dict):
            for name in names:
                if name in args:
                    return str(args[name])
        return ""

    def get_host_iocs(self) -> dict:
        reg, files, mutexes = [], [], []
        sr, sf, sm = set(), set(), set()
        for proc in self.get_processes():
            for call in proc.get("calls", []):
                api  = call.get("api", "").lower()
                args = call.get("arguments", [])
                if any(k in api for k in ("regsetvalue", "regcreatekey", "regopenkeyex")):
                    v = self._extract_arg(args, "regkey", "key", "fullname")
                    if v and v not in sr: sr.add(v); reg.append(v)
                if any(k in api for k in ("createfile", "writefile", "movefile", "copyfile")):
                    v = self._extract_arg(args, "filename", "filepath", "newfilepath")
                    if v and v not in sf: sf.add(v); files.append(v)
                if any(k in api for k in ("createmutex", "openmutex")):
                    v = self._extract_arg(args, "mutexname", "name")
                    if v and v not in sm: sm.add(v); mutexes.append(v)
        return {"registry": reg[:30], "files": files[:30], "mutexes": mutexes[:30]}

    # ── CAPE ──────────────────────────────────────────────────
    def get_cape_payloads(self) -> list:
        return self.raw.get("CAPE", {}).get("payloads", [])

    def get_cape_configs(self) -> list:
        configs = []
        for payload in self.get_cape_payloads():
            cfg = payload.get("cape_config", None)
            if cfg:
                configs.append({
                    "sha256": payload.get("sha256", ""),
                    "family": payload.get("cape_type", ""),
                    "config": cfg,
                })
        return configs

    # ── 전체 텍스트 (AI 분석용) ───────────────────────────────
    def get_summary_for_ai(self) -> dict:
        return {
            "info":       self.get_info(),
            "verdict":    self.get_verdict(),
            "hashes":     self.get_hashes(),
            "signatures": [
                {"name": s.get("name"), "severity": s.get("severity"),
                 "description": s.get("description"), "ttp": s.get("ttp", [])}
                for s in self.get_signatures()
            ],
            "network": {
                "dns":      [d.get("request") for d in self.get_dns()],
                "http":     [h.get("uri") for h in self.get_http()],
                "suricata": [a.get("alert", {}).get("signature") for a in self.get_suricata()],
            },
            "cape_configs": self.get_cape_configs(),
        }
