"""CAPEv2 report.json parser"""
import json
from pathlib import Path


def load_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


class ReportParser:
    def __init__(self, data: dict):
        self.raw = data

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
        return self.get_pe().get("imports", [])

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
        return sigs

    # ── ATT&CK ────────────────────────────────────────────────
    def get_ttps(self) -> list:
        # signatures 이름 → description 매핑
        sig_map = {s.get("name", ""): s.get("description", "") for s in self.get_signatures()}

        ttps = []
        seen = set()

        # 방식 1: top-level ttps 배열 {"signature":..., "ttps":[...]}
        for entry in self.raw.get("ttps", []):
            sig_name = entry.get("signature", "")
            desc = sig_map.get(sig_name, "")
            for tid in entry.get("ttps", []):
                if tid not in seen:
                    seen.add(tid)
                    ttps.append({
                        "technique_id": tid,
                        "signature":    sig_name,
                        "description":  desc,
                    })

        # 방식 2: signatures 내부 ttp 키 (이전 CAPEv2 포맷 호환)
        for sig in self.get_signatures():
            sig_name = sig.get("name", "")
            for tid in sig.get("ttp", []):
                if tid not in seen:
                    seen.add(tid)
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
