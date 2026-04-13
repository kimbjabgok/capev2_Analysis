"""CAPEv2 분석 결과 → HTML 리포트 생성 (5-section layout)"""
import html
from datetime import datetime

TECHNIQUE_TACTICS = {
    "T1059": "Execution",        "T1055": "Defense Evasion",
    "T1547": "Persistence",      "T1053": "Persistence",
    "T1071": "Command & Control","T1105": "Command & Control",
    "T1218": "Defense Evasion",  "T1027": "Defense Evasion",
    "T1082": "Discovery",        "T1083": "Discovery",
    "T1057": "Discovery",        "T1012": "Discovery",
    "T1016": "Discovery",        "T1033": "Discovery",
    "T1543": "Persistence",      "T1546": "Persistence",
    "T1555": "Credential Access","T1539": "Credential Access",
    "T1552": "Credential Access","T1041": "Exfiltration",
    "T1090": "Command & Control","T1095": "Command & Control",
    "T1571": "Command & Control","T1573": "Command & Control",
    "T1008": "Command & Control","T1219": "Command & Control",
    "T1102": "Command & Control","T1056": "Collection",
    "T1113": "Collection",       "T1115": "Collection",
}

SEV_COLOR = {
    "critical": "#e05252", "high": "#e07050",
    "medium":   "#e0c050", "low":  "#8888cc", "info": "#888888",
}
VERDICT_COLOR = {
    "MALICIOUS":  "#e05252",
    "SUSPICIOUS": "#e07050",
    "CLEAN":      "#4caf50",
}


def _e(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _kv_rows(pairs) -> str:
    return "".join(
        f"<tr><td class='kv-key'>{_e(k)}</td><td class='mono'>{_e(v)}</td></tr>"
        for k, v in pairs
    )


def generate(parser, all_sigs: list, ai_text: str = "") -> str:
    verdict  = parser.get_verdict()
    hashes   = parser.get_hashes()
    info     = parser.get_info()
    fi       = parser.get_file_info()
    score    = verdict["score"]
    families = verdict["families"]
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")

    if   score >= 7: label = "MALICIOUS"
    elif score >= 4: label = "SUSPICIOUS"
    else:            label = "CLEAN"

    vcolor = VERDICT_COLOR[label]

    # ── Page 1: Executive Summary ─────────────────────────────
    family_html = (
        " ".join(f"<span class='badge family'>{_e(f)}</span>" for f in families)
        if families else "—"
    )

    page1 = f"""
    <section class="page">
      <div class="cover-header">
        <h1>MALWARE ANALYSIS REPORT</h1>
      </div>
      <div class="meta-row">
        <table class="kv-table"><tbody>
          <tr><td class='kv-key'>분석 일시</td><td>{_e(now)}</td></tr>
          <tr><td class='kv-key'>Report ID</td><td class='mono'>{_e(info.get('id','—'))}</td></tr>
        </tbody></table>
      </div>
      <div class="verdict-box" style="background:{vcolor}">
        {_e(label)}&nbsp;&nbsp;—&nbsp;&nbsp;Score: {_e(score)} / 10
      </div>
      <table class="kv-table"><tbody>
        <tr><td class='kv-key'>파일명</td><td class='mono'>{_e(fi.get('name','—'))}</td></tr>
        <tr><td class='kv-key'>SHA256</td><td class='mono'>{_e(hashes.get('sha256','—'))}</td></tr>
        <tr><td class='kv-key'>악성코드 패밀리</td><td>{family_html}</td></tr>
      </tbody></table>
    </section>"""

    # ── Page 2: File Information & IOC ────────────────────────
    hash_rows = _kv_rows([(k.upper(), v) for k, v in hashes.items() if v])

    pe_secs = parser.get_pe_sections()
    pe_sec_rows = "".join(
        f"<tr><td class='mono'>{_e(s.get('name',''))}</td>"
        f"<td class='mono'>{_e(s.get('virtual_address',''))}</td>"
        f"<td class='mono'>{_e(s.get('virtual_size',''))}</td>"
        f"<td class='mono'>{_e(s.get('size_of_data', s.get('size_of_raw_data','')))}</td>"
        f"<td>{_e(s.get('entropy',''))}</td></tr>"
        for s in pe_secs
    ) if pe_secs else "<tr><td colspan='5' class='empty'>없음</td></tr>"

    susp = parser.get_suspicious_imports()
    susp_rows = "".join(
        f"<tr><td class='mono'>{_e(i['dll'])}</td>"
        f"<td class='mono'>{_e(', '.join(i['functions']))}</td></tr>"
        for i in susp
    ) if susp else "<tr><td colspan='2' class='empty'>없음</td></tr>"

    net  = parser.get_network_iocs()
    net_rows = "".join(
        f"<tr><td class='badge-cell'><span class='badge ioc-type'>{t}</span></td>"
        f"<td class='mono'>{_e(v)}</td></tr>"
        for t, v in (
            [("Domain", d) for d in net["domains"][:20]] +
            [("IP",     ip) for ip in net["ips"][:20]] +
            [("URL",    u)  for u  in net["urls"][:20]]
        )
    ) or "<tr><td colspan='2' class='empty'>없음</td></tr>"

    host = parser.get_host_iocs()
    host_rows = "".join(
        f"<tr><td class='badge-cell'><span class='badge ioc-type'>{t}</span></td>"
        f"<td class='mono'>{_e(v)}</td></tr>"
        for t, v in (
            [("Registry", r) for r in host["registry"][:15]] +
            [("File",     f_) for f_ in host["files"][:15]] +
            [("Mutex",    m)  for m  in host["mutexes"][:15]]
        )
    ) or "<tr><td colspan='2' class='empty'>없음</td></tr>"

    page2 = f"""
    <section class="page">
      <div class="section-header">2. File Information &amp; IOC</div>

      <h3>File Hashes</h3>
      <table class="kv-table"><tbody>{hash_rows}</tbody></table>

      <h3>PE Sections</h3>
      <table class="data-table">
        <thead><tr><th>Name</th><th>Virt. Address</th><th>Virt. Size</th><th>Raw Size</th><th>Entropy</th></tr></thead>
        <tbody>{pe_sec_rows}</tbody>
      </table>

      <h3>Suspicious Imports</h3>
      <table class="data-table">
        <thead><tr><th>DLL</th><th>Functions</th></tr></thead>
        <tbody>{susp_rows}</tbody>
      </table>

      <h3>Network IOC</h3>
      <table class="data-table">
        <thead><tr><th>Type</th><th>Value</th></tr></thead>
        <tbody>{net_rows}</tbody>
      </table>

      <h3>Host IOC</h3>
      <table class="data-table">
        <thead><tr><th>Type</th><th>Value</th></tr></thead>
        <tbody>{host_rows}</tbody>
      </table>
    </section>"""

    # ── Page 3: Detection Signatures ─────────────────────────
    sig_rows = ""
    for sig in all_sigs:
        sev    = str(sig.get("severity", "info")).lower()
        sc     = SEV_COLOR.get(sev, "#888")
        is_cmr = sig.get("name", "").startswith("[CMR]")
        bold   = "font-weight:bold;" if is_cmr else ""
        sig_rows += (
            f"<tr class='{'cmr-row' if is_cmr else ''}'>"
            f"<td><span class='sev-badge' style='background:{sc}'>{sev.upper()}</span></td>"
            f"<td style='{bold}'>{_e(sig.get('name',''))}</td>"
            f"<td>{_e(sig.get('description',''))}</td></tr>"
        )

    page3 = f"""
    <section class="page">
      <div class="section-header">3. Detection Signatures</div>
      <table class="data-table">
        <thead><tr><th>Severity</th><th>Name</th><th>Description</th></tr></thead>
        <tbody>{sig_rows if sig_rows else "<tr><td colspan='3' class='empty'>없음</td></tr>"}</tbody>
      </table>
    </section>"""

    # ── Page 4: MITRE ATT&CK ─────────────────────────────────
    ttps = parser.get_ttps()
    ttp_rows = "".join(
        f"<tr>"
        f"<td class='mono'>{_e(t['technique_id'])}</td>"
        f"<td>{_e(TECHNIQUE_TACTICS.get(t['technique_id'].split('.')[0], '—'))}</td>"
        f"<td>{_e(t.get('description',''))}</td></tr>"
        for t in ttps
    ) if ttps else "<tr><td colspan='3' class='empty'>없음</td></tr>"

    page4 = f"""
    <section class="page">
      <div class="section-header">4. MITRE ATT&amp;CK</div>
      <table class="data-table">
        <thead><tr><th>Technique ID</th><th>Tactic</th><th>Description</th></tr></thead>
        <tbody>{ttp_rows}</tbody>
      </table>
    </section>"""

    # ── Page 5: AI Analysis ───────────────────────────────────
    if ai_text:
        ai_html = ""
        for line in ai_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                ai_html += "<br>"
            elif stripped.startswith("## "):
                ai_html += f"<h3>{_e(stripped[3:])}</h3>"
            else:
                ai_html += f"<p>{_e(stripped)}</p>"
        ai_content = f"<div class='ai-box'>{ai_html}</div>"
    else:
        ai_content = "<p class='empty'>AI 분석 결과 없음 — AI 분석 탭에서 분석을 실행한 후 내보내기 하세요.</p>"

    page5 = f"""
    <section class="page">
      <div class="section-header">5. AI Analysis</div>
      {ai_content}
    </section>"""

    # ── CSS + 조합 ─────────────────────────────────────────────
    css = """
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:0}
    .page{background:#16213e;border-radius:8px;padding:24px;margin:20px auto;max-width:960px}
    .cover-header{background:#0a0a1a;border-radius:6px;padding:32px;text-align:center;margin-bottom:16px}
    h1{font-size:1.6rem;color:#7ec8e3;letter-spacing:.1em}
    h3{font-size:.95rem;color:#7ec8e3;margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid #0f3460}
    .section-header{background:#0f3460;color:#7ec8e3;font-size:1.05rem;font-weight:bold;
                    padding:10px 14px;border-radius:4px;margin-bottom:16px}
    .verdict-box{border-radius:6px;padding:18px;text-align:center;font-size:1.3rem;
                 font-weight:bold;color:#fff;margin:14px 0}
    .meta-row{margin-bottom:12px}
    .kv-table{width:100%;border-collapse:collapse;font-size:.88rem;margin-bottom:4px}
    .kv-key{color:#6c7086;font-weight:bold;width:160px;padding:5px 10px;
            background:#0f3460;white-space:nowrap}
    .kv-table td{padding:5px 10px;border-bottom:1px solid #0f3460}
    .data-table{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:4px}
    .data-table th{background:#0f3460;color:#7ec8e3;text-align:left;padding:6px 10px}
    .data-table td{padding:5px 10px;border-bottom:1px solid #0f3460;vertical-align:top}
    .data-table tr:hover td{background:#0f346044}
    .mono{font-family:Consolas,monospace;font-size:.82rem;word-break:break-all}
    .sev-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.78rem;
               font-weight:bold;color:#1a1a2e}
    .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.8rem;font-weight:bold}
    .family{background:#e0a050;color:#1a1a2e}
    .ioc-type{background:#0f3460;color:#7ec8e3}
    .badge-cell{white-space:nowrap;width:90px}
    .cmr-row td{background:#0f346033}
    .ai-box{line-height:1.7;font-size:.9rem}
    .ai-box h3{color:#7ec8e3;margin:14px 0 6px}
    .ai-box p{margin:4px 0;color:#cdd6f4}
    .empty{color:#6c7086;font-style:italic;padding:8px 10px}
    @media print{
      body{background:#fff;color:#000}
      .page{background:#fff;border:1px solid #ccc;page-break-after:always;margin:0;border-radius:0}
      .section-header{background:#0f3460}
      .cover-header{background:#1a1a2e}
    }
    """

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CAPEv2 Report — {_e(hashes.get('sha256','')[:16])}...</title>
<style>{css}</style>
</head>
<body>
{page1}
{page2}
{page3}
{page4}
{page5}
</body>
</html>"""
