"""리포트 내보내기 — HTML (Bootstrap Darkly) + PDF (reportlab)"""

# ══════════════════════════════════════════════════════════════
# html_export
# ══════════════════════════════════════════════════════════════
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
    "T1486": "Impact",           "T1490": "Impact",
    "T1497": "Defense Evasion",  "T1518": "Discovery",
    "T1548": "Privilege Escalation", "T1562": "Defense Evasion",
    "T1564": "Defense Evasion",  "T1574": "Defense Evasion",
    "T1620": "Defense Evasion",  "T1622": "Defense Evasion",
    "T1005": "Collection",
}

SEV_BADGE = {
    "critical": "danger",
    "high":     "warning",
    "medium":   "info",
    "low":      "success",
    "info":     "secondary",
}

SEV_LIST = {
    "critical": "list-group-item-danger",
    "high":     "list-group-item-warning",
    "medium":   "list-group-item-primary",
    "low":      "list-group-item-success",
    "info":     "list-group-item-secondary",
}

VERDICT_BADGE = {
    "MALICIOUS":  "danger",
    "SUSPICIOUS": "warning",
    "CLEAN":      "success",
}

VERDICT_KO = {
    "MALICIOUS":  "악성",
    "SUSPICIOUS": "의심",
    "CLEAN":      "정상",
}


def _e(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def generate_html(parser, all_sigs: list, ai_text: str = "") -> str:
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

    vbadge = VERDICT_BADGE[label]
    vko    = VERDICT_KO[label]

    sha256   = hashes.get("sha256", "")
    filename = _e(fi.get("name", info.get("id", "—")))

    navbar = f"""
<nav class="navbar navbar-dark bg-dark border-bottom border-secondary px-3 py-2">
  <div class="d-flex align-items-center gap-3">
    <span class="navbar-brand fw-bold mb-0">
      <i class="fas fa-bug text-danger me-2"></i>CAPE Report Analyzer
    </span>
    <span class="text-muted font-monospace small">{filename}</span>
  </div>
  <div class="d-flex align-items-center gap-2">
    <span class="badge bg-secondary">Score: {_e(score)}/10</span>
    <span class="badge bg-{vbadge} fs-6 px-3">{_e(label)} — {_e(vko)}</span>
    <span class="text-muted small">{_e(now)}</span>
  </div>
</nav>"""

    if families:
        fam_badges = " ".join(
            f'<span class="badge bg-danger fs-6 px-3 py-2">{_e(f)}</span>'
            for f in families
        )
        detection_card = f"""
<div class="card mb-3">
  <div class="card-header fw-bold"><i class="fas fa-shield-virus me-2 text-danger"></i>Detections</div>
  <div class="card-body text-center py-3">{fam_badges}</div>
</div>"""
    else:
        detection_card = ""

    tabs_nav = """
<ul class="nav nav-tabs" id="mainTab" role="tablist">
  <li class="nav-item">
    <a class="nav-link active" id="tab-overview" data-bs-toggle="tab" href="#pane-overview" role="tab">
      <i class="fas fa-info-circle me-1"></i>Overview
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-sigs" data-bs-toggle="tab" href="#pane-sigs" role="tab">
      <i class="fas fa-exclamation-triangle me-1"></i>Signatures
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-network" data-bs-toggle="tab" href="#pane-network" role="tab">
      <i class="fas fa-network-wired me-1"></i>Network
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-attack" data-bs-toggle="tab" href="#pane-attack" role="tab">
      <i class="fas fa-crosshairs me-1"></i>ATT&amp;CK
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-ai" data-bs-toggle="tab" href="#pane-ai" role="tab">
      <i class="fas fa-robot me-1"></i>AI 분석
    </a>
  </li>
</ul>"""

    analysis_rows = "".join([
        f"<dt class='col-sm-3 text-muted'>분석 ID</dt><dd class='col-sm-9 font-monospace'>{_e(info.get('id','—'))}</dd>",
        f"<dt class='col-sm-3 text-muted'>분석 일시</dt><dd class='col-sm-9'>{_e(now)}</dd>",
        f"<dt class='col-sm-3 text-muted'>분석 시간</dt><dd class='col-sm-9'>{_e(info.get('duration','—'))} 초</dd>",
        f"<dt class='col-sm-3 text-muted'>패키지</dt><dd class='col-sm-9'>{_e(info.get('package','—'))}</dd>",
    ])

    pe = parser.get_pe()
    vt_link  = f'<a href="https://www.virustotal.com/gui/file/{_e(sha256)}/" target="_blank" class="badge bg-danger text-decoration-none ms-1">[VT]</a>'
    baz_link = f'<a href="https://bazaar.abuse.ch/sample/{_e(sha256)}/" target="_blank" class="badge bg-warning text-dark text-decoration-none ms-1">[Bazaar]</a>'

    hash_rows_html = ""
    for k, v in hashes.items():
        if not v:
            continue
        extra = (vt_link + baz_link) if k == "sha256" else ""
        hash_rows_html += f"""
<tr>
  <th class="text-muted" style="width:110px">{k.upper()}</th>
  <td class="font-monospace small">
    <span id="hash-{k}">{_e(v)}</span>{extra}
    <button class="btn btn-sm btn-outline-secondary py-0 px-1 ms-2"
            onclick="copyText('{_e(v)}')" title="복사">
      <i class="fas fa-copy"></i>
    </button>
  </td>
</tr>"""

    file_detail_rows = "".join([
        f"<tr><th class='text-muted' style='width:130px'>파일명</th><td class='font-monospace'><b>{_e(fi.get('name','—'))}</b></td></tr>",
        f"<tr><th class='text-muted'>파일 타입</th><td>{_e(fi.get('type','—'))}</td></tr>",
        f"<tr><th class='text-muted'>파일 크기</th><td>{_e(fi.get('size','—'))} bytes</td></tr>",
    ])
    if pe.get("timestamp"):
        file_detail_rows += f"<tr><th class='text-muted'>PE Timestamp</th><td class='font-monospace'>{_e(pe.get('timestamp',''))}</td></tr>"
    if pe.get("imagebase"):
        file_detail_rows += f"<tr><th class='text-muted'>ImageBase</th><td class='font-monospace'>{_e(pe.get('imagebase',''))}</td></tr>"

    yara_m = parser.get_yara_matches()
    if yara_m:
        yara_items = "".join(
            f'<li class="list-group-item list-group-item-warning"><i class="fas fa-search me-2"></i>{_e(y.get("name", y) if isinstance(y, dict) else y)}</li>'
            for y in yara_m
        )
        yara_card = f"""
<div class="card mb-3">
  <div class="card-header"><i class="fas fa-file-code me-2 text-warning"></i>YARA Matches</div>
  <ul class="list-group list-group-flush">{yara_items}</ul>
</div>"""
    else:
        yara_card = ""

    pe_secs = parser.get_pe_sections()
    if pe_secs:
        pe_sec_rows = "".join(
            f"<tr>"
            f"<td class='font-monospace'>{_e(s.get('name',''))}</td>"
            f"<td class='font-monospace'>{_e(s.get('virtual_address',''))}</td>"
            f"<td class='font-monospace'>{_e(s.get('virtual_size',''))}</td>"
            f"<td class='font-monospace'>{_e(s.get('size_of_data', s.get('size_of_raw_data','')))}</td>"
            f"<td class='{'text-danger fw-bold' if float(s.get('entropy',0) or 0) > 7 else ''}'>{_e(s.get('entropy',''))}</td>"
            f"</tr>"
            for s in pe_secs
        )
        pe_section_card = f"""
<div class="card mb-3">
  <div class="card-header" role="button" data-bs-toggle="collapse" data-bs-target="#collapse-pe-sec">
    <i class="fas fa-layer-group me-2 text-info"></i>PE Sections
    <i class="fas fa-chevron-down float-end"></i>
  </div>
  <div class="collapse" id="collapse-pe-sec">
    <div class="table-responsive">
      <table class="table table-striped table-bordered table-dark table-sm mb-0">
        <thead><tr><th>Name</th><th>Virt. Address</th><th>Virt. Size</th><th>Raw Size</th><th>Entropy</th></tr></thead>
        <tbody>{pe_sec_rows}</tbody>
      </table>
    </div>
  </div>
</div>"""
    else:
        pe_section_card = ""

    susp = parser.get_suspicious_imports()
    if susp:
        susp_rows = "".join(
            f"<tr>"
            f"<td class='font-monospace text-warning'>{_e(i['dll'])}</td>"
            f"<td><small class='font-monospace'>" +
            " ".join(
                f'<a href="https://docs.microsoft.com/en-us/search/?terms={_e(fn)}" '
                f'target="_blank" class="badge bg-secondary text-decoration-none me-1">{_e(fn)}</a>'
                for fn in i["functions"]
            ) +
            f"</small></td>"
            f"</tr>"
            for i in susp
        )
        imports_card = f"""
<div class="card mb-3">
  <div class="card-header" role="button" data-bs-toggle="collapse" data-bs-target="#collapse-imports">
    <i class="fas fa-plug me-2 text-warning"></i>Suspicious Imports
    <span class="badge bg-warning text-dark ms-2">{len(susp)}</span>
    <i class="fas fa-chevron-down float-end"></i>
  </div>
  <div class="collapse" id="collapse-imports">
    <div class="table-responsive">
      <table class="table table-striped table-bordered table-dark table-sm mb-0">
        <thead><tr><th>DLL</th><th>Functions <small class="text-muted">(클릭 → MS Docs)</small></th></tr></thead>
        <tbody>{susp_rows}</tbody>
      </table>
    </div>
  </div>
</div>"""
    else:
        imports_card = ""

    pane_overview = f"""
<div class="row mb-3">
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-header"><i class="fas fa-file me-2 text-primary"></i>File Details</div>
      <table class="table table-dark table-sm mb-0"><tbody>{file_detail_rows}</tbody></table>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-header"><i class="fas fa-fingerprint me-2 text-primary"></i>File Hashes</div>
      <table class="table table-dark table-sm mb-0"><tbody>{hash_rows_html}</tbody></table>
    </div>
  </div>
</div>
<div class="card mb-3">
  <div class="card-header" role="button" data-bs-toggle="collapse" data-bs-target="#collapse-analysis">
    <i class="fas fa-flask me-2 text-secondary"></i>Analysis Summary
    <i class="fas fa-chevron-down float-end"></i>
  </div>
  <div class="collapse" id="collapse-analysis">
    <div class="card-body">
      <dl class="row mb-0">{analysis_rows}</dl>
    </div>
  </div>
</div>
{yara_card}
{pe_section_card}
{imports_card}"""

    sig_items = ""
    sig_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sig in all_sigs:
        sev = str(sig.get("severity", "info")).lower()
        sig_counts[sev] = sig_counts.get(sev, 0) + 1
        list_cls  = SEV_LIST.get(sev, "list-group-item-secondary")
        badge_cls = SEV_BADGE.get(sev, "secondary")
        name = _e(sig.get("name", ""))
        desc = _e(sig.get("description", ""))
        is_custom = sig.get("name", "").startswith("[YB]")
        custom_badge = '<span class="badge bg-primary ms-1">YB</span>' if is_custom else ""
        sig_items += f"""
<li class="list-group-item {list_cls} d-flex justify-content-between align-items-start">
  <div>
    <span class="fw-bold">{name}</span>{custom_badge}
    <div class="text-muted small mt-1">{desc}</div>
  </div>
  <span class="badge bg-{badge_cls} ms-2">{sev.upper()}</span>
</li>"""

    summary_badges = " ".join(
        '<span class="badge bg-{}">{}: {}</span>'.format(
            SEV_BADGE.get(s, "secondary"), s.upper(), c
        )
        for s, c in sig_counts.items() if c > 0
    )

    pane_sigs = f"""
<div class="d-flex gap-2 mb-3 flex-wrap">{summary_badges}</div>
<ul class="list-group">
{sig_items if sig_items else '<li class="list-group-item">탐지된 시그니처 없음</li>'}
</ul>"""

    net  = parser.get_network_iocs()
    host = parser.get_host_iocs()

    def _ioc_table(items, label):
        if not items:
            return '<p class="text-muted fst-italic">없음</p>'
        rows = "".join(
            f'<tr><td class="font-monospace small">{_e(v)}</td></tr>'
            for v in items
        )
        return f"""
<table class="table table-dark table-striped table-bordered table-sm">
  <thead><tr><th>{label}</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

    dns_html   = _ioc_table(net["domains"],    "Domain")
    ip_html    = _ioc_table(net["ips"],        "IP Address")
    url_html   = _ioc_table(net["urls"],       "URL")
    reg_html   = _ioc_table(host["registry"],  "Registry Key")
    file_html  = _ioc_table(host["files"],     "File Path")
    mutex_html = _ioc_table(host["mutexes"],   "Mutex")

    pane_network = f"""
<ul class="nav nav-pills mb-3" id="netTab" role="tablist">
  <li class="nav-item"><a class="nav-link active" data-bs-toggle="pill" href="#net-dns">
    <i class="fas fa-globe me-1"></i>DNS <span class="badge bg-secondary">{len(net["domains"])}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-ip">
    <i class="fas fa-server me-1"></i>IP <span class="badge bg-secondary">{len(net["ips"])}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-url">
    <i class="fas fa-link me-1"></i>HTTP <span class="badge bg-secondary">{len(net["urls"])}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-reg">
    <i class="fas fa-key me-1"></i>Registry <span class="badge bg-secondary">{len(host["registry"])}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-file">
    <i class="fas fa-file me-1"></i>Files <span class="badge bg-secondary">{len(host["files"])}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-mutex">
    <i class="fas fa-lock me-1"></i>Mutexes <span class="badge bg-secondary">{len(host["mutexes"])}</span></a></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="net-dns">{dns_html}</div>
  <div class="tab-pane fade" id="net-ip">{ip_html}</div>
  <div class="tab-pane fade" id="net-url">{url_html}</div>
  <div class="tab-pane fade" id="net-reg">{reg_html}</div>
  <div class="tab-pane fade" id="net-file">{file_html}</div>
  <div class="tab-pane fade" id="net-mutex">{mutex_html}</div>
</div>"""

    ttps = parser.get_ttps()
    if ttps:
        ttp_rows = ""
        seen = set()
        for t in ttps:
            tid = t["technique_id"]
            if tid in seen:
                continue
            seen.add(tid)
            tid_base = tid.split(".")[0]
            tactic = _e(TECHNIQUE_TACTICS.get(tid_base, "—"))
            desc   = _e(t.get("description", ""))
            sig    = _e(t.get("signature", ""))
            mitre_url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            ttp_rows += f"""
<tr>
  <td><a href="{mitre_url}" target="_blank" class="badge bg-primary text-decoration-none font-monospace">{_e(tid)}</a></td>
  <td><span class="badge bg-secondary">{tactic}</span></td>
  <td class="small">{desc}</td>
  <td class="small text-muted">{sig}</td>
</tr>"""
        ttp_table = f"""
<div class="table-responsive">
  <table class="table table-dark table-striped table-bordered">
    <thead><tr><th>Technique</th><th>Tactic</th><th>Description</th><th>Signature</th></tr></thead>
    <tbody>{ttp_rows}</tbody>
  </table>
</div>"""
    else:
        ttp_table = '<p class="text-muted fst-italic">ATT&CK TTP 없음</p>'

    pane_attack = ttp_table

    if ai_text:
        ai_html = ""
        for line in ai_text.split("\n"):
            s = line.strip()
            if not s:
                ai_html += "<div class='mb-2'></div>"
            elif s.startswith("## "):
                ai_html += f"<h5 class='text-info mt-3 mb-2'>{_e(s[3:])}</h5>"
            elif s.startswith("# "):
                ai_html += f"<h4 class='text-primary mt-3 mb-2'>{_e(s[2:])}</h4>"
            elif s.startswith("- ") or s.startswith("• "):
                ai_html += f"<div class='ms-3 mb-1'>• {_e(s[2:])}</div>"
            else:
                ai_html += f"<p class='mb-1'>{_e(s)}</p>"
        pane_ai = f'<div class="card card-body bg-dark">{ai_html}</div>'
    else:
        pane_ai = '<p class="text-muted fst-italic">AI 분석 결과 없음 — AI 분석 탭에서 실행 후 내보내기 하세요.</p>'

    return f"""<!DOCTYPE html>
<html lang="ko" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CAPE Report — {_e(sha256[:16])}...</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootswatch@5.3.2/dist/darkly/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>
    body {{ font-size: .9rem; }}
    .font-monospace {{ font-size: .82rem; word-break: break-all; }}
    .card-header[data-bs-toggle="collapse"] {{ cursor: pointer; }}
    .card-header[data-bs-toggle="collapse"]:hover {{ background: rgba(255,255,255,.05); }}
    .navbar {{ position: sticky; top: 0; z-index: 1000; }}
    .table th {{ white-space: nowrap; }}
    pre {{ background: #222; padding: 12px; border-radius: 6px; font-size: .8rem; }}
  </style>
</head>
<body>
{navbar}
<div class="container-fluid py-3">
  {detection_card}
  {tabs_nav}
  <div class="tab-content mt-3" id="mainTabContent">
    <div class="tab-pane fade show active" id="pane-overview" role="tabpanel">
      {pane_overview}
    </div>
    <div class="tab-pane fade" id="pane-sigs" role="tabpanel">
      {pane_sigs}
    </div>
    <div class="tab-pane fade" id="pane-network" role="tabpanel">
      {pane_network}
    </div>
    <div class="tab-pane fade" id="pane-attack" role="tabpanel">
      {pane_attack}
    </div>
    <div class="tab-pane fade" id="pane-ai" role="tabpanel">
      {pane_ai}
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
function copyText(text) {{
  navigator.clipboard.writeText(text).then(() => {{
    const el = document.activeElement;
    const orig = el.innerHTML;
    el.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => {{ el.innerHTML = orig; }}, 1200);
  }});
}}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════
# pdf_export (reportlab)
# ══════════════════════════════════════════════════════════════
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True

    PAGE_W, PAGE_H = A4
    MARGIN    = 2 * cm
    CONTENT_W = PAGE_W - 2 * MARGIN

    C_BG      = colors.HexColor("#1a1a2e")
    C_SECTION = colors.HexColor("#0f3460")
    C_ACCENT  = colors.HexColor("#4a9fd4")
    C_WHITE   = colors.white
    C_LIGHT   = colors.HexColor("#f0f4f8")
    C_ROW_ALT = colors.HexColor("#f8f8f8")
    C_GRID    = colors.HexColor("#dddddd")
    C_BODY    = colors.HexColor("#222222")
    C_DIM     = colors.HexColor("#888888")
    C_CRIT    = colors.HexColor("#e05252")
    C_HIGH    = colors.HexColor("#e07050")
    C_MED     = colors.HexColor("#e0c050")
    C_LOW     = colors.HexColor("#8888cc")
    C_GREEN   = colors.HexColor("#4caf50")

    SEV_COLOR = {
        "critical": C_CRIT, "high": C_HIGH,
        "medium":   C_MED,  "low":  C_LOW, "info": C_DIM,
    }
    VERDICT_COLOR = {"MALICIOUS": C_CRIT, "SUSPICIOUS": C_HIGH, "CLEAN": C_GREEN}

    TABLE_STYLE_BASE = [
        ("BACKGROUND",    (0, 0), (-1,  0), C_SECTION),
        ("TEXTCOLOR",     (0, 0), (-1,  0), C_WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_ROW_ALT, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_GRID),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]

except ImportError:
    REPORTLAB_AVAILABLE = False

_PDF_TECHNIQUE_TACTICS = {
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


def _register_fonts():
    import os, platform
    if platform.system() == "Windows":
        d = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
        try:
            pdfmetrics.registerFont(TTFont("Malgun",      str(d / "malgun.ttf")))
            pdfmetrics.registerFont(TTFont("Malgun-Bold", str(d / "malgunbd.ttf")))
            return "Malgun", "Malgun-Bold"
        except Exception:
            pass
    return "Helvetica", "Helvetica-Bold"


def _styles(f, fb):
    def ps(name, **kw):
        return ParagraphStyle(name, fontName=f, fontSize=9,
                              textColor=C_BODY, leading=kw.pop('leading', 13), **kw)
    return {
        "title":   ParagraphStyle("title",   fontName=fb, fontSize=22,
                                  textColor=C_WHITE, leading=30, alignment=TA_CENTER),
        "verdict": ParagraphStyle("verdict", fontName=fb, fontSize=18,
                                  textColor=C_WHITE, leading=26, alignment=TA_CENTER),
        "section": ParagraphStyle("section", fontName=fb, fontSize=11,
                                  textColor=C_WHITE, leading=16),
        "sub":     ParagraphStyle("sub",     fontName=fb, fontSize=9,
                                  textColor=C_SECTION, leading=13),
        "body":    ps("body"),
        "mono":    ParagraphStyle("mono",    fontName="Courier", fontSize=8,
                                  textColor=C_BODY, leading=12),
        "label":   ParagraphStyle("label",   fontName=fb, fontSize=9,
                                  textColor=C_DIM, leading=12),
        "ai":      ps("ai", leading=15),
    }


def _sec_hdr(text, S) -> "Table":
    t = Table([[Paragraph(text, S["section"])]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_SECTION),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
    ]))
    return t


def _kv(rows, S, cw=None) -> "Table":
    cw = cw or [4*cm, CONTENT_W - 4*cm]
    data = [[Paragraph(str(k), S["label"]),
             Paragraph(str(v), S["mono"])] for k, v in rows]
    t = Table(data, colWidths=cw)
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",           (0,0), (-1,-1), 0.3, C_GRID),
        ("TOPPADDING",     (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
        ("LEFTPADDING",    (0,0), (-1,-1), 8),
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
    ]))
    return t


def _sub(text, S):
    return Paragraph(text, S["sub"])


def generate_pdf(parser, all_sigs: list, ai_text: str, output_path: str) -> None:
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab가 설치되지 않았습니다: pip install reportlab")

    f, fb = _register_fonts()
    S = _styles(f, fb)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
    )
    story = []
    sp = lambda n=0.3: Spacer(1, n * cm)

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

    cover = Table([[Paragraph("MALWARE ANALYSIS REPORT", S["title"])]],
                  colWidths=[CONTENT_W])
    cover.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 30),
        ("BOTTOMPADDING", (0,0), (-1,-1), 30),
    ]))
    story += [cover, sp(0.4)]

    story.append(_kv([
        ("분석 일시", now),
        ("Report ID", info.get("id", "—")),
    ], S))
    story.append(sp(0.5))

    vbox = Table([[Paragraph(f"{label}  —  Score: {score} / 10", S["verdict"])]],
                 colWidths=[CONTENT_W])
    vbox.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), VERDICT_COLOR[label]),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
    ]))
    story += [vbox, sp(0.5)]

    story.append(_kv([
        ("파일명",           fi.get("name", "—")),
        ("SHA256",          hashes.get("sha256", "—")),
        ("악성코드 패밀리",   ", ".join(families) if families else "—"),
    ], S))
    story.append(PageBreak())

    story += [_sec_hdr("2. File Information & IOC", S), sp()]

    story.append(_sub("File Hashes", S))
    story.append(sp(0.15))
    story.append(_kv([(k.upper(), v) for k, v in hashes.items() if v], S))
    story.append(sp(0.4))

    pe_secs = parser.get_pe_sections()
    if pe_secs:
        story.append(_sub("PE Sections", S))
        story.append(sp(0.15))
        cw = [3*cm, 3*cm, 3*cm, 2.5*cm, CONTENT_W - 11.5*cm]
        hdr = [Paragraph(h, S["label"])
               for h in ["Name", "Virt. Address", "Virt. Size", "Raw Size", "Entropy"]]
        rows = [hdr] + [[
            Paragraph(s.get("name", ""), S["mono"]),
            Paragraph(str(s.get("virtual_address", "")), S["mono"]),
            Paragraph(str(s.get("virtual_size", "")), S["mono"]),
            Paragraph(str(s.get("size_of_data", s.get("size_of_raw_data", ""))), S["mono"]),
            Paragraph(str(s.get("entropy", "")), S["mono"]),
        ] for s in pe_secs]
        t = Table(rows, colWidths=cw)
        t.setStyle(TableStyle(TABLE_STYLE_BASE))
        story += [t, sp(0.4)]

    susp = parser.get_suspicious_imports()
    if susp:
        story.append(_sub("Suspicious Imports", S))
        story.append(sp(0.15))
        story.append(_kv(
            [(imp["dll"], ", ".join(imp["functions"])) for imp in susp], S
        ))
        story.append(sp(0.4))

    net = parser.get_network_iocs()
    story.append(_sub("Network IOC", S))
    story.append(sp(0.15))
    net_rows = (
        [("Domain", d) for d in net["domains"][:20]] +
        [("IP",     ip) for ip in net["ips"][:20]] +
        [("URL",    u)  for u  in net["urls"][:20]]
    )
    story.append(_kv(net_rows, S) if net_rows else Paragraph("없음", S["body"]))
    story.append(sp(0.4))

    host = parser.get_host_iocs()
    story.append(_sub("Host IOC", S))
    story.append(sp(0.15))
    host_rows = (
        [("Registry", r) for r in host["registry"][:15]] +
        [("File",     f_) for f_ in host["files"][:15]] +
        [("Mutex",    m)  for m  in host["mutexes"][:15]]
    )
    story.append(_kv(host_rows, S) if host_rows else Paragraph("없음", S["body"]))
    story.append(PageBreak())

    story += [_sec_hdr("3. Detection Signatures", S), sp()]

    if all_sigs:
        cw3  = [2.2*cm, 5.5*cm, CONTENT_W - 7.7*cm]
        hdr3 = [Paragraph(h, S["label"]) for h in ["Severity", "Name", "Description"]]
        rows3 = [hdr3]
        for sig in all_sigs:
            sev    = str(sig.get("severity", "info")).lower()
            sc     = SEV_COLOR.get(sev, C_DIM)
            is_cmr = sig.get("name", "").startswith("[CMR]")
            fn     = fb if is_cmr else f
            rows3.append([
                Paragraph(sev.upper(), ParagraphStyle("sv", fontName=fn,
                           fontSize=8, textColor=sc, leading=12)),
                Paragraph(sig.get("name", ""), ParagraphStyle("nm", fontName=fn,
                           fontSize=8, textColor=C_BODY, leading=12)),
                Paragraph(sig.get("description", ""), S["body"]),
            ])
        t3 = Table(rows3, colWidths=cw3)
        t3.setStyle(TableStyle(TABLE_STYLE_BASE))
        story.append(t3)
    else:
        story.append(Paragraph("탐지된 시그니처 없음", S["body"]))

    story.append(PageBreak())

    story += [_sec_hdr("4. MITRE ATT&CK", S), sp()]

    ttps = parser.get_ttps()
    if ttps:
        cw4  = [2.8*cm, 4.2*cm, CONTENT_W - 7*cm]
        hdr4 = [Paragraph(h, S["label"])
                for h in ["Technique ID", "Tactic", "Description"]]
        rows4 = [hdr4] + [[
            Paragraph(t["technique_id"], S["mono"]),
            Paragraph(_PDF_TECHNIQUE_TACTICS.get(t["technique_id"].split(".")[0], "—"), S["body"]),
            Paragraph(t.get("description", ""), S["body"]),
        ] for t in ttps]
        t4 = Table(rows4, colWidths=cw4)
        t4.setStyle(TableStyle(TABLE_STYLE_BASE))
        story.append(t4)
    else:
        story.append(Paragraph("탐지된 ATT&CK TTP 없음", S["body"]))

    story.append(PageBreak())

    story += [_sec_hdr("5. AI Analysis", S), sp()]

    if ai_text:
        for line in ai_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                story.append(sp(0.1))
            elif stripped.startswith("## "):
                story += [sp(0.2),
                          Paragraph(stripped[3:], ParagraphStyle(
                              "aih", fontName=fb, fontSize=10,
                              textColor=C_SECTION, leading=14)),
                          sp(0.1)]
            else:
                story.append(Paragraph(stripped, S["ai"]))
    else:
        story.append(Paragraph(
            "AI 분석 결과 없음 — AI 분석 탭에서 분석을 실행한 후 내보내기 하세요.",
            S["body"]))

    doc.build(story)
