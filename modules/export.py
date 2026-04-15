"""리포트 내보내기 — HTML (Bootstrap Darkly)"""

# ══════════════════════════════════════════════════════════════
# html_export
# ══════════════════════════════════════════════════════════════
import html
import json
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
    <a class="nav-link" id="tab-attack" data-bs-toggle="tab" href="#pane-attack" role="tab">
      <i class="fas fa-crosshairs me-1"></i>ATT&amp;CK
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-network" data-bs-toggle="tab" href="#pane-network" role="tab">
      <i class="fas fa-network-wired me-1"></i>Network
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-behavior" data-bs-toggle="tab" href="#pane-behavior" role="tab">
      <i class="fas fa-microchip me-1"></i>Behavior
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" id="tab-cape" data-bs-toggle="tab" href="#pane-cape" role="tab">
      <i class="fas fa-box-open me-1"></i>CAPE
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

    _dns    = parser.get_dns()
    _http   = parser.get_http()
    _tls    = parser.get_tls()
    _ssh    = parser.get_ssh()
    _nfiles = parser.get_network_files()
    _hosts  = parser.get_hosts()
    _tcp    = parser.get_tcp()
    _udp    = parser.get_udp()
    _dead   = parser.get_dead_hosts()

    def _ntable(cols, rows):
        if not rows:
            return '<p class="text-muted fst-italic small">데이터 없음</p>'
        th = "".join(f"<th>{_e(c)}</th>" for c in cols)
        tb = "".join(
            "<tr>" + "".join(
                f'<td class="font-monospace small" style="word-break:break-all">{_e(v)}</td>'
                for v in r
            ) + "</tr>"
            for r in rows
        )
        return (f'<div class="table-responsive"><table class="table table-dark table-striped'
                f' table-bordered table-sm mb-0"><thead><tr>{th}</tr></thead>'
                f'<tbody>{tb}</tbody></table></div>')

    dns_html = _ntable(
        ["Request", "Type", "Answers"],
        [(d.get("request", ""), d.get("type", ""),
          ", ".join(a.get("data", "") for a in d.get("answers", []))) for d in _dns]
    )
    http_html = _ntable(
        ["URI", "Method", "Host", "User-Agent", "Status"],
        [(h.get("uri", ""), h.get("method", ""), h.get("host", ""),
          h.get("user-agent", "")[:80], h.get("status", "")) for h in _http]
    )
    tls_html = _ntable(
        ["SNI", "Version", "Src IP", "Dst IP", "JA3"],
        [(t.get("sni", ""), t.get("version", ""),
          t.get("src_ip", t.get("src", "")), t.get("dst_ip", t.get("dst", "")),
          t.get("ja3", {}).get("hash", "") if isinstance(t.get("ja3"), dict) else t.get("ja3", ""))
         for t in _tls]
    )
    ssh_html = _ntable(
        ["Src IP", "Dst IP", "Client Banner", "Server Banner"],
        [(s.get("src_ip", ""), s.get("dst_ip", ""),
          s.get("client", {}).get("banner", ""), s.get("server", {}).get("banner", ""))
         for s in _ssh]
    )
    nfiles_html = _ntable(
        ["Path", "SHA256", "URI"],
        [(f.get("path", f.get("filename", "")), f.get("sha256", ""), f.get("uri", ""))
         for f in _nfiles]
    )
    hosts_html = _ntable(
        ["IP", "Country", "Ports", "Process"],
        [(h.get("ip", ""), h.get("country_name", ""),
          ", ".join(str(p) for p in h.get("ports", [])),
          h.get("process_name", "") or "") for h in _hosts]
    )
    tcp_html = _ntable(
        ["Src", "Sport", "Dst", "Dport", "Process"],
        [(t.get("src", ""), t.get("sport", ""),
          t.get("dst", ""), t.get("dport", ""),
          t.get("process_name", "") or "") for t in _tcp]
    )
    udp_html = _ntable(
        ["Src", "Sport", "Dst", "Dport", "Process"],
        [(u.get("src", ""), u.get("sport", ""),
          u.get("dst", ""), u.get("dport", ""),
          u.get("process_name", "") or "") for u in _udp]
    )
    dead_html = _ntable(
        ["IP", "Port"],
        [(d[0], d[1]) if isinstance(d, list) else (d.get("ip", ""), d.get("port", ""))
         for d in _dead]
    )

    pane_network = f"""
<ul class="nav nav-pills mb-3 flex-wrap" id="netTab" role="tablist">
  <li class="nav-item"><a class="nav-link active" data-bs-toggle="pill" href="#net-dns">
    <i class="fas fa-globe me-1"></i>DNS <span class="badge bg-secondary">{len(_dns)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-http">
    <i class="fas fa-link me-1"></i>HTTP <span class="badge bg-secondary">{len(_http)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-tls">
    <i class="fas fa-lock me-1"></i>TLS <span class="badge bg-secondary">{len(_tls)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-ssh">
    <i class="fas fa-terminal me-1"></i>SSH <span class="badge bg-secondary">{len(_ssh)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-files">
    <i class="fas fa-file me-1"></i>Files <span class="badge bg-secondary">{len(_nfiles)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-hosts">
    <i class="fas fa-server me-1"></i>Hosts <span class="badge bg-secondary">{len(_hosts)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-tcp">
    <i class="fas fa-exchange-alt me-1"></i>TCP <span class="badge bg-secondary">{len(_tcp)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-udp">
    <i class="fas fa-exchange-alt me-1"></i>UDP <span class="badge bg-secondary">{len(_udp)}</span></a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="pill" href="#net-dead">
    <i class="fas fa-skull me-1"></i>Dead Hosts <span class="badge bg-secondary">{len(_dead)}</span></a></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="net-dns">{dns_html}</div>
  <div class="tab-pane fade" id="net-http">{http_html}</div>
  <div class="tab-pane fade" id="net-tls">{tls_html}</div>
  <div class="tab-pane fade" id="net-ssh">{ssh_html}</div>
  <div class="tab-pane fade" id="net-files">{nfiles_html}</div>
  <div class="tab-pane fade" id="net-hosts">{hosts_html}</div>
  <div class="tab-pane fade" id="net-tcp">{tcp_html}</div>
  <div class="tab-pane fade" id="net-udp">{udp_html}</div>
  <div class="tab-pane fade" id="net-dead">{dead_html}</div>
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

    # ── Behavior ──────────────────────────────────────────────
    api_calls  = parser.get_api_calls(max_per_process=500)
    host_iocs  = parser.get_host_iocs()

    if api_calls:
        api_rows = [
            (c["pid"], c["process"], c["api"], c["category"], c["args"][:200])
            for c in api_calls[:3000]
        ]
        api_tbl = _ntable(["PID", "Process", "API", "Category", "Args"], api_rows)
        trunc_note = (f'<p class="text-muted small">※ 최대 500개/프로세스, 총 {len(api_calls)}개 표시</p>'
                      if len(api_calls) >= 500 else "")
    else:
        api_tbl = '<p class="text-muted fst-italic">동적 분석 데이터 없음</p>'
        trunc_note = ""

    reg_tbl   = _ntable(["Registry Key"], [(r,) for r in host_iocs["registry"]])
    hfile_tbl = _ntable(["File Path"],    [(f,) for f in host_iocs["files"]])
    mutex_tbl = _ntable(["Mutex"],        [(m,) for m in host_iocs["mutexes"]])

    pane_behavior = f"""
<h6 class="text-accent mb-2"><i class="fas fa-list me-1"></i>API Calls</h6>
{trunc_note}
{api_tbl}
<div class="row mt-4">
  <div class="col-md-4">
    <h6 class="text-warning"><i class="fas fa-key me-1"></i>Registry <span class="badge bg-secondary">{len(host_iocs["registry"])}</span></h6>
    {reg_tbl}
  </div>
  <div class="col-md-4">
    <h6 class="text-info"><i class="fas fa-file me-1"></i>Files <span class="badge bg-secondary">{len(host_iocs["files"])}</span></h6>
    {hfile_tbl}
  </div>
  <div class="col-md-4">
    <h6 class="text-secondary"><i class="fas fa-lock me-1"></i>Mutexes <span class="badge bg-secondary">{len(host_iocs["mutexes"])}</span></h6>
    {mutex_tbl}
  </div>
</div>"""

    # ── CAPE ──────────────────────────────────────────────────
    payloads = parser.get_cape_payloads()
    configs  = parser.get_cape_configs()

    if payloads:
        payload_rows = [
            (p.get("sha256", ""), p.get("cape_type", p.get("type", "")),
             p.get("size", ""), "Yes" if p.get("cape_config") else "No")
            for p in payloads
        ]
        payload_tbl = _ntable(["SHA256", "Type", "Size", "Config?"], payload_rows)
    else:
        payload_tbl = '<p class="text-muted fst-italic">추출된 페이로드 없음</p>'

    if configs:
        cfg_blocks = "".join(
            f'<h6 class="text-warning mt-3">[{_e(c["family"])}] {_e(c["sha256"][:16])}…</h6>'
            f'<pre class="small">{_e(json.dumps(c["config"], ensure_ascii=False, indent=2))}</pre>'
            for c in configs
        )
    else:
        cfg_blocks = '<p class="text-muted fst-italic">추출된 악성코드 설정값 없음</p>'

    pane_cape = f"""
<h6 class="text-accent mb-2"><i class="fas fa-box-open me-1"></i>Payloads <span class="badge bg-secondary">{len(payloads)}</span></h6>
{payload_tbl}
<hr>
<h6 class="text-warning mt-3"><i class="fas fa-cog me-1"></i>Malware Configs</h6>
{cfg_blocks}"""

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
    <div class="tab-pane fade" id="pane-attack" role="tabpanel">
      {pane_attack}
    </div>
    <div class="tab-pane fade" id="pane-network" role="tabpanel">
      {pane_network}
    </div>
    <div class="tab-pane fade" id="pane-behavior" role="tabpanel">
      {pane_behavior}
    </div>
    <div class="tab-pane fade" id="pane-cape" role="tabpanel">
      {pane_cape}
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


