"""CAPEv2 분석 결과 → HTML 리포트 생성"""
import html
from datetime import datetime


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def generate(parser, all_sigs: list, ai_text: str = "") -> str:
    verdict  = parser.get_verdict()
    hashes   = parser.get_hashes()
    info     = parser.get_info()
    score    = verdict["score"]
    families = verdict["families"]
    ttps     = parser.get_ttps()
    pe_secs  = parser.get_pe_sections()
    pe_imps  = parser.get_pe_imports()
    yara_m   = parser.get_yara_matches()

    SEV_COLOR = {
        "critical": "#e05252", "high": "#e07050",
        "medium": "#e0c050",   "low": "#8888cc", "info": "#888888",
    }

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── 해시 rows ──────────────────────────────────────────────
    hash_rows = "".join(
        f"<tr><td>{k.upper()}</td><td class='mono'>{_esc(v)}</td></tr>"
        for k, v in hashes.items() if v
    )

    # ── Signatures rows ────────────────────────────────────────
    sig_rows = ""
    for s in all_sigs:
        sev   = str(s.get("severity", "info")).lower()
        color = SEV_COLOR.get(sev, "#888")
        name  = _esc(s.get("name", ""))
        desc  = _esc(s.get("description", ""))
        sig_rows += (
            f"<tr>"
            f"<td><span class='badge' style='background:{color}'>{sev.upper()}</span></td>"
            f"<td>{name}</td><td>{desc}</td>"
            f"</tr>"
        )

    # ── ATT&CK rows ────────────────────────────────────────────
    ttp_rows = "".join(
        f"<tr><td class='mono'>{_esc(t['technique_id'])}</td>"
        f"<td>{_esc(t['signature'])}</td>"
        f"<td>{_esc(t['description'])}</td></tr>"
        for t in ttps
    )

    # ── PE Sections rows ───────────────────────────────────────
    pe_sec_rows = "".join(
        f"<tr><td class='mono'>{_esc(s.get('name',''))}</td>"
        f"<td class='mono'>{_esc(s.get('virtual_address',''))}</td>"
        f"<td class='mono'>{_esc(s.get('virtual_size',''))}</td>"
        f"<td>{_esc(s.get('entropy',''))}</td></tr>"
        for s in pe_secs
    )

    # ── PE Imports rows ────────────────────────────────────────
    pe_imp_rows = "".join(
        f"<tr><td class='mono'>{_esc(imp.get('dll',''))}</td>"
        f"<td>{_esc(', '.join(i.get('name','') for i in imp.get('imports',[])[:15]))}</td></tr>"
        for imp in pe_imps[:50]
    )

    # ── YARA ──────────────────────────────────────────────────
    yara_items = "".join(
        f"<li class='mono'>{_esc(m.get('name', str(m)))}</li>" for m in yara_m
    ) if yara_m else "<li>없음</li>"

    # ── Families ──────────────────────────────────────────────
    family_html = (
        " ".join(f"<span class='badge' style='background:#e0a050'>{_esc(f)}</span>" for f in families)
        if families else "—"
    )

    # ── AI 분석 ────────────────────────────────────────────────
    ai_section = ""
    if ai_text:
        import re
        safe = _esc(ai_text).replace("##", "<br><strong>").replace("\n", "<br>")
        ai_section = f"""
        <section>
          <h2>AI 분석</h2>
          <div class='ai-box'>{safe}</div>
        </section>"""

    html_out = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CAPEv2 Report — {_esc(hashes.get('sha256','')[:16])}...</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#e0e0e0;padding:24px}}
  h1{{font-size:1.4rem;color:#7ec8e3;margin-bottom:4px}}
  h2{{font-size:1.1rem;color:#7ec8e3;margin:20px 0 8px}}
  section{{background:#16213e;border-radius:8px;padding:16px;margin-bottom:16px}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:4px;font-size:.8rem;font-weight:bold;color:#1a1a2e}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{background:#0f3460;color:#7ec8e3;text-align:left;padding:6px 10px}}
  td{{padding:5px 10px;border-bottom:1px solid #0f3460;vertical-align:top}}
  tr:hover td{{background:#0f3460aa}}
  .mono{{font-family:Consolas,monospace;font-size:.82rem;word-break:break-all}}
  ul{{list-style:none;padding-left:8px}}
  ul li::before{{content:"• ";color:#7ec8e3}}
  .ai-box{{background:#0f3460;border-radius:6px;padding:14px;line-height:1.7;font-size:.9rem;white-space:pre-wrap}}
  .meta{{color:#888;font-size:.8rem;margin-top:4px}}
  a{{color:#7ec8e3}}
</style>
</head>
<body>
<h1>CAPEv2 Malware Analysis Report</h1>
<p class="meta">생성: {now} &nbsp;|&nbsp; {_esc(info.get('id',''))}</p>

<section>
  <h2>File Hashes</h2>
  <table><tbody>{hash_rows}</tbody></table>
</section>

<section>
  <h2>Signatures ({len(all_sigs)}개)</h2>
  <table>
    <thead><tr><th>Severity</th><th>Name</th><th>Description</th></tr></thead>
    <tbody>{sig_rows if sig_rows else '<tr><td colspan=3>없음</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>MITRE ATT&amp;CK TTPs ({len(ttps)}개)</h2>
  <table>
    <thead><tr><th>Technique ID</th><th>Signature</th><th>Description</th></tr></thead>
    <tbody>{ttp_rows if ttp_rows else '<tr><td colspan=3>없음</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>PE Sections</h2>
  <table>
    <thead><tr><th>Name</th><th>Virtual Address</th><th>Virtual Size</th><th>Entropy</th></tr></thead>
    <tbody>{pe_sec_rows if pe_sec_rows else '<tr><td colspan=4>없음</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>PE Imports</h2>
  <table>
    <thead><tr><th>DLL</th><th>Functions</th></tr></thead>
    <tbody>{pe_imp_rows if pe_imp_rows else '<tr><td colspan=2>없음</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>YARA Matches</h2>
  <ul>{yara_items}</ul>
</section>
{ai_section}
</body>
</html>"""
    return html_out
