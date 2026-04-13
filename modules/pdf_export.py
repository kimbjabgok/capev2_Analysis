"""PDF 리포트 생성 — reportlab (5-page layout)"""
from datetime import datetime
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

    # ── Colors ────────────────────────────────────────────────
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


def _sec_hdr(text, S) -> Table:
    t = Table([[Paragraph(text, S["section"])]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_SECTION),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
    ]))
    return t


def _kv(rows, S, cw=None) -> Table:
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


def generate(parser, all_sigs: list, ai_text: str, output_path: str) -> None:
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
    sp  = lambda n=0.3: Spacer(1, n * cm)

    # ── Page 1: Executive Summary ─────────────────────────────
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

    # 커버 헤더
    cover = Table([[Paragraph("MALWARE ANALYSIS REPORT", S["title"])]],
                  colWidths=[CONTENT_W])
    cover.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 30),
        ("BOTTOMPADDING", (0,0), (-1,-1), 30),
    ]))
    story += [cover, sp(0.4)]

    # 메타 정보
    story.append(_kv([
        ("분석 일시", now),
        ("Report ID", info.get("id", "—")),
    ], S))
    story.append(sp(0.5))

    # 판정 박스
    vbox = Table([[Paragraph(f"{label}  —  Score: {score} / 10", S["verdict"])]],
                 colWidths=[CONTENT_W])
    vbox.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), VERDICT_COLOR[label]),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
    ]))
    story += [vbox, sp(0.5)]

    # 파일 기본 정보
    story.append(_kv([
        ("파일명",           fi.get("name", "—")),
        ("SHA256",          hashes.get("sha256", "—")),
        ("악성코드 패밀리",   ", ".join(families) if families else "—"),
    ], S))
    story.append(PageBreak())

    # ── Page 2: File Information & IOC ────────────────────────
    story += [_sec_hdr("2. File Information & IOC", S), sp()]

    # File Hashes
    story.append(_sub("File Hashes", S))
    story.append(sp(0.15))
    story.append(_kv([(k.upper(), v) for k, v in hashes.items() if v], S))
    story.append(sp(0.4))

    # PE Sections
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

    # Suspicious Imports
    susp = parser.get_suspicious_imports()
    if susp:
        story.append(_sub("Suspicious Imports", S))
        story.append(sp(0.15))
        story.append(_kv(
            [(imp["dll"], ", ".join(imp["functions"])) for imp in susp], S
        ))
        story.append(sp(0.4))

    # Network IOC
    net = parser.get_network_iocs()
    story.append(_sub("Network IOC", S))
    story.append(sp(0.15))
    net_rows = (
        [("Domain", d) for d in net["domains"][:20]] +
        [("IP",     ip) for ip in net["ips"][:20]] +
        [("URL",    u)  for u  in net["urls"][:20]]
    )
    story.append(_kv(net_rows, S) if net_rows
                 else Paragraph("없음", S["body"]))
    story.append(sp(0.4))

    # Host IOC
    host = parser.get_host_iocs()
    story.append(_sub("Host IOC", S))
    story.append(sp(0.15))
    host_rows = (
        [("Registry", r) for r in host["registry"][:15]] +
        [("File",     f_) for f_ in host["files"][:15]] +
        [("Mutex",    m)  for m  in host["mutexes"][:15]]
    )
    story.append(_kv(host_rows, S) if host_rows
                 else Paragraph("없음", S["body"]))
    story.append(PageBreak())

    # ── Page 3: Detection Signatures ─────────────────────────
    story += [_sec_hdr("3. Detection Signatures", S), sp()]

    if all_sigs:
        cw3  = [2.2*cm, 5.5*cm, CONTENT_W - 7.7*cm]
        hdr3 = [Paragraph(h, S["label"]) for h in ["Severity", "Name", "Description"]]
        rows3 = [hdr3]
        for sig in all_sigs:
            sev      = str(sig.get("severity", "info")).lower()
            sc       = SEV_COLOR.get(sev, C_DIM)
            is_cmr   = sig.get("name", "").startswith("[CMR]")
            fn       = fb if is_cmr else f
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

    # ── Page 4: MITRE ATT&CK ─────────────────────────────────
    story += [_sec_hdr("4. MITRE ATT&CK", S), sp()]

    ttps = parser.get_ttps()
    if ttps:
        cw4  = [2.8*cm, 4.2*cm, CONTENT_W - 7*cm]
        hdr4 = [Paragraph(h, S["label"])
                for h in ["Technique ID", "Tactic", "Description"]]
        rows4 = [hdr4] + [[
            Paragraph(t["technique_id"], S["mono"]),
            Paragraph(TECHNIQUE_TACTICS.get(t["technique_id"].split(".")[0], "—"), S["body"]),
            Paragraph(t.get("description", ""), S["body"]),
        ] for t in ttps]
        t4 = Table(rows4, colWidths=cw4)
        t4.setStyle(TableStyle(TABLE_STYLE_BASE))
        story.append(t4)
    else:
        story.append(Paragraph("탐지된 ATT&CK TTP 없음", S["body"]))

    story.append(PageBreak())

    # ── Page 5: AI Analysis ───────────────────────────────────
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
