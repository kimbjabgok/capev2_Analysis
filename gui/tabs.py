"""모든 탭 빌드 함수 (tab_overview/signatures/attack/behavior/network/cape/ai 통합)"""
import tkinter as tk
from tkinter import ttk
import threading
import webbrowser
import json

from gui.styles import *

MITRE_BASE = "https://attack.mitre.org/techniques/"
SEVERITIES  = ["All", "Info", "Low", "Medium", "High", "Critical"]


# ── Overview ──────────────────────────────────────────────────
def build_overview(parent: ttk.Frame, parser, config: dict, refresh_vt_cb=None):
    from modules import services as _svc

    for w in parent.winfo_children():
        w.destroy()

    hashes   = parser.get_hashes()
    verdict  = parser.get_verdict()
    score    = verdict["score"]
    families = verdict["families"]
    pe       = parser.get_pe()
    yara_m   = parser.get_yara_matches()

    # 위협 판정 배지
    badge_frame = ttk.Frame(parent)
    badge_frame.pack(fill="x", padx=12, pady=(12, 4))

    if score >= 7:
        badge_color, badge_text = CRITICAL, "MALICIOUS"
    elif score >= 4:
        badge_color, badge_text = ORANGE, "SUSPICIOUS"
    else:
        badge_color, badge_text = GREEN, "CLEAN"

    tk.Label(badge_frame, text=f"  {badge_text}  ",
             bg=badge_color, fg=BG, font=("Segoe UI", 13, "bold"),
             relief="flat", padx=8, pady=4).pack(side="left")
    tk.Label(badge_frame, text=f"  Score: {score}/10",
             bg=BG, fg=FG, font=FONT_TITLE).pack(side="left", padx=10)
    if families:
        tk.Label(badge_frame, text="Family: " + ", ".join(families),
                 bg=BG, fg=YELLOW, font=FONT_LABEL).pack(side="left", padx=6)

    ttk.Separator(parent, orient="horizontal").pack(fill="x", padx=12, pady=6)

    # 위협 요약 카드 (행동 태그 + 주요 TTP)
    _BEHAVIOR_TAGS = {
        "antidebug":   "안티 디버깅",  "antiav":      "안티 AV",
        "antivm":      "안티 VM",      "ransomware":  "랜섬웨어",
        "injection":   "프로세스 인젝션", "c2":        "C2 통신",
        "network":     "네트워크 활동", "persistence": "지속성",
        "dropper":     "드로퍼",       "downloader":  "다운로더",
        "keylogger":   "키로거",       "spyware":     "스파이웨어",
        "infostealer": "정보 탈취",    "banker":      "뱅킹 악성코드",
        "rootkit":     "루트킷",       "bootkit":     "부트킷",
        "exploit":     "익스플로잇",   "shellcode":   "셸코드",
        "packer":      "패커",         "obfuscation": "난독화",
        "cryptominer": "크립토마이너", "backdoor":    "백도어",
        "rat":         "원격 제어(RAT)", "worm":      "웜",
        "trojan":      "트로이목마",   "generic":     "일반 악성코드",
    }
    _TTP_DESCS = {
        "T1027": "난독화/패킹",         "T1055": "프로세스 인젝션",
        "T1003": "자격증명 덤핑",        "T1021": "원격 서비스",
        "T1059": "커맨드 인터프리터",    "T1082": "시스템 정보 수집",
        "T1083": "파일/디렉터리 탐색",   "T1105": "원격 도구 이전",
        "T1112": "레지스트리 수정",      "T1140": "파일 디코딩",
        "T1202": "간접 커맨드 실행",     "T1204": "사용자 실행",
        "T1218": "시스템 바이너리 실행", "T1219": "원격 접근 SW",
        "T1486": "데이터 암호화(랜섬웨어)", "T1490": "백업/복구 방해",
        "T1497": "샌드박스 탐지",        "T1518": "보안 SW 탐지",
        "T1547": "자동 실행",            "T1548": "권한 상승",
        "T1562": "방어 무력화",          "T1564": "아티팩트 숨기기",
        "T1566": "피싱",                 "T1574": "DLL 하이재킹",
        "T1620": "반사적 코드 로딩",     "T1622": "디버거 탐지",
        "T1005": "로컬 데이터 수집",
    }

    summary_lf = tk.LabelFrame(parent, text="위협 요약",
                                bg=BG, fg=ACCENT, font=FONT_LABEL,
                                relief="flat", bd=1, highlightbackground=BG3)
    summary_lf.pack(fill="x", padx=12, pady=4)

    seen_tags: list = []
    for sig in parser.get_signatures():
        tag = _BEHAVIOR_TAGS.get(sig.get("category", "").lower())
        if tag and tag not in seen_tags:
            seen_tags.append(tag)

    if seen_tags:
        tag_row = tk.Frame(summary_lf, bg=BG)
        tag_row.pack(fill="x", padx=8, pady=(6, 2))
        tk.Label(tag_row, text="행동 태그:", bg=BG, fg=FG_DIM,
                 font=FONT_LABEL).pack(side="left")
        for tag in seen_tags[:8]:
            tk.Label(tag_row, text=f" {tag} ",
                     bg=BG3, fg=ACCENT, font=("Segoe UI", 9),
                     relief="flat", padx=6, pady=2).pack(side="left", padx=3)

    ttps = parser.get_ttps()
    if ttps:
        tk.Label(summary_lf, text="주요 TTP:", bg=BG, fg=FG_DIM,
                 font=FONT_LABEL).pack(anchor="w", padx=8, pady=(4, 0))
        seen_ids: set = set()
        ttp_count = 0
        for ttp in ttps:
            tid = ttp.get("technique_id", "")
            tid_base = tid.split(".")[0]
            if tid_base in seen_ids or ttp_count >= 6:
                continue
            seen_ids.add(tid_base)
            desc = _TTP_DESCS.get(tid_base, ttp.get("description", ""))
            ttp_row = tk.Frame(summary_lf, bg=BG)
            ttp_row.pack(fill="x", padx=8, pady=1)
            tk.Label(ttp_row, text=f"  • {tid}", bg=BG, fg=YELLOW,
                     font=FONT_MONO, width=12, anchor="w").pack(side="left")
            tk.Label(ttp_row, text=desc, bg=BG, fg=FG,
                     font=FONT_LABEL).pack(side="left", padx=4)
            ttp_count += 1
        tk.Frame(summary_lf, bg=BG, height=4).pack()

    # 해시 (클릭 복사)
    hash_lf = tk.LabelFrame(parent, text="File Hashes",
                             bg=BG, fg=ACCENT, font=FONT_LABEL,
                             relief="flat", bd=1, highlightbackground=BG3)
    hash_lf.pack(fill="x", padx=12, pady=4)

    def _copy(val):
        parent.clipboard_clear()
        parent.clipboard_append(val)
        parent.update()

    for label, val in hashes.items():
        if not val:
            continue
        row = ttk.Frame(hash_lf)
        row.pack(fill="x", padx=6, pady=2)
        tk.Label(row, text=f"{label.upper():<8}", bg=BG, fg=FG_DIM,
                 font=FONT_MONO, width=8, anchor="w").pack(side="left")
        lbl = tk.Label(row, text=val, bg=BG, fg=FG, font=FONT_MONO,
                       cursor="hand2", anchor="w")
        lbl.pack(side="left", fill="x", expand=True)
        lbl.bind("<Button-1>", lambda e, v=val: _copy(v))
        lbl.bind("<Enter>", lambda e, l=lbl: l.config(fg=ACCENT))
        lbl.bind("<Leave>", lambda e, l=lbl: l.config(fg=FG))
        tk.Label(row, text="[copy]", bg=BG, fg=FG_DIM,
                 font=FONT_MONO, cursor="hand2").pack(side="left", padx=4)

    # VirusTotal
    vt_frame = tk.LabelFrame(parent, text="VirusTotal",
                              bg=BG, fg=ACCENT, font=FONT_LABEL,
                              relief="flat", bd=1, highlightbackground=BG3)
    vt_frame.pack(fill="x", padx=12, pady=4)

    vt_info_var = tk.StringVar(value="— (API 키 필요)")
    vt_lbl = tk.Label(vt_frame, textvariable=vt_info_var, bg=BG, fg=FG, font=FONT_MONO)
    vt_lbl.pack(side="left", padx=8, pady=4)

    sha256 = hashes.get("sha256", "")

    def _do_vt_lookup():
        api_key = config.get("vt_api_key", "")
        if not api_key:
            vt_info_var.set("VirusTotal API 키를 도구 메뉴 → 설정에서 입력하세요.")
            return
        vt_info_var.set("조회 중...")
        result = _svc.lookup_hash(sha256, api_key)
        if "error" in result:
            if result["error"] == "rate_limit":
                vt_info_var.set(f"⚠ {result['message']}")
                vt_lbl.config(fg=YELLOW)
            else:
                vt_info_var.set(f"오류: {result.get('message', result['error'])}")
                vt_lbl.config(fg=RED)
        else:
            pos   = result["positives"]
            total = result["total"]
            link  = result.get("link", "")
            color = RED if pos > 10 else ORANGE if pos > 0 else GREEN
            vt_info_var.set(f"{pos}/{total} engines detected")
            vt_lbl.config(fg=color, cursor="hand2")
            if link:
                vt_lbl.bind("<Button-1>", lambda e: webbrowser.open(link))

    ttk.Button(vt_frame, text="VT 조회",
               command=lambda: threading.Thread(target=_do_vt_lookup, daemon=True).start()
               ).pack(side="left", padx=6, pady=4)

    # PE Sections
    pe_sections = parser.get_pe_sections()
    if pe_sections:
        sec_lf = tk.LabelFrame(parent, text="PE Sections",
                                bg=BG, fg=ACCENT, font=FONT_LABEL,
                                relief="flat", bd=1, highlightbackground=BG3)
        sec_lf.pack(fill="x", padx=12, pady=4)
        cols = ["Name", "Virtual Size", "Virtual Address", "Raw Size", "Entropy"]
        tv = scrolled_treeview(sec_lf, cols)
        tv.pack(fill="x", padx=4, pady=4)
        for s in pe_sections:
            tv.insert("", "end", values=(
                s.get("name", ""),
                s.get("virtual_size", ""),
                s.get("virtual_address", ""),
                s.get("size_of_data", s.get("size_of_raw_data", "")),
                s.get("entropy", ""),
            ))

    # PE Imports
    pe_imports = parser.get_pe_imports()
    if pe_imports:
        imp_lf = tk.LabelFrame(parent, text="PE Imports",
                                bg=BG, fg=ACCENT, font=FONT_LABEL,
                                relief="flat", bd=1, highlightbackground=BG3)
        imp_lf.pack(fill="x", padx=12, pady=4)
        tv2 = scrolled_treeview(imp_lf, ["DLL", "Functions"])
        tv2.pack(fill="x", padx=4, pady=4)
        for imp in pe_imports[:50]:
            dll = imp.get("dll", "")
            fns = ", ".join(i.get("name", "") for i in imp.get("imports", [])[:10])
            tv2.insert("", "end", values=(dll, fns))

    # YARA Matches
    if yara_m:
        yara_lf = tk.LabelFrame(parent, text="YARA Matches",
                                 bg=BG, fg=ACCENT, font=FONT_LABEL,
                                 relief="flat", bd=1, highlightbackground=BG3)
        yara_lf.pack(fill="x", padx=12, pady=4)
        for m in yara_m:
            tk.Label(yara_lf, text=f"  • {m.get('name', m)}",
                     bg=BG, fg=YELLOW, font=FONT_MONO).pack(anchor="w", padx=6)


# ── Signatures ────────────────────────────────────────────────
def build_signatures(parent: ttk.Frame, all_sigs: list):
    for w in parent.winfo_children():
        w.destroy()

    filter_frame = ttk.Frame(parent)
    filter_frame.pack(fill="x", padx=12, pady=8)
    tk.Label(filter_frame, text="Severity Filter:", bg=BG, fg=FG,
             font=FONT_LABEL).pack(side="left")

    sel_var = tk.StringVar(value="All")
    for sev in SEVERITIES:
        color = SEVERITY_COLOR.get(sev.lower(), FG)
        tk.Radiobutton(filter_frame, text=sev, variable=sel_var, value=sev,
                       bg=BG, fg=color, selectcolor=BG2,
                       activebackground=BG, activeforeground=color,
                       font=FONT_LABEL,
                       command=lambda: _refresh()).pack(side="left", padx=6)

    tk.Label(filter_frame, text=f"  총 {len(all_sigs)}개",
             bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(side="left", padx=10)

    paned = tk.PanedWindow(parent, orient="horizontal",
                           bg=BG3, sashwidth=4, relief="flat")
    paned.pack(fill="both", expand=True, padx=12, pady=4)

    left = ttk.Frame(paned)
    paned.add(left, width=380)
    tv = scrolled_treeview(left, ["Severity", "Name"])
    tv.column("Severity", width=80,  minwidth=60)
    tv.column("Name",     width=280, minwidth=120)

    right = ttk.Frame(paned)
    paned.add(right)
    detail_text = scrolled_text(right)
    detail_text.config(state="disabled")

    def _show_detail(event):
        sel = tv.selection()
        if not sel:
            return
        idx = int(tv.item(sel[0], "tags")[0])
        sig = visible[idx]
        detail_text.config(state="normal")
        detail_text.delete("1.0", "end")
        detail_text.tag_config("title",   foreground=ACCENT,    font=("Consolas", 11, "bold"))
        detail_text.tag_config("sev",     foreground=SEVERITY_COLOR.get(sig.get("severity","").lower(), FG))
        detail_text.tag_config("label",   foreground=FG_DIM)
        detail_text.tag_config("ev",      foreground=YELLOW)
        detail_text.tag_config("ttp_tag", foreground=GREEN)
        detail_text.insert("end", sig.get("name", "") + "\n", "title")
        detail_text.insert("end", f"\n[Severity]  ", "label")
        detail_text.insert("end", sig.get("severity", "").upper() + "\n", "sev")
        detail_text.insert("end", f"\n[Description]\n", "label")
        detail_text.insert("end", sig.get("description", "") + "\n")
        ttps = sig.get("ttp", [])
        if ttps:
            detail_text.insert("end", f"\n[ATT&CK TTP]\n", "label")
            detail_text.insert("end", "  " + "  ".join(ttps) + "\n", "ttp_tag")
        evidence = sig.get("evidence", [])
        if evidence:
            detail_text.insert("end", f"\n[Evidence] ({len(evidence)} items)\n", "label")
            for ev in evidence[:30]:
                detail_text.insert("end", f"  • {ev}\n", "ev")
        detail_text.config(state="disabled")

    tv.bind("<<TreeviewSelect>>", _show_detail)
    visible: list = []

    def _refresh():
        tv.delete(*tv.get_children())
        visible.clear()
        sev_filter = sel_var.get().lower()
        for sig in all_sigs:
            sev = sig.get("severity", "info").lower()
            if sev_filter != "all" and sev != sev_filter:
                continue
            color  = SEVERITY_COLOR.get(sev, FG)
            tag_id = str(len(visible))
            visible.append(sig)
            tv.insert("", "end", tags=(tag_id,), values=(sev.upper(), sig.get("name", "")))
            tv.tag_configure(tag_id, foreground=color)

    _refresh()


# ── ATT&CK ────────────────────────────────────────────────────
def build_attack(parent: ttk.Frame, ttps: list):
    for w in parent.winfo_children():
        w.destroy()

    if not ttps:
        tk.Label(parent, text="ATT&CK TTP 없음", bg=BG, fg=FG_DIM,
                 font=FONT_TITLE).pack(expand=True)
        return

    tk.Label(parent, text=f"MITRE ATT&CK TTPs — {len(ttps)}개 탐지",
             bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=8)

    cols = ["Technique ID", "Signature", "Description"]
    tv = scrolled_treeview(parent, cols)
    tv.column("Technique ID", width=120, minwidth=80)
    tv.column("Signature",    width=240, minwidth=120)
    tv.column("Description",  width=500, minwidth=200)

    for ttp in ttps:
        tv.insert("", "end", values=(
            ttp.get("technique_id", ""),
            ttp.get("signature", ""),
            ttp.get("description", ""),
        ))

    def _open_mitre(event):
        sel = tv.selection()
        if not sel:
            return
        tid = tv.item(sel[0], "values")[0]
        if tid:
            webbrowser.open(MITRE_BASE + tid.replace(".", "/"))

    tv.bind("<ButtonRelease-1>", _open_mitre)
    tk.Label(parent, text="※ Technique ID 클릭으로 MITRE ATT&CK 페이지 열기",
             bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(anchor="w", padx=12, pady=4)


# ── Behavior ──────────────────────────────────────────────────
def build_behavior(parent: ttk.Frame, api_calls: list):
    for w in parent.winfo_children():
        w.destroy()

    if not api_calls:
        tk.Label(parent,
                 text="동적 분석 데이터가 없습니다.\n샌드박스에서 프로세스 행위가 기록되지 않았거나 정적 분석만 수행된 리포트입니다.",
                 bg=BG, fg=FG_DIM, font=FONT_LABEL,
                 justify="center").pack(expand=True)
        return

    tk.Label(parent, text=f"API Calls — {len(api_calls)}개 (최대 1,000개/프로세스)",
             bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=6)

    procs = {}
    for c in api_calls:
        key = f"{c['process']} (PID {c['pid']})"
        procs.setdefault(key, []).append(c)

    top = ttk.Frame(parent)
    top.pack(fill="x", padx=12, pady=4)
    tk.Label(top, text="Process:", bg=BG, fg=FG, font=FONT_LABEL).pack(side="left")

    proc_list = ["All"] + list(procs.keys())
    sel_var = tk.StringVar(value="All")
    combo = ttk.Combobox(top, textvariable=sel_var, values=proc_list,
                         width=50, state="readonly")
    combo.pack(side="left", padx=8)

    tk.Label(top, text="Filter:", bg=BG, fg=FG, font=FONT_LABEL).pack(side="left", padx=(16, 4))
    search_var = tk.StringVar()
    ttk.Entry(top, textvariable=search_var, width=30).pack(side="left")

    cols = ["PID", "Process", "API", "Category", "Args"]
    tv = scrolled_treeview(parent, cols)
    tv.column("PID",      width=60,  minwidth=40)
    tv.column("Process",  width=180, minwidth=80)
    tv.column("API",      width=200, minwidth=100)
    tv.column("Category", width=100, minwidth=60)
    tv.column("Args",     width=500, minwidth=100)

    def _refresh(*_):
        tv.delete(*tv.get_children())
        proc_filter   = sel_var.get()
        search_filter = search_var.get().lower()
        data = api_calls if proc_filter == "All" else procs.get(proc_filter, [])
        count = 0
        for c in data:
            row = (c["pid"], c["process"], c["api"], c["category"], c["args"][:200])
            if search_filter and search_filter not in " ".join(str(v) for v in row).lower():
                continue
            tv.insert("", "end", values=row)
            count += 1
            if count >= 2000:
                break

    combo.bind("<<ComboboxSelected>>", _refresh)
    search_var.trace_add("write", _refresh)
    _refresh()


# ── Network ───────────────────────────────────────────────────
def _fill_table(parent, data: list, columns: list, extract_fn):
    if not data:
        tk.Label(parent, text="데이터 없음", bg=BG, fg=FG_DIM,
                 font=FONT_LABEL).pack(expand=True)
        return
    tv = scrolled_treeview(parent, columns)
    for item in data:
        tv.insert("", "end", values=extract_fn(item))


def build_network(parent: ttk.Frame, parser):
    for w in parent.winfo_children():
        w.destroy()

    nb = ttk.Notebook(parent)
    nb.pack(fill="both", expand=True, padx=4, pady=4)

    tab_sur = ttk.Frame(nb)
    nb.add(tab_sur, text="Suricata Alerts")
    _fill_table(tab_sur, parser.get_suricata(),
                ["SID", "Severity", "Signature", "Src IP", "Dst IP", "Proto"],
                lambda a: (
                    a.get("alert", {}).get("signature_id", ""),
                    a.get("alert", {}).get("severity", ""),
                    a.get("alert", {}).get("signature", ""),
                    a.get("src_ip", ""), a.get("dest_ip", ""), a.get("proto", ""),
                ))

    tab_dns = ttk.Frame(nb)
    nb.add(tab_dns, text="DNS")
    _fill_table(tab_dns, parser.get_dns(),
                ["Request", "Type", "Answers"],
                lambda d: (
                    d.get("request", ""), d.get("type", ""),
                    ", ".join(a.get("data", "") for a in d.get("answers", [])),
                ))

    tab_http = ttk.Frame(nb)
    nb.add(tab_http, text="HTTP")
    _fill_table(tab_http, parser.get_http(),
                ["URI", "Method", "Host", "User-Agent", "Status"],
                lambda h: (
                    h.get("uri", ""), h.get("method", ""), h.get("host", ""),
                    h.get("user-agent", "")[:60], h.get("status", ""),
                ))

    tab_tls = ttk.Frame(nb)
    nb.add(tab_tls, text="TLS")
    _fill_table(tab_tls, parser.get_tls(),
                ["SNI", "Version", "Src IP", "Dst IP", "JA3"],
                lambda t: (
                    t.get("sni", ""), t.get("version", ""),
                    t.get("src_ip", t.get("src", "")),
                    t.get("dst_ip", t.get("dst", "")),
                    t.get("ja3", {}).get("hash", "") if isinstance(t.get("ja3"), dict) else t.get("ja3", ""),
                ))

    tab_ssh = ttk.Frame(nb)
    nb.add(tab_ssh, text="SSH")
    _fill_table(tab_ssh, parser.get_ssh(),
                ["Src IP", "Dst IP", "Client Banner", "Server Banner"],
                lambda s: (
                    s.get("src_ip", ""), s.get("dst_ip", ""),
                    s.get("client", {}).get("banner", ""),
                    s.get("server", {}).get("banner", ""),
                ))

    tab_files = ttk.Frame(nb)
    nb.add(tab_files, text="Files")
    _fill_table(tab_files, parser.get_network_files(),
                ["Path", "SHA256", "URI"],
                lambda f: (
                    f.get("path", f.get("filename", "")),
                    f.get("sha256", ""), f.get("uri", ""),
                ))

    tab_hosts = ttk.Frame(nb)
    nb.add(tab_hosts, text="Hosts")
    _fill_table(tab_hosts, parser.get_hosts(),
                ["IP", "Country", "Ports", "Process"],
                lambda h: (
                    h.get("ip", ""),
                    h.get("country_name", ""),
                    ", ".join(str(p) for p in h.get("ports", [])),
                    h.get("process_name", "") or "",
                ))

    tab_tcp = ttk.Frame(nb)
    nb.add(tab_tcp, text="TCP")
    _fill_table(tab_tcp, parser.get_tcp(),
                ["Src", "Sport", "Dst", "Dport", "Process"],
                lambda t: (
                    t.get("src", ""), t.get("sport", ""),
                    t.get("dst", ""), t.get("dport", ""),
                    t.get("process_name", "") or "",
                ))

    tab_udp = ttk.Frame(nb)
    nb.add(tab_udp, text="UDP")
    _fill_table(tab_udp, parser.get_udp(),
                ["Src", "Sport", "Dst", "Dport", "Process"],
                lambda u: (
                    u.get("src", ""), u.get("sport", ""),
                    u.get("dst", ""), u.get("dport", ""),
                    u.get("process_name", "") or "",
                ))

    tab_dead = ttk.Frame(nb)
    nb.add(tab_dead, text="Dead Hosts")
    _fill_table(tab_dead, parser.get_dead_hosts(),
                ["IP", "Port"],
                lambda d: (
                    (d[0], d[1]) if isinstance(d, list)
                    else (d.get("ip", ""), d.get("port", ""))
                ))


# ── CAPE ──────────────────────────────────────────────────────
def build_cape(parent: ttk.Frame, parser, yara_results: list):
    for w in parent.winfo_children():
        w.destroy()

    payloads = parser.get_cape_payloads()
    configs  = parser.get_cape_configs()

    if not payloads:
        tk.Label(parent,
                 text="추출된 페이로드가 없습니다.\n동적 분석이 수행되지 않았거나 CAPE가 페이로드를 덤프하지 못한 리포트입니다.",
                 bg=BG, fg=FG_DIM, font=FONT_LABEL,
                 justify="center").pack(expand=True)
        return

    tk.Label(parent, text=f"CAPE Payloads — {len(payloads)}개",
             bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=8)

    cols = ["SHA256", "Type", "Size", "YARA Hit", "Config?"]
    tv = scrolled_treeview(parent, cols)
    tv.column("SHA256",   width=280, minwidth=120)
    tv.column("Type",     width=150, minwidth=80)
    tv.column("Size",     width=80,  minwidth=50)
    tv.column("YARA Hit", width=200, minwidth=80)
    tv.column("Config?",  width=60,  minwidth=40)

    yara_map = {r["sha256"]: r["matches"] for r in yara_results}

    for p in payloads:
        sha      = p.get("sha256", "")
        yara_hit = ", ".join(m["rule"] for m in yara_map.get(sha, []))
        has_cfg  = "Yes" if p.get("cape_config") else "No"
        tv.insert("", "end", values=(
            sha, p.get("cape_type", p.get("type", "")),
            p.get("size", ""), yara_hit, has_cfg,
        ))

    # 선택한 페이로드 해시 (클릭 복사)
    hash_lf = tk.LabelFrame(parent, text="선택한 페이로드 해시",
                             bg=BG, fg=ACCENT, font=FONT_LABEL,
                             relief="flat", bd=1, highlightbackground=BG3)
    hash_lf.pack(fill="x", padx=12, pady=(0, 4))
    tk.Label(hash_lf, text="위 목록에서 페이로드를 선택하면 해시를 표시합니다.",
             bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(padx=8, pady=6)

    def _copy(val: str):
        parent.clipboard_clear()
        parent.clipboard_append(val)
        parent.update()

    def _on_select(event):
        sel = tv.selection()
        if not sel:
            return
        sha256  = tv.item(sel[0], "values")[0]
        payload = next((p for p in payloads if p.get("sha256", "") == sha256), None)
        if not payload:
            return
        for w in hash_lf.winfo_children():
            w.destroy()
        for key, label in [("md5","MD5   "),("sha1","SHA1  "),("sha256","SHA256"),("sha512","SHA512")]:
            val = payload.get(key, "")
            if not val:
                continue
            row = ttk.Frame(hash_lf)
            row.pack(fill="x", padx=6, pady=1)
            tk.Label(row, text=label, bg=BG, fg=FG_DIM,
                     font=FONT_MONO, width=8, anchor="w").pack(side="left")
            lbl = tk.Label(row, text=val, bg=BG, fg=FG,
                           font=FONT_MONO, cursor="hand2", anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            lbl.bind("<Button-1>", lambda e, v=val: _copy(v))
            lbl.bind("<Enter>",    lambda e, l=lbl: l.config(fg=ACCENT))
            lbl.bind("<Leave>",    lambda e, l=lbl: l.config(fg=FG))
            tk.Label(row, text="[copy]", bg=BG, fg=FG_DIM,
                     font=FONT_MONO, cursor="hand2").pack(side="left", padx=4)

    tv.bind("<<TreeviewSelect>>", _on_select)

    if configs:
        ttk.Separator(parent, orient="horizontal").pack(fill="x", padx=12, pady=8)
        tk.Label(parent, text=f"Malware Configs — {len(configs)}개",
                 bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=4)
        cfg_text = scrolled_text(parent)
        cfg_text.config(state="normal")
        for cfg in configs:
            cfg_text.insert("end", f"[{cfg['family']}] sha256: {cfg['sha256']}\n")
            cfg_text.insert("end", json.dumps(cfg["config"], ensure_ascii=False, indent=2) + "\n\n")
        cfg_text.config(state="disabled")
    else:
        tk.Label(parent, text="추출된 악성코드 설정값 없음",
                 bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(padx=12, pady=4, anchor="w")


# ── AI 분석 ───────────────────────────────────────────────────
def build_ai(parent: ttk.Frame, parser, config: dict, save_config_cb, store_cb=None):
    from modules import services as _svc

    for w in parent.winfo_children():
        w.destroy()

    status_var = tk.StringVar(value="분석 버튼을 눌러 시작하세요.")
    btn_row = ttk.Frame(parent)
    btn_row.pack(fill="x", padx=12, pady=10)
    tk.Label(btn_row, textvariable=status_var, bg=BG, fg=FG_DIM,
             font=FONT_LABEL).pack(side="left")

    result_text = scrolled_text(parent)
    result_text.config(state="disabled")
    result_text.tag_config("body",  foreground=FG)
    result_text.tag_config("error", foreground=RED)

    def _run():
        api_key = config.get("groq_api_key", "")
        if not api_key:
            status_var.set("[오류] Groq API 키가 없습니다 (.env 확인)")
            return
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        status_var.set("AI 분석 중...")
        summary = parser.get_summary_for_ai()
        try:
            text = _svc.analyze(summary, api_key)
            tag  = "error" if text.startswith("[오류]") else "body"
            result_text.insert("end", text, tag)
            status_var.set("분석 완료.")
            if store_cb and not text.startswith("[오류]"):
                store_cb("AI", text)
        except Exception as e:
            result_text.insert("end", f"[오류] {e}", "error")
            status_var.set("분석 실패.")
        result_text.config(state="disabled")

    ttk.Button(btn_row, text="AI 분석 실행",
               command=lambda: threading.Thread(target=_run, daemon=True).start()
               ).pack(side="right")
