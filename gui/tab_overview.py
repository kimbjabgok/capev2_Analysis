"""Overview 탭"""
import tkinter as tk
from tkinter import ttk
import threading
import webbrowser

from gui.styles import *
from modules import vt_api as VT


def build(parent: ttk.Frame, parser, config: dict, refresh_vt_cb=None):
    for w in parent.winfo_children():
        w.destroy()

    hashes   = parser.get_hashes()
    verdict  = parser.get_verdict()
    score    = verdict["score"]
    families = verdict["families"]
    pe       = parser.get_pe()
    yara_m   = parser.get_yara_matches()

    # ── 위협 판정 배지 ─────────────────────────────────────────
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

    # ── 해시 (클릭 복사) ───────────────────────────────────────
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

    # ── VirusTotal ─────────────────────────────────────────────
    vt_frame = tk.LabelFrame(parent, text="VirusTotal",
                              bg=BG, fg=ACCENT, font=FONT_LABEL,
                              relief="flat", bd=1, highlightbackground=BG3)
    vt_frame.pack(fill="x", padx=12, pady=4)

    vt_info_var = tk.StringVar(value="— (API 키 필요)")
    vt_lbl = tk.Label(vt_frame, textvariable=vt_info_var,
                      bg=BG, fg=FG, font=FONT_MONO)
    vt_lbl.pack(side="left", padx=8, pady=4)

    sha256 = hashes.get("sha256", "")

    def _do_vt_lookup():
        api_key = config.get("vt_api_key", "")
        if not api_key:
            vt_info_var.set("VirusTotal API 키를 도구 메뉴 → 설정에서 입력하세요.")
            return
        vt_info_var.set("조회 중...")
        result = VT.lookup_hash(sha256, api_key)
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

    btn = ttk.Button(vt_frame, text="VT 조회", command=lambda: threading.Thread(target=_do_vt_lookup, daemon=True).start())
    btn.pack(side="left", padx=6, pady=4)

    # ── PE 섹션 ────────────────────────────────────────────────
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
                hex(s.get("virtual_address", 0)),
                s.get("size_of_raw_data", ""),
                f"{s.get('entropy', 0):.2f}",
            ))

    # ── PE Imports ─────────────────────────────────────────────
    pe_imports = parser.get_pe_imports()
    if pe_imports:
        imp_lf = tk.LabelFrame(parent, text="PE Imports",
                                bg=BG, fg=ACCENT, font=FONT_LABEL,
                                relief="flat", bd=1, highlightbackground=BG3)
        imp_lf.pack(fill="x", padx=12, pady=4)
        cols2 = ["DLL", "Functions"]
        tv2 = scrolled_treeview(imp_lf, cols2)
        tv2.pack(fill="x", padx=4, pady=4)
        for imp in pe_imports[:50]:
            dll  = imp.get("dll", "")
            fns  = ", ".join(i.get("name", "") for i in imp.get("imports", [])[:10])
            tv2.insert("", "end", values=(dll, fns))

    # ── YARA Matches ───────────────────────────────────────────
    if yara_m:
        yara_lf = tk.LabelFrame(parent, text="YARA Matches",
                                 bg=BG, fg=ACCENT, font=FONT_LABEL,
                                 relief="flat", bd=1, highlightbackground=BG3)
        yara_lf.pack(fill="x", padx=12, pady=4)
        for m in yara_m:
            tk.Label(yara_lf, text=f"  • {m.get('name', m)}",
                     bg=BG, fg=YELLOW, font=FONT_MONO).pack(anchor="w", padx=6)
