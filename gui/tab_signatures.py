"""Signatures 탭"""
import tkinter as tk
from tkinter import ttk

from gui.styles import *

SEVERITIES = ["All", "Info", "Low", "Medium", "High", "Critical"]


def build(parent: ttk.Frame, all_sigs: list):
    for w in parent.winfo_children():
        w.destroy()

    # ── 필터 바 ────────────────────────────────────────────────
    filter_frame = ttk.Frame(parent)
    filter_frame.pack(fill="x", padx=12, pady=8)
    tk.Label(filter_frame, text="Severity Filter:", bg=BG, fg=FG,
             font=FONT_LABEL).pack(side="left")

    sel_var = tk.StringVar(value="All")
    for sev in SEVERITIES:
        color = SEVERITY_COLOR.get(sev.lower(), FG)
        rb = tk.Radiobutton(filter_frame, text=sev, variable=sel_var, value=sev,
                            bg=BG, fg=color, selectcolor=BG2,
                            activebackground=BG, activeforeground=color,
                            font=FONT_LABEL,
                            command=lambda: _refresh())
        rb.pack(side="left", padx=6)

    tk.Label(filter_frame, text=f"  총 {len(all_sigs)}개",
             bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(side="left", padx=10)

    # ── 분할 패널 ──────────────────────────────────────────────
    paned = tk.PanedWindow(parent, orient="horizontal",
                           bg=BG3, sashwidth=4, relief="flat")
    paned.pack(fill="both", expand=True, padx=12, pady=4)

    # 왼쪽: 시그니처 목록
    left = ttk.Frame(paned)
    paned.add(left, width=380)

    cols = ["Severity", "Name"]
    tv = scrolled_treeview(left, cols)
    tv.column("Severity", width=80,  minwidth=60)
    tv.column("Name",     width=280, minwidth=120)

    # 오른쪽: 증거 상세
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

        detail_text.tag_config("title",    foreground=ACCENT,    font=("Consolas", 11, "bold"))
        detail_text.tag_config("sev",      foreground=SEVERITY_COLOR.get(sig.get("severity","").lower(), FG))
        detail_text.tag_config("label",    foreground=FG_DIM)
        detail_text.tag_config("ev",       foreground=YELLOW)
        detail_text.tag_config("ttp_tag",  foreground=GREEN)

        detail_text.insert("end", sig.get("name","") + "\n", "title")
        detail_text.insert("end", f"\n[Severity]  ", "label")
        detail_text.insert("end", sig.get("severity","").upper() + "\n", "sev")
        detail_text.insert("end", f"\n[Description]\n", "label")
        detail_text.insert("end", sig.get("description","") + "\n")

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
        for i, sig in enumerate(all_sigs):
            sev = sig.get("severity", "info").lower()
            if sev_filter != "all" and sev != sev_filter:
                continue
            color = SEVERITY_COLOR.get(sev, FG)
            tag_id = str(len(visible))
            visible.append(sig)
            name = sig.get("name", "")
            tv.insert("", "end", tags=(tag_id,), values=(sev.upper(), name))
            tv.tag_configure(tag_id, foreground=color)

    _refresh()
