"""ATT&CK 탭"""
import tkinter as tk
from tkinter import ttk
import webbrowser

from gui.styles import *

MITRE_BASE = "https://attack.mitre.org/techniques/"


def build(parent: ttk.Frame, ttps: list):
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
            url = MITRE_BASE + tid.replace(".", "/")
            webbrowser.open(url)

    tv.bind("<Double-1>", _open_mitre)
    tk.Label(parent, text="※ 더블클릭으로 MITRE 페이지 열기",
             bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(anchor="w", padx=12, pady=4)
