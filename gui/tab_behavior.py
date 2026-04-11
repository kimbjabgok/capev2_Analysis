"""Behavior 탭 — 프로세스별 API 호출"""
import tkinter as tk
from tkinter import ttk

from gui.styles import *


def build(parent: ttk.Frame, api_calls: list):
    for w in parent.winfo_children():
        w.destroy()

    total = len(api_calls)
    tk.Label(parent, text=f"API Calls — {total}개 (최대 1,000개/프로세스)",
             bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=6)

    # 프로세스 목록 추출
    procs = {}
    for c in api_calls:
        key = f"{c['process']} (PID {c['pid']})"
        procs.setdefault(key, []).append(c)

    # 프로세스 선택 콤보
    top = ttk.Frame(parent)
    top.pack(fill="x", padx=12, pady=4)
    tk.Label(top, text="Process:", bg=BG, fg=FG, font=FONT_LABEL).pack(side="left")

    proc_list = ["All"] + list(procs.keys())
    sel_var = tk.StringVar(value="All")
    combo = ttk.Combobox(top, textvariable=sel_var, values=proc_list,
                         width=50, state="readonly")
    combo.pack(side="left", padx=8)

    # 검색
    tk.Label(top, text="Filter:", bg=BG, fg=FG, font=FONT_LABEL).pack(side="left", padx=(16, 4))
    search_var = tk.StringVar()
    search_entry = ttk.Entry(top, textvariable=search_var, width=30)
    search_entry.pack(side="left")

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
            if count >= 2000:  # 화면 성능 보호
                break

    combo.bind("<<ComboboxSelected>>", _refresh)
    search_var.trace_add("write", _refresh)
    _refresh()
