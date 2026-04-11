"""공통 색상 / 스타일 상수"""
import tkinter as tk
from tkinter import ttk

BG       = "#1e1e2e"
BG2      = "#2a2a3e"
BG3      = "#313145"
FG       = "#cdd6f4"
FG_DIM   = "#6c7086"
ACCENT   = "#89b4fa"
GREEN    = "#a6e3a1"
YELLOW   = "#f9e2af"
ORANGE   = "#fab387"
RED      = "#f38ba8"
CRITICAL = "#ff5555"

SEVERITY_COLOR = {
    "info":     ACCENT,
    "low":      GREEN,
    "medium":   YELLOW,
    "high":     ORANGE,
    "critical": CRITICAL,
}

FONT_MONO  = ("Consolas", 10)
FONT_LABEL = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 12, "bold")
FONT_H1    = ("Segoe UI", 14, "bold")


def apply_theme(root: tk.Tk):
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG, foreground=FG, font=FONT_LABEL,
                    fieldbackground=BG2, bordercolor=BG3, troughcolor=BG2)
    style.configure("TFrame",       background=BG)
    style.configure("TLabel",       background=BG,  foreground=FG)
    style.configure("TButton",      background=BG2, foreground=FG, padding=6)
    style.map("TButton",
              background=[("active", BG3), ("pressed", ACCENT)],
              foreground=[("active", FG)])
    style.configure("TNotebook",    background=BG,  borderwidth=0)
    style.configure("TNotebook.Tab",background=BG2, foreground=FG_DIM,
                    padding=[12, 6])
    style.map("TNotebook.Tab",
              background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])
    style.configure("Treeview",     background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=22)
    style.configure("Treeview.Heading", background=BG3, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
    style.map("Treeview", background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])
    style.configure("TCombobox",    background=BG2, foreground=FG,
                    fieldbackground=BG2, selectbackground=BG3)
    style.configure("TScrollbar",   background=BG2, troughcolor=BG,
                    arrowcolor=FG_DIM)
    style.configure("TEntry",       fieldbackground=BG2, foreground=FG,
                    insertcolor=FG)
    style.configure("TSeparator",   background=BG3)


def scrolled_text(parent, **kw) -> tk.Text:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True, **kw)
    sb = ttk.Scrollbar(frame, orient="vertical")
    sb.pack(side="right", fill="y")
    t = tk.Text(frame, yscrollcommand=sb.set, wrap="word",
                bg=BG2, fg=FG, font=FONT_MONO,
                insertbackground=FG, selectbackground=BG3,
                relief="flat", borderwidth=0)
    t.pack(side="left", fill="both", expand=True)
    sb.config(command=t.yview)
    return t


def scrolled_treeview(parent, columns: list, **kw) -> ttk.Treeview:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True, **kw)
    vsb = ttk.Scrollbar(frame, orient="vertical")
    vsb.pack(side="right", fill="y")
    hsb = ttk.Scrollbar(frame, orient="horizontal")
    hsb.pack(side="bottom", fill="x")
    tv = ttk.Treeview(frame, columns=columns, show="headings",
                      yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tv.pack(fill="both", expand=True)
    vsb.config(command=tv.yview)
    hsb.config(command=tv.xview)
    for col in columns:
        tv.heading(col, text=col)
        tv.column(col, width=150, minwidth=60)
    return tv
