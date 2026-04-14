"""CAPE 탭 — 페이로드 해시 + 악성코드 설정값"""
import tkinter as tk
from tkinter import ttk
import json

from gui.styles import *


def build(parent: ttk.Frame, parser, yara_results: list):
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

    # ── 페이로드 목록 ──────────────────────────────────────────
    cols = ["SHA256", "Type", "Size", "YARA Hit", "Config?"]
    tv = scrolled_treeview(parent, cols)
    tv.column("SHA256",   width=280, minwidth=120)
    tv.column("Type",     width=150, minwidth=80)
    tv.column("Size",     width=80,  minwidth=50)
    tv.column("YARA Hit", width=200, minwidth=80)
    tv.column("Config?",  width=60,  minwidth=40)

    yara_map = {r["sha256"]: r["matches"] for r in yara_results}

    for p in payloads:
        sha = p.get("sha256", "")
        yara_hit = ", ".join(m["rule"] for m in yara_map.get(sha, []))
        has_cfg  = "Yes" if p.get("cape_config") else "No"
        tv.insert("", "end", values=(
            sha,
            p.get("cape_type", p.get("type", "")),
            p.get("size", ""),
            yara_hit,
            has_cfg,
        ))

    # ── 선택한 페이로드 해시 (클릭 복사) ──────────────────────────
    hash_lf = tk.LabelFrame(parent, text="선택한 페이로드 해시",
                             bg=BG, fg=ACCENT, font=FONT_LABEL,
                             relief="flat", bd=1, highlightbackground=BG3)
    hash_lf.pack(fill="x", padx=12, pady=(0, 4))

    hint_lbl = tk.Label(hash_lf, text="위 목록에서 페이로드를 선택하면 해시를 표시합니다.",
                        bg=BG, fg=FG_DIM, font=FONT_LABEL)
    hint_lbl.pack(padx=8, pady=6)

    def _copy(val: str):
        parent.clipboard_clear()
        parent.clipboard_append(val)
        parent.update()

    def _on_select(event):
        sel = tv.selection()
        if not sel:
            return
        sha256 = tv.item(sel[0], "values")[0]
        payload = next((p for p in payloads if p.get("sha256", "") == sha256), None)
        if not payload:
            return

        for w in hash_lf.winfo_children():
            w.destroy()

        hash_keys = [
            ("md5",    "MD5   "),
            ("sha1",   "SHA1  "),
            ("sha256", "SHA256"),
            ("sha512", "SHA512"),
        ]
        for key, label in hash_keys:
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

    # ── 악성코드 설정값 ────────────────────────────────────────
    if configs:
        ttk.Separator(parent, orient="horizontal").pack(fill="x", padx=12, pady=8)
        tk.Label(parent, text=f"Malware Configs — {len(configs)}개",
                 bg=BG, fg=ACCENT, font=FONT_TITLE).pack(anchor="w", padx=12, pady=4)

        cfg_text = scrolled_text(parent)
        cfg_text.config(state="normal")
        for cfg in configs:
            cfg_text.insert("end", f"[{cfg['family']}] sha256: {cfg['sha256']}\n", )
            cfg_text.insert("end", json.dumps(cfg["config"], ensure_ascii=False, indent=2) + "\n\n")
        cfg_text.config(state="disabled")
    else:
        tk.Label(parent, text="추출된 악성코드 설정값 없음",
                 bg=BG, fg=FG_DIM, font=FONT_LABEL).pack(padx=12, pady=4, anchor="w")
