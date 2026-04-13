"""AI 분석 탭 — Groq"""
import tkinter as tk
from tkinter import ttk
import threading

from gui.styles import *
from modules import ai_analysis


def build(parent: ttk.Frame, parser, config: dict, save_config_cb, store_cb=None):
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
        status_var.set("Groq 분석 중...")
        summary = parser.get_summary_for_ai()
        try:
            text = ai_analysis.analyze(summary, api_key)
            tag = "error" if text.startswith("[오류]") else "body"
            result_text.insert("end", text, tag)
            status_var.set("분석 완료.")
            if store_cb and not text.startswith("[오류]"):
                store_cb("Groq", text)
        except Exception as e:
            result_text.insert("end", f"[오류] {e}", "error")
            status_var.set("분석 실패.")
        result_text.config(state="disabled")

    ttk.Button(btn_row, text="Groq 분석 실행",
               command=lambda: threading.Thread(target=_run, daemon=True).start()
               ).pack(side="right")
