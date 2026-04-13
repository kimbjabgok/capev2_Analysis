"""AI 분석 탭 — Gemini / Claude"""
import tkinter as tk
from tkinter import ttk
import threading

from gui.styles import *
from modules import ai_analysis


def build(parent: ttk.Frame, parser, config: dict, save_config_cb):
    for w in parent.winfo_children():
        w.destroy()

    nb = ttk.Notebook(parent)
    nb.pack(fill="both", expand=True)

    _make_panel(nb, "Groq",   "groq_api_key",   parser, config)
    _make_panel(nb, "Gemini", "gemini_api_key", parser, config)
    _make_panel(nb, "Claude", "claude_api_key", parser, config)


def _make_panel(nb, label: str, key_name: str, parser, config: dict):
    frame = ttk.Frame(nb)
    nb.add(frame, text=label)

    status_var = tk.StringVar(value="분석 버튼을 눌러 시작하세요.")
    btn_row = ttk.Frame(frame)
    btn_row.pack(fill="x", padx=12, pady=10)
    tk.Label(btn_row, textvariable=status_var, bg=BG, fg=FG_DIM,
             font=FONT_LABEL).pack(side="left")

    result_text = scrolled_text(frame)
    result_text.config(state="disabled")
    result_text.tag_config("body",  foreground=FG)
    result_text.tag_config("error", foreground=RED)

    def _run():
        api_key = config.get(key_name, "")
        if not api_key:
            status_var.set(f"[오류] {label} API 키가 없습니다 (.env 확인)")
            return
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        status_var.set(f"{label} 분석 중...")
        summary = parser.get_summary_for_ai()
        try:
            if label == "Gemini":
                text = ai_analysis.analyze_gemini(summary, api_key)
            elif label == "Groq":
                text = ai_analysis.analyze_groq(summary, api_key)
            else:
                text = ai_analysis.analyze_claude(summary, api_key)
            tag = "error" if text.startswith("[오류]") else "body"
            result_text.insert("end", text, tag)
            status_var.set("분석 완료.")
        except Exception as e:
            result_text.insert("end", f"[오류] {e}", "error")
            status_var.set("분석 실패.")
        result_text.config(state="disabled")

    ttk.Button(btn_row, text=f"{label} 분석 실행",
               command=lambda: threading.Thread(target=_run, daemon=True).start()
               ).pack(side="right")
