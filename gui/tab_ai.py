"""AI 분석 탭 — Gemini 전용"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading

from gui.styles import *
from modules import ai_analysis


def build(parent: ttk.Frame, parser, config: dict, save_config_cb):
    for w in parent.winfo_children():
        w.destroy()

    # ── 분석 버튼 영역 ─────────────────────────────────────────
    btn_frame = ttk.Frame(parent)
    btn_frame.pack(fill="x", padx=12, pady=10)

    status_var = tk.StringVar(value="분석 버튼을 눌러 시작하세요.")
    tk.Label(btn_frame, textvariable=status_var, bg=BG, fg=FG_DIM,
             font=FONT_LABEL).pack(side="left")

    result_text = scrolled_text(parent)
    result_text.config(state="disabled")
    result_text.tag_config("body",  foreground=FG)
    result_text.tag_config("error", foreground=RED)

    def _do_analysis():
        api_key = config.get("ai_api_key", "")
        if not api_key:
            status_var.set("API 키 없음 — .env의 GEMINI_API_KEY를 확인하세요.")
            return
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        status_var.set("Gemini 분석 중...")
        summary = parser.get_summary_for_ai()
        try:
            text = ai_analysis.analyze_gemini(summary, api_key)
            tag = "error" if text.startswith("[오류]") else "body"
            result_text.insert("end", text, tag)
            status_var.set("분석 완료.")
        except Exception as e:
            result_text.insert("end", f"[오류] {e}", "error")
            status_var.set("분석 실패.")
        result_text.config(state="disabled")

    ttk.Button(btn_frame, text="Gemini 분석 실행",
               command=lambda: threading.Thread(target=_do_analysis, daemon=True).start()
               ).pack(side="right")
