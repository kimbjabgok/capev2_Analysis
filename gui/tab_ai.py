"""AI 분석 탭"""
import tkinter as tk
from tkinter import ttk
import threading

from gui.styles import *
from modules import ai_analysis


def build(parent: ttk.Frame, parser, config: dict, save_config_cb):
    for w in parent.winfo_children():
        w.destroy()

    # ── 설정 영역 ──────────────────────────────────────────────
    cfg_frame = ttk.Frame(parent)
    cfg_frame.pack(fill="x", padx=12, pady=8)

    # Provider 선택
    tk.Label(cfg_frame, text="AI Provider:", bg=BG, fg=FG,
             font=FONT_LABEL).grid(row=0, column=0, sticky="w", pady=4)
    provider_var = tk.StringVar(value=config.get("ai_provider", "claude"))
    for i, p in enumerate(["claude", "gemini"]):
        tk.Radiobutton(cfg_frame, text=p.capitalize(), variable=provider_var, value=p,
                       bg=BG, fg=FG, selectcolor=BG2,
                       activebackground=BG, font=FONT_LABEL).grid(row=0, column=i+1, padx=8)

    # API 키 입력
    tk.Label(cfg_frame, text="API Key:", bg=BG, fg=FG,
             font=FONT_LABEL).grid(row=1, column=0, sticky="w", pady=4)
    key_var = tk.StringVar(value=config.get("ai_api_key", ""))
    key_entry = ttk.Entry(cfg_frame, textvariable=key_var, width=60, show="*")
    key_entry.grid(row=1, column=1, columnspan=3, sticky="ew", padx=4)

    show_var = tk.BooleanVar()
    def _toggle_show():
        key_entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(cfg_frame, text="표시", variable=show_var, command=_toggle_show,
                   bg=BG, fg=FG, selectcolor=BG2,
                   activebackground=BG, font=FONT_LABEL).grid(row=1, column=4, padx=4)

    def _save_key():
        config["ai_api_key"]  = key_var.get().strip()
        config["ai_provider"] = provider_var.get()
        save_config_cb(config)
        tk.messagebox.showinfo("저장", "API 키가 저장되었습니다.")

    ttk.Button(cfg_frame, text="키 저장", command=_save_key).grid(row=1, column=5, padx=8)

    ttk.Separator(parent, orient="horizontal").pack(fill="x", padx=12, pady=4)

    # ── 분석 결과 영역 ─────────────────────────────────────────
    btn_frame = ttk.Frame(parent)
    btn_frame.pack(fill="x", padx=12, pady=4)

    status_var = tk.StringVar(value="분석 버튼을 눌러 시작하세요.")
    tk.Label(btn_frame, textvariable=status_var, bg=BG, fg=FG_DIM,
             font=FONT_LABEL).pack(side="left")

    result_text = scrolled_text(parent)
    result_text.config(state="disabled")

    result_text.tag_config("h2",    foreground=ACCENT,   font=("Consolas", 11, "bold"))
    result_text.tag_config("body",  foreground=FG)
    result_text.tag_config("error", foreground=RED)

    def _do_analysis():
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        status_var.set("분석 중...")
        api_key  = key_var.get().strip() or config.get("ai_api_key", "")
        provider = provider_var.get()
        summary  = parser.get_summary_for_ai()
        try:
            text = ai_analysis.analyze(summary, provider, api_key)
            result_text.insert("end", text, "body")
        except Exception as e:
            result_text.insert("end", f"[오류] {e}", "error")
        status_var.set("분석 완료.")
        result_text.config(state="disabled")

    ttk.Button(btn_frame, text="AI 분석 실행",
               command=lambda: threading.Thread(target=_do_analysis, daemon=True).start()
               ).pack(side="right")

    from tkinter import messagebox
