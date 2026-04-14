"""메인 애플리케이션 윈도우"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
import os
import sys
import tempfile
import webbrowser
from pathlib import Path

from gui.styles import (apply_theme, BG, BG2, BG3, FG, ACCENT, FG_DIM,
                        FONT_TITLE, FONT_LABEL, RED, GREEN, YELLOW, ORANGE)
from gui import tab_overview, tab_signatures, tab_attack, tab_behavior, tab_cape, tab_ai
from modules.parser import ReportParser, load_report
from modules import signatures as sig_engine, yara_engine, whitenoise, html_export, pdf_export

CONFIG_PATH = Path(os.environ.get("APPDATA", ".")) / "CAPEv2Analyzer" / "config.json"

_DARK_HDR = "#0f0f1a"
_BORDER   = "#313244"


# ── Config helpers ─────────────────────────────────────────
def load_config() -> dict:
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text("utf-8"))
        except Exception:
            pass
    if not cfg.get("groq_api_key"):
        cfg["groq_api_key"] = os.environ.get("GROQ_API_KEY", "")
    if not cfg.get("vt_api_key"):
        cfg["vt_api_key"] = os.environ.get("VT_API_KEY", "")
    return cfg


def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")


# ── Custom button factory ──────────────────────────────────
def _btn(parent, text, command, bg=BG3, fg=FG,
         hover_bg=ACCENT, hover_fg=BG,
         pad_x=14, pad_y=6, state="normal", font=("Segoe UI", 9)):
    b = tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg,
        activebackground=hover_bg, activeforeground=hover_fg,
        font=font, relief="flat", borderwidth=0,
        padx=pad_x, pady=pad_y, cursor="hand2", state=state,
    )

    def _enter(e):
        if str(b["state"]) != "disabled":
            b.config(bg=hover_bg, fg=hover_fg)

    def _leave(e):
        if str(b["state"]) != "disabled":
            b.config(bg=bg, fg=fg)

    b.bind("<Enter>", _enter)
    b.bind("<Leave>", _leave)
    return b


# ── Main App ───────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self, initial_file: str = None):
        super().__init__()
        self.title("CAPEv2 Report Analyzer")
        self.geometry("1280x820")
        self.minsize(960, 640)
        apply_theme(self)

        self.config_data  = load_config()
        self.parser       = None
        self.all_sigs     = []
        self.report_path  = None
        self._ai_results  = {}
        self._loading     = False
        self._loading_dots = 0

        self._build_menu()
        self._build_header()
        self._build_toolbar()
        self._build_verdict_strip()
        self._build_notebook()
        self._build_statusbar()
        self._setup_dnd()

        if initial_file:
            self.after(200, lambda: self._open_file(initial_file))
        else:
            self.after(400, self._check_first_run)

    # ── 메뉴 ──────────────────────────────────────────────────
    def _build_menu(self):
        menubar = tk.Menu(self, bg=BG2, fg=FG,
                          activebackground=ACCENT, activeforeground=BG,
                          relief="flat", borderwidth=0)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=False, bg=BG2, fg=FG,
                            activebackground=ACCENT, activeforeground=BG)
        file_menu.add_command(label="리포트 열기  (Ctrl+O)", command=self._browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="종료", command=self.destroy)
        menubar.add_cascade(label="파일", menu=file_menu)

        tool_menu = tk.Menu(menubar, tearoff=False, bg=BG2, fg=FG,
                            activebackground=ACCENT, activeforeground=BG)
        tool_menu.add_command(label="설정", command=self._open_settings)
        menubar.add_cascade(label="도구", menu=tool_menu)

        self.bind("<Control-o>", lambda e: self._browse_file())

    # ── 헤더 바 (브랜딩) ────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=_DARK_HDR, height=46)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="CAPE", bg=_DARK_HDR, fg=ACCENT,
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=(18, 0), pady=10)
        tk.Label(hdr, text="v2 Report Analyzer", bg=_DARK_HDR, fg=FG_DIM,
                 font=("Segoe UI", 10)).pack(side="left", padx=(4, 0), pady=10)

        settings_btn = tk.Button(
            hdr, text="⚙  설정", command=self._open_settings,
            bg=_DARK_HDR, fg=FG_DIM,
            activebackground=BG2, activeforeground=FG,
            font=("Segoe UI", 9), relief="flat", borderwidth=0,
            padx=14, pady=0, cursor="hand2",
        )
        settings_btn.pack(side="right", padx=10)
        settings_btn.bind("<Enter>", lambda e: settings_btn.config(fg=ACCENT))
        settings_btn.bind("<Leave>", lambda e: settings_btn.config(fg=FG_DIM))

        tk.Frame(self, bg=_BORDER, height=1).pack(fill="x")

    # ── 툴바 ──────────────────────────────────────────────────
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG2, height=50)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        open_btn = _btn(bar, "열기", self._browse_file,
                        bg=ACCENT, fg=_DARK_HDR,
                        hover_bg=FG, hover_fg=_DARK_HDR,
                        font=("Segoe UI", 9, "bold"), pad_x=16, pad_y=6)
        open_btn.pack(side="left", padx=(14, 8), pady=10)

        tk.Frame(bar, bg=_BORDER, width=1).pack(side="left", fill="y", pady=10)

        self.path_label = tk.Label(
            bar, text="JSON 리포트 파일을 열거나 드래그하세요.",
            bg=BG2, fg=FG_DIM, font=("Segoe UI", 9),
        )
        self.path_label.pack(side="left", padx=14)

        self.loading_label = tk.Label(bar, text="", bg=BG2, fg=ACCENT,
                                      font=("Segoe UI", 9, "italic"))
        self.loading_label.pack(side="right", padx=10)

        self.pdf_btn = _btn(bar, "PDF 내보내기", self._export_pdf,
                            bg=BG3, fg=FG_DIM,
                            hover_bg=ACCENT, hover_fg=BG,
                            state="disabled")
        self.pdf_btn.pack(side="right", padx=(4, 14), pady=10)

        self.export_btn = _btn(bar, "HTML 내보내기", self._export_html,
                               bg=BG3, fg=FG_DIM,
                               hover_bg=ACCENT, hover_fg=BG,
                               state="disabled")
        self.export_btn.pack(side="right", padx=4, pady=10)

        self.browser_btn = _btn(bar, "🌐 브라우저로 보기", self._open_in_browser,
                                bg=ACCENT, fg=_DARK_HDR,
                                hover_bg=FG, hover_fg=_DARK_HDR,
                                font=("Segoe UI", 9, "bold"),
                                state="disabled")
        self.browser_btn.pack(side="right", padx=4, pady=10)

        tk.Frame(self, bg=_BORDER, height=1).pack(fill="x")

    # ── 판정 배너 ─────────────────────────────────────────────
    def _build_verdict_strip(self):
        self._verdict_frame = tk.Frame(self, height=0)
        self._verdict_frame.pack(fill="x")
        self._verdict_frame.pack_propagate(False)

    def _show_verdict(self, score: int, label: str, families: list):
        _colors = {"MALICIOUS": RED, "SUSPICIOUS": ORANGE, "CLEAN": GREEN}
        _labels = {"MALICIOUS": "MALICIOUS  —  악성", "SUSPICIOUS": "SUSPICIOUS  —  의심", "CLEAN": "CLEAN  —  정상"}
        bg = _colors.get(label, ACCENT)

        for w in self._verdict_frame.winfo_children():
            w.destroy()
        self._verdict_frame.config(height=36, bg=bg)

        fam_str = f"   |   패밀리: {', '.join(families)}" if families else ""
        tk.Label(
            self._verdict_frame,
            text=f"  {_labels.get(label, label)}   |   위협 점수: {score} / 10{fam_str}",
            bg=bg, fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=12, pady=6)

    def _hide_verdict(self):
        for w in self._verdict_frame.winfo_children():
            w.destroy()
        self._verdict_frame.config(height=0)

    # ── 노트북 탭 ──────────────────────────────────────────────
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        self.frames = {}
        tab_names = ["Overview", "Signatures", "ATT&CK",
                     "Behavior", "CAPE", "AI 분석"]
        for name in tab_names:
            f = ttk.Frame(self.nb)
            self.nb.add(f, text=f"  {name}  ")
            self.frames[name] = f

        for name, frame in self.frames.items():
            tk.Label(frame, text="리포트 파일을 열어주세요.",
                     bg=BG, fg=FG_DIM, font=FONT_TITLE).pack(expand=True)

    # ── 상태바 ────────────────────────────────────────────────
    def _build_statusbar(self):
        tk.Frame(self, bg=_BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self, bg=_DARK_HDR, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status_var = tk.StringVar(value="준비")
        tk.Label(bar, textvariable=self.status_var,
                 bg=_DARK_HDR, fg=FG_DIM, font=("Segoe UI", 8)).pack(side="left", padx=12)

        self.stat_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.stat_var,
                 bg=_DARK_HDR, fg=FG_DIM, font=("Segoe UI", 8)).pack(side="right", padx=12)

    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.update_idletasks()

    # ── DnD ──────────────────────────────────────────────────
    def _setup_dnd(self):
        try:
            from tkinterdnd2 import DND_FILES
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)
        except ImportError:
            pass

    def _on_drop(self, event):
        path = event.data.strip("{}")
        if path.endswith(".json"):
            self._open_file(path)

    # ── 파일 열기 ─────────────────────────────────────────────
    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="CAPEv2 리포트 선택",
            filetypes=[("JSON 리포트", "*.json"), ("모든 파일", "*.*")]
        )
        if path:
            self._open_file(path)

    def _open_file(self, path: str):
        self._hide_verdict()
        self._set_status(f"로딩 중: {path}")
        self._start_loading()

        def _load():
            try:
                data   = load_report(path)
                parser = ReportParser(data)

                yara_results = yara_engine.scan_report_payloads(data)

                wn = whitenoise.load_filter()

                parser.set_whitenoise_filter(wn)

                custom_sigs = sig_engine.run_all(data)
                custom_sigs = whitenoise.filter_signatures(custom_sigs, wn)
                parser.set_custom_sigs(custom_sigs)

                all_sigs = whitenoise.filter_signatures(parser.get_signatures(), wn)

                self.report_path = path
                self.parser      = parser
                self.all_sigs    = all_sigs
                self._raw_data   = data
                self._yara_res   = yara_results

                self.after(0, lambda: self._populate_tabs(parser, all_sigs, yara_results))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("오류", str(e)))
                self.after(0, lambda: self._set_status("로드 실패"))
                self.after(0, self._stop_loading)

        threading.Thread(target=_load, daemon=True).start()

    # ── 로딩 애니메이션 ─────────────────────────────────────────
    def _start_loading(self):
        self._loading = True
        self._loading_dots = 0
        self._animate_loading()

    def _animate_loading(self):
        if not self._loading:
            return
        self.loading_label.config(text="분석 중" + "." * (self._loading_dots % 4))
        self._loading_dots += 1
        self.after(400, self._animate_loading)

    def _stop_loading(self):
        self._loading = False
        self.loading_label.config(text="")

    # ── 탭 데이터 채우기 ─────────────────────────────────────────
    def _populate_tabs(self, parser: ReportParser, all_sigs: list, yara_results: list):
        self._stop_loading()

        name = Path(self.report_path).name
        self.path_label.config(text=f"  {name}", fg=FG)
        self.title(f"CAPEv2 Report Analyzer — {name}")

        # Verdict 배너
        verdict  = parser.get_verdict()
        score    = verdict["score"]
        families = verdict["families"]
        if   score >= 7: v_label = "MALICIOUS"
        elif score >= 4: v_label = "SUSPICIOUS"
        else:            v_label = "CLEAN"
        self._show_verdict(score, v_label, families)

        # Scrollable wrapper
        def scrollable(parent):
            canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
            vsb    = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)
            inner  = ttk.Frame(canvas)
            win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))
            inner.bind("<Configure>", lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")))
            canvas.bind_all("<MouseWheel>",
                            lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            return inner

        errors = []

        def safe_build(tab_name, fn, *args):
            try:
                fn(*args)
            except Exception as e:
                import traceback
                errors.append(f"[{tab_name}] {e}\n{traceback.format_exc()}")
                f = self.frames[tab_name]
                for w in f.winfo_children():
                    w.destroy()
                tk.Label(f, text=f"[오류] {e}", bg=BG, fg=RED,
                         font=FONT_LABEL, wraplength=800,
                         justify="left").pack(padx=12, pady=12, anchor="w")

        # Overview
        f = self.frames["Overview"]
        for w in f.winfo_children():
            w.destroy()
        try:
            inner = scrollable(f)
            tab_overview.build(inner, parser, self.config_data)
        except Exception as e:
            import traceback
            errors.append(f"[Overview] {e}\n{traceback.format_exc()}")
            tk.Label(f, text=f"[오류] {e}", bg=BG, fg=RED,
                     font=FONT_LABEL, wraplength=800).pack(padx=12, pady=12, anchor="w")

        safe_build("Signatures", tab_signatures.build, self.frames["Signatures"], all_sigs)

        ttps = parser.get_ttps()
        safe_build("ATT&CK", tab_attack.build, self.frames["ATT&CK"], ttps)

        wn = whitenoise.load_filter()
        api_calls = whitenoise.filter_api_calls(parser.get_api_calls(), wn)
        safe_build("Behavior", tab_behavior.build, self.frames["Behavior"], api_calls)

        safe_build("CAPE", tab_cape.build, self.frames["CAPE"], parser, yara_results)

        self._ai_results = {}
        def _store_ai(provider, text):
            self._ai_results[provider] = text
        safe_build("AI 분석", tab_ai.build, self.frames["AI 분석"],
                   parser, self.config_data, save_config, _store_ai)

        # 내보내기 버튼 활성화
        self.export_btn.config(state="normal", fg=FG, bg=BG3)
        self.pdf_btn.config(state="normal", fg=FG, bg=BG3)
        self.browser_btn.config(state="normal")

        # 브라우저 자동 오픈
        self._open_in_browser()

        self.stat_var.set(f"시그니처 {len(all_sigs)}개  |  점수 {score}/10")
        if errors:
            self._set_status(f"로드 완료 (탭 오류 {len(errors)}개)")
            print("\n".join(errors))
        else:
            self._set_status(f"로드 완료 — {name}")

    # ── 브라우저로 보기 ────────────────────────────────────────
    def _open_in_browser(self):
        if not self.parser:
            return
        try:
            ai_text = "\n\n".join(
                f"## {p}\n{t}" for p, t in self._ai_results.items()
            )
            html_str = html_export.generate(self.parser, self.all_sigs, ai_text)
            tmp = Path(tempfile.gettempdir()) / "cape_report_preview.html"
            tmp.write_text(html_str, encoding="utf-8")
            webbrowser.open(tmp.as_uri())
        except Exception as e:
            messagebox.showerror("오류", str(e))

    # ── PDF 내보내기 ───────────────────────────────────────────
    def _export_pdf(self):
        if not self.parser:
            return
        import webbrowser
        sha = self.parser.get_hashes().get("sha256", "report")[:16]
        path = filedialog.asksaveasfilename(
            title="PDF 저장",
            defaultextension=".pdf",
            initialfile=f"cape_report_{sha}.pdf",
            filetypes=[("PDF 파일", "*.pdf"), ("모든 파일", "*.*")],
        )
        if not path:
            return
        try:
            ai_text = "\n\n".join(
                f"## {p}\n{t}" for p, t in self._ai_results.items()
            )
            pdf_export.generate(self.parser, self.all_sigs, ai_text, path)
            webbrowser.open(f"file:///{os.path.abspath(path)}")
            self._set_status(f"PDF 저장 완료: {path}")
        except Exception as e:
            messagebox.showerror("PDF 내보내기 오류", str(e))

    # ── HTML 내보내기 ──────────────────────────────────────────
    def _export_html(self):
        if not self.parser:
            return
        import webbrowser
        sha = self.parser.get_hashes().get("sha256", "report")[:16]
        path = filedialog.asksaveasfilename(
            title="HTML 저장",
            defaultextension=".html",
            initialfile=f"cape_report_{sha}.html",
            filetypes=[("HTML 파일", "*.html"), ("모든 파일", "*.*")],
        )
        if not path:
            return
        try:
            ai_text = "\n\n".join(
                f"### {p}\n{t}" for p, t in self._ai_results.items()
            )
            html_str = html_export.generate(self.parser, self.all_sigs, ai_text)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_str)
            webbrowser.open(f"file:///{os.path.abspath(path)}")
            self._set_status(f"HTML 저장 완료: {path}")
        except Exception as e:
            messagebox.showerror("내보내기 오류", str(e))

    # ── 첫 실행 감지 ──────────────────────────────────────────
    def _check_first_run(self):
        missing = not self.config_data.get("groq_api_key") and \
                  not self.config_data.get("vt_api_key")
        if not missing:
            return

        # 안내 배너 표시
        bar = tk.Frame(self, bg="#2d2250", height=36)
        bar.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        tk.Label(bar, text="⚙  API 키가 설정되지 않았습니다. AI 분석 및 VirusTotal 기능을 사용하려면 설정을 완료하세요.",
                 bg="#2d2250", fg="#cba6f7",
                 font=("Segoe UI", 9)).pack(side="left", padx=14, pady=8)

        def _open_and_close():
            bar.destroy()
            self._open_settings()

        tk.Button(bar, text="지금 설정", command=_open_and_close,
                  bg="#cba6f7", fg="#1e1e2e",
                  font=("Segoe UI", 9, "bold"), relief="flat",
                  padx=10, pady=2, cursor="hand2").pack(side="left", padx=4)

        tk.Button(bar, text="✕", command=bar.destroy,
                  bg="#2d2250", fg="#6c7086",
                  font=("Segoe UI", 9), relief="flat",
                  padx=8, pady=0, cursor="hand2").pack(side="right", padx=8)

    # ── 설정 창 ───────────────────────────────────────────────
    def _open_settings(self):
        win = tk.Toplevel(self)
        win.title("설정")
        win.geometry("500x260")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()
        win.transient(self)

        # 헤더
        hdr = tk.Frame(win, bg=BG2, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="설정", bg=BG2, fg=FG,
                 font=("Segoe UI", 11, "bold")).pack(side="left", padx=18, pady=14)
        tk.Frame(win, bg=_BORDER, height=1).pack(fill="x")

        # 입력 영역
        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=20)

        entries = []

        def row(label_text, key, show=False):
            fr = tk.Frame(body, bg=BG)
            fr.pack(fill="x", pady=7)
            tk.Label(fr, text=label_text, bg=BG, fg=FG_DIM,
                     font=("Segoe UI", 9), width=22, anchor="w").pack(side="left")
            var = tk.StringVar(value=self.config_data.get(key, ""))
            ent = ttk.Entry(fr, textvariable=var, width=32,
                            show="*" if show else "")
            ent.pack(side="left", fill="x", expand=True)
            entries.append((var, key))

        row("VirusTotal API Key", "vt_api_key",   show=True)
        row("Groq API Key",       "groq_api_key", show=True)

        # 하단 버튼 바
        tk.Frame(win, bg=_BORDER, height=1).pack(fill="x")
        btn_bar = tk.Frame(win, bg=BG2, height=50)
        btn_bar.pack(fill="x")
        btn_bar.pack_propagate(False)

        def _save():
            for var, key in entries:
                self.config_data[key] = var.get().strip()
            save_config(self.config_data)
            messagebox.showinfo("설정", "저장되었습니다.", parent=win)
            win.destroy()

        save_btn = _btn(btn_bar, "저장", _save,
                        bg=ACCENT, fg=_DARK_HDR,
                        hover_bg=FG, hover_fg=_DARK_HDR,
                        font=("Segoe UI", 9, "bold"), pad_x=18, pad_y=6)
        save_btn.pack(side="right", padx=16, pady=10)

        cancel_btn = _btn(btn_bar, "취소", win.destroy, pad_x=14, pad_y=6)
        cancel_btn.pack(side="right", padx=4, pady=10)
