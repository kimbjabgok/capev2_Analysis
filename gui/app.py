"""메인 애플리케이션 윈도우"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
import os
import sys
from pathlib import Path

from gui.styles import apply_theme, BG, BG2, BG3, FG, ACCENT, FG_DIM, FONT_TITLE, FONT_LABEL, RED, GREEN, YELLOW
from gui import tab_overview, tab_signatures, tab_attack, tab_behavior, tab_cape, tab_ai
from modules.parser import ReportParser, load_report
from modules import signatures as sig_engine, yara_engine, discord_alert, whitenoise

CONFIG_PATH = Path(os.environ.get("APPDATA", ".")) / "CAPEv2Analyzer" / "config.json"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text("utf-8"))
        except Exception:
            pass
    return {}


def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")


class App(tk.Tk):
    def __init__(self, initial_file: str = None):
        super().__init__()
        self.title("CAPEv2 Report Analyzer")
        self.geometry("1280x800")
        self.minsize(900, 600)
        apply_theme(self)

        self.config_data = load_config()
        self.parser      = None
        self.all_sigs    = []
        self.report_path = None

        self._build_menu()
        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()
        self._setup_dnd()

        if initial_file:
            self.after(200, lambda: self._open_file(initial_file))

    # ── 메뉴 ──────────────────────────────────────────────────
    def _build_menu(self):
        menubar = tk.Menu(self, bg=BG2, fg=FG, activebackground=BG3,
                          activeforeground=ACCENT, relief="flat")
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=False, bg=BG2, fg=FG,
                            activebackground=BG3, activeforeground=ACCENT)
        file_menu.add_command(label="리포트 열기  (Ctrl+O)", command=self._browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="종료", command=self.destroy)
        menubar.add_cascade(label="파일", menu=file_menu)

        tool_menu = tk.Menu(menubar, tearoff=False, bg=BG2, fg=FG,
                            activebackground=BG3, activeforeground=ACCENT)
        tool_menu.add_command(label="설정", command=self._open_settings)
        menubar.add_cascade(label="도구", menu=tool_menu)

        self.bind("<Control-o>", lambda e: self._browse_file())

    # ── 툴바 ──────────────────────────────────────────────────
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG2, height=40)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        ttk.Button(bar, text="리포트 열기", command=self._browse_file).pack(
            side="left", padx=8, pady=4)

        self.path_label = tk.Label(bar, text="파일을 드래그하거나 열기 버튼을 누르세요.",
                                   bg=BG2, fg=FG_DIM, font=FONT_LABEL)
        self.path_label.pack(side="left", padx=8)

        self.discord_btn = ttk.Button(bar, text="Discord 알림 전송",
                                      command=self._send_discord, state="disabled")
        self.discord_btn.pack(side="right", padx=8, pady=4)

    # ── 노트북 탭 ──────────────────────────────────────────────
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=4, pady=4)

        self.frames = {}
        tab_names = ["Overview", "Signatures", "ATT&CK",
                     "Behavior", "CAPE", "AI 분석"]
        for name in tab_names:
            f = ttk.Frame(self.nb)
            self.nb.add(f, text=name)
            self.frames[name] = f

        # 빈 상태 표시
        for name, frame in self.frames.items():
            tk.Label(frame, text="리포트 파일을 열어주세요.",
                     bg=BG, fg=FG_DIM, font=FONT_TITLE).pack(expand=True)

    # ── 상태바 ────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=BG2, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.status_var = tk.StringVar(value="준비")
        tk.Label(bar, textvariable=self.status_var,
                 bg=BG2, fg=FG_DIM, font=("Segoe UI", 9)).pack(side="left", padx=8)

    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.update_idletasks()

    # ── Drag & Drop ───────────────────────────────────────────
    def _setup_dnd(self):
        try:
            from tkinterdnd2 import DND_FILES
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)
        except ImportError:
            pass  # tkinterdnd2 없으면 DnD 비활성화

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
        self._set_status(f"로딩 중: {path}")
        def _load():
            try:
                data   = load_report(path)
                parser = ReportParser(data)

                # 커스텀 시그니처
                custom_sigs = sig_engine.run_all(data)

                # YARA
                yara_results = yara_engine.scan_report_payloads(data)

                # 화이트노이즈 필터
                wn = whitenoise.load_filter()
                raw_sigs = parser.get_signatures()
                filtered_sigs = whitenoise.filter_signatures(raw_sigs, wn)
                all_sigs = filtered_sigs + custom_sigs

                self.report_path = path
                self.parser      = parser
                self.all_sigs    = all_sigs
                self._raw_data   = data
                self._yara_res   = yara_results

                self.after(0, lambda: self._populate_tabs(parser, all_sigs, yara_results))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("오류", str(e)))
                self.after(0, lambda: self._set_status("로드 실패"))

        threading.Thread(target=_load, daemon=True).start()

    def _populate_tabs(self, parser: ReportParser, all_sigs: list, yara_results: list):
        name = Path(self.report_path).name
        self.path_label.config(text=name, fg=ACCENT)
        self.title(f"CAPEv2 Report Analyzer — {name}")

        # Scrollable wrapper
        def scrollable(parent):
            canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
            vsb    = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)
            inner  = ttk.Frame(canvas)
            win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
            def _on_resize(e):
                canvas.itemconfig(win_id, width=e.width)
            canvas.bind("<Configure>", _on_resize)
            inner.bind("<Configure>", lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")))
            def _on_mousewheel(e):
                canvas.yview_scroll(int(-1*(e.delta/120)), "units")
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            return inner

        errors = []

        def safe_build(tab_name, fn, *args):
            try:
                fn(*args)
            except Exception as e:
                import traceback
                errors.append(f"[{tab_name}] {e}\n{traceback.format_exc()}")
                f = self.frames[tab_name]
                for w in f.winfo_children(): w.destroy()
                tk.Label(f, text=f"[오류] {e}", bg=BG, fg=RED,
                         font=FONT_LABEL, wraplength=800, justify="left").pack(padx=12, pady=12, anchor="w")

        # Overview
        f = self.frames["Overview"]
        for w in f.winfo_children(): w.destroy()
        try:
            inner = scrollable(f)
            tab_overview.build(inner, parser, self.config_data)
        except Exception as e:
            import traceback
            errors.append(f"[Overview] {e}\n{traceback.format_exc()}")
            tk.Label(f, text=f"[오류] {e}", bg=BG, fg=RED,
                     font=FONT_LABEL, wraplength=800).pack(padx=12, pady=12, anchor="w")

        # Signatures
        safe_build("Signatures", tab_signatures.build, self.frames["Signatures"], all_sigs)

        # ATT&CK
        ttps = parser.get_ttps()
        safe_build("ATT&CK", tab_attack.build, self.frames["ATT&CK"], ttps)

        # Behavior
        wn = whitenoise.load_filter()
        api_calls = whitenoise.filter_api_calls(parser.get_api_calls(), wn)
        safe_build("Behavior", tab_behavior.build, self.frames["Behavior"], api_calls)

        # CAPE
        safe_build("CAPE", tab_cape.build, self.frames["CAPE"], parser, yara_results)

        # AI
        safe_build("AI 분석", tab_ai.build, self.frames["AI 분석"], parser, self.config_data, save_config)

        self.discord_btn.config(state="normal")
        if errors:
            self._set_status(f"로드 완료 (일부 탭 오류 {len(errors)}개) — 시그니처 {len(all_sigs)}개")
            print("\n".join(errors))  # 콘솔에 상세 오류 출력
        else:
            self._set_status(f"로드 완료 — 시그니처 {len(all_sigs)}개")

    # ── Discord 알림 ───────────────────────────────────────────
    def _send_discord(self):
        if not self.parser:
            return
        webhook = self.config_data.get("discord_webhook", "")
        if not webhook:
            messagebox.showwarning("Discord", "설정에서 웹훅 URL을 먼저 입력해주세요.")
            return
        summary = self.parser.get_summary_for_ai()
        result  = discord_alert.send_alert(webhook, summary, self.all_sigs)
        if result.get("success"):
            messagebox.showinfo("Discord", f"알림 전송 완료 ({result['count']}개 시그니처)")
        elif result.get("skipped"):
            messagebox.showinfo("Discord", "High 이상 시그니처 없음 — 전송하지 않음")
        else:
            messagebox.showerror("Discord", str(result.get("error", "알 수 없는 오류")))

    # ── 설정 창 ───────────────────────────────────────────────
    def _open_settings(self):
        win = tk.Toplevel(self)
        win.title("설정")
        win.geometry("520x320")
        win.configure(bg=BG)
        win.resizable(False, False)

        def row(label, key, show=False):
            fr = ttk.Frame(win)
            fr.pack(fill="x", padx=16, pady=6)
            tk.Label(fr, text=label, bg=BG, fg=FG, font=FONT_LABEL,
                     width=20, anchor="w").pack(side="left")
            var = tk.StringVar(value=self.config_data.get(key, ""))
            ent = ttk.Entry(fr, textvariable=var, width=36, show="*" if show else "")
            ent.pack(side="left", fill="x", expand=True)
            return var, key

        items = [
            ("VirusTotal API Key",  "vt_api_key",        True),
            ("Discord Webhook URL", "discord_webhook",   False),
            ("Claude API Key",      "ai_api_key",        True),
        ]
        vars_ = [row(*it) for it in items]

        def _save():
            for var, key in vars_:
                self.config_data[key] = var.get().strip()
            save_config(self.config_data)
            messagebox.showinfo("설정", "저장되었습니다.", parent=win)
            win.destroy()

        ttk.Button(win, text="저장", command=_save).pack(pady=12)
