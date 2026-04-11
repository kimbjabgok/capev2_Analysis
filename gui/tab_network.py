"""Network 탭 (서브탭 포함)"""
import tkinter as tk
from tkinter import ttk

from gui.styles import *


def _fill_table(parent, data: list, columns: list, extract_fn):
    if not data:
        tk.Label(parent, text="데이터 없음", bg=BG, fg=FG_DIM,
                 font=FONT_LABEL).pack(expand=True)
        return
    tv = scrolled_treeview(parent, columns)
    for item in data:
        tv.insert("", "end", values=extract_fn(item))


def build(parent: ttk.Frame, parser):
    for w in parent.winfo_children():
        w.destroy()

    nb = ttk.Notebook(parent)
    nb.pack(fill="both", expand=True, padx=4, pady=4)

    # ── Suricata Alerts ────────────────────────────────────────
    tab_sur = ttk.Frame(nb)
    nb.add(tab_sur, text="Suricata Alerts")
    alerts = parser.get_suricata()
    _fill_table(tab_sur, alerts,
                ["SID", "Severity", "Signature", "Src IP", "Dst IP", "Proto"],
                lambda a: (
                    a.get("alert", {}).get("signature_id", ""),
                    a.get("alert", {}).get("severity", ""),
                    a.get("alert", {}).get("signature", ""),
                    a.get("src_ip", ""),
                    a.get("dest_ip", ""),
                    a.get("proto", ""),
                ))

    # ── DNS ───────────────────────────────────────────────────
    tab_dns = ttk.Frame(nb)
    nb.add(tab_dns, text="DNS")
    dns_records = parser.get_dns()
    _fill_table(tab_dns, dns_records,
                ["Request", "Type", "Answers"],
                lambda d: (
                    d.get("request", ""),
                    d.get("type", ""),
                    ", ".join(
                        a.get("data", "") for a in d.get("answers", [])
                    ),
                ))

    # ── HTTP ──────────────────────────────────────────────────
    tab_http = ttk.Frame(nb)
    nb.add(tab_http, text="HTTP")
    http_records = parser.get_http()
    _fill_table(tab_http, http_records,
                ["URI", "Method", "Host", "User-Agent", "Status"],
                lambda h: (
                    h.get("uri", ""),
                    h.get("method", ""),
                    h.get("host", ""),
                    h.get("user-agent", "")[:60],
                    h.get("status", ""),
                ))

    # ── TLS ───────────────────────────────────────────────────
    tab_tls = ttk.Frame(nb)
    nb.add(tab_tls, text="TLS")
    tls_records = parser.get_tls()
    _fill_table(tab_tls, tls_records,
                ["SNI", "Version", "Src IP", "Dst IP", "JA3"],
                lambda t: (
                    t.get("sni", ""),
                    t.get("version", ""),
                    t.get("src_ip", t.get("src", "")),
                    t.get("dst_ip", t.get("dst", "")),
                    t.get("ja3", {}).get("hash", "") if isinstance(t.get("ja3"), dict) else t.get("ja3", ""),
                ))

    # ── SSH ───────────────────────────────────────────────────
    tab_ssh = ttk.Frame(nb)
    nb.add(tab_ssh, text="SSH")
    ssh_records = parser.get_ssh()
    _fill_table(tab_ssh, ssh_records,
                ["Src IP", "Dst IP", "Client Banner", "Server Banner"],
                lambda s: (
                    s.get("src_ip", ""),
                    s.get("dst_ip", ""),
                    s.get("client", {}).get("banner", ""),
                    s.get("server", {}).get("banner", ""),
                ))

    # ── Files ─────────────────────────────────────────────────
    tab_files = ttk.Frame(nb)
    nb.add(tab_files, text="Files")
    net_files = parser.get_network_files()
    _fill_table(tab_files, net_files,
                ["Path", "SHA256", "URI"],
                lambda f: (
                    f.get("path", f.get("filename", "")),
                    f.get("sha256", ""),
                    f.get("uri", ""),
                ))
