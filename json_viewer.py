#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    STEALTH SCANNER - JSON VIEWER v1.0                          ║
║                                                                                 ║
║  Visualizzatore dati JSON delle scansioni                                      ║
║                                                                                 ║
║  Autore: Red-Penguin                                         ║
║  Versione: 1.0                                                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox, END
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class Config:
    VERSION = "1.0"
    OUTPUT_FOLDER = "Analisi"


class JSONViewerGUI(ctk.CTk):
    """Interfaccia grafica per la visualizzazione dei report JSON"""
    
    def __init__(self):
        super().__init__()
        
        self.title(f"Stealth Scanner - JSON Viewer v{Config.VERSION}")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        self.current_file = None
        self.current_data = None
        
        self.colors = {
            "success": "#00D26A",
            "warning": "#FFB800",
            "danger": "#FF3B3B",
            "info": "#0EA5E9",
            "muted": "#6B7280",
            "card_bg": "#1E1E2E",
            "critical": "#FF3B3B",
            "high": "#FF8C00",
            "medium": "#FFB800",
            "low": "#00D26A"
        }
        
        # Percorso cartella analisi (nella stessa directory dello script)
        script_dir = Path(__file__).parent.resolve()
        self.analysis_path = script_dir / Config.OUTPUT_FOLDER
        if not self.analysis_path.exists():
            self.analysis_path = Path.cwd() / Config.OUTPUT_FOLDER
        
        self._create_ui()
        self._load_file_list()
    
    def _create_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        self._create_header()
        
        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=3)
        content.grid_rowconfigure(0, weight=1)
        
        self._create_left_panel(content)
        self._create_right_panel(content)
    
    def _create_header(self):
        header = ctk.CTkFrame(self, height=80, fg_color=self.colors["card_bg"])
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_propagate(False)
        
        # Title
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=20, pady=15)
        
        ctk.CTkLabel(
            title_frame,
            text="📊 JSON Viewer - Stealth Scanner",
            font=ctk.CTkFont(size=22, weight="bold")
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            title_frame,
            text=f"Red-Penguin | v{Config.VERSION}",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["muted"]
        ).pack(anchor="w")
        
        # Buttons
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right", padx=20, pady=15)
        
        ctk.CTkButton(
            btn_frame,
            text="📂 Apri File",
            width=120,
            command=self._open_file
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Aggiorna Lista",
            width=120,
            command=self._load_file_list
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="📁 Apri Cartella",
            width=120,
            command=self._open_folder
        ).pack(side="left", padx=5)
    
    def _create_left_panel(self, parent):
        left_panel = ctk.CTkFrame(parent, fg_color="transparent")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_panel.grid_rowconfigure(1, weight=1)
        left_panel.grid_columnconfigure(0, weight=1)
        
        # Header
        header_card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        header_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        ctk.CTkLabel(
            header_card,
            text="📋 Report Salvati",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=15)
        
        # Search
        search_frame = ctk.CTkFrame(header_card, fg_color="transparent")
        search_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Cerca...",
            height=35
        )
        self.search_entry.pack(fill="x")
        self.search_entry.bind("<KeyRelease>", self._filter_files)
        
        # File list
        list_card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        list_card.grid(row=1, column=0, sticky="nsew")
        list_card.grid_rowconfigure(0, weight=1)
        list_card.grid_columnconfigure(0, weight=1)
        
        self.file_list_frame = ctk.CTkScrollableFrame(list_card, fg_color="transparent")
        self.file_list_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.file_buttons = []
    
    def _create_right_panel(self, parent):
        right_panel = ctk.CTkFrame(parent, fg_color="transparent")
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)
        
        # File info header
        info_header = ctk.CTkFrame(right_panel, fg_color=self.colors["card_bg"])
        info_header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        header_content = ctk.CTkFrame(info_header, fg_color="transparent")
        header_content.pack(fill="x", padx=15, pady=15)
        
        self.file_title = ctk.CTkLabel(
            header_content,
            text="Seleziona un report",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.file_title.pack(anchor="w")
        
        self.file_info = ctk.CTkLabel(
            header_content,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=self.colors["muted"]
        )
        self.file_info.pack(anchor="w")
        
        # Tabs
        self.tabview = ctk.CTkTabview(right_panel)
        self.tabview.grid(row=1, column=0, sticky="nsew")
        
        # Tab Overview
        self.tab_overview = self.tabview.add("📊 Overview")
        self.overview_frame = ctk.CTkScrollableFrame(self.tab_overview)
        self.overview_frame.pack(fill="both", expand=True)
        
        # Tab Vulnerabilità
        self.tab_vuln = self.tabview.add("⚠️ Vulnerabilità")
        self.vuln_frame = ctk.CTkScrollableFrame(self.tab_vuln)
        self.vuln_frame.pack(fill="both", expand=True)
        
        # Tab Porte
        self.tab_ports = self.tabview.add("🔌 Porte")
        self.ports_frame = ctk.CTkScrollableFrame(self.tab_ports)
        self.ports_frame.pack(fill="both", expand=True)
        
        # Tab Attacchi
        self.tab_attacks = self.tabview.add("🎯 Attacchi")
        self.attacks_frame = ctk.CTkScrollableFrame(self.tab_attacks)
        self.attacks_frame.pack(fill="both", expand=True)
        
        # Tab Geolocalizzazione
        self.tab_geo = self.tabview.add("🌍 Geolocalizzazione")
        self.geo_frame = ctk.CTkScrollableFrame(self.tab_geo)
        self.geo_frame.pack(fill="both", expand=True)
        
        # Tab JSON Raw
        self.tab_raw = self.tabview.add("📝 JSON Raw")
        self.raw_text = ctk.CTkTextbox(
            self.tab_raw,
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.raw_text.pack(fill="both", expand=True)
    
    def _load_file_list(self):
        """Carica la lista dei file JSON dalla cartella"""
        # Clear existing
        for btn in self.file_buttons:
            btn.destroy()
        self.file_buttons = []
        
        if not self.analysis_path.exists():
            ctk.CTkLabel(
                self.file_list_frame,
                text="Cartella non trovata",
                text_color=self.colors["muted"]
            ).pack(pady=20)
            return
        
        # Get JSON files
        json_files = sorted(
            self.analysis_path.glob("*.json"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        if not json_files:
            ctk.CTkLabel(
                self.file_list_frame,
                text="Nessun report trovato\n\nEsegui una scansione per generare report",
                text_color=self.colors["muted"],
                justify="center"
            ).pack(pady=20)
            return
        
        for file_path in json_files:
            self._add_file_button(file_path)
    
    def _add_file_button(self, file_path: Path):
        """Aggiunge un pulsante per un file"""
        # Get file info
        try:
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            size = file_path.stat().st_size
            
            # Try to get target from filename
            name = file_path.stem
            parts = name.rsplit('_', 2)
            target = parts[0] if parts else name
            
            # Load to check vulnerabilities count
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                vuln_count = len(data.get("vulnerabilities", []))
                port_count = len(data.get("open_ports", []))
            except Exception:
                vuln_count = 0
                port_count = 0
            
        except Exception:
            return
        
        # Create button frame
        btn_frame = ctk.CTkFrame(self.file_list_frame, fg_color="#2D2D3D")
        btn_frame.pack(fill="x", pady=3, padx=2)
        btn_frame.bind("<Button-1>", lambda e, p=file_path: self._load_file(p))
        
        # Content
        content = ctk.CTkFrame(btn_frame, fg_color="transparent")
        content.pack(fill="x", padx=10, pady=8)
        content.bind("<Button-1>", lambda e, p=file_path: self._load_file(p))
        
        # Target name
        ctk.CTkLabel(
            content,
            text=target[:30] + "..." if len(target) > 30 else target,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w"
        ).pack(fill="x")
        
        # Info row
        info_frame = ctk.CTkFrame(content, fg_color="transparent")
        info_frame.pack(fill="x", pady=(3, 0))
        
        ctk.CTkLabel(
            info_frame,
            text=mtime.strftime("%d/%m/%Y %H:%M"),
            font=ctk.CTkFont(size=10),
            text_color=self.colors["muted"]
        ).pack(side="left")
        
        # Vulnerability badge
        if vuln_count > 0:
            badge_color = self.colors["danger"] if vuln_count >= 3 else self.colors["warning"]
            ctk.CTkLabel(
                info_frame,
                text=f"⚠️ {vuln_count}",
                font=ctk.CTkFont(size=10),
                text_color=badge_color
            ).pack(side="right", padx=5)
        
        ctk.CTkLabel(
            info_frame,
            text=f"🔌 {port_count}",
            font=ctk.CTkFont(size=10),
            text_color=self.colors["info"]
        ).pack(side="right")
        
        self.file_buttons.append(btn_frame)
    
    def _filter_files(self, event=None):
        """Filtra la lista dei file"""
        search_term = self.search_entry.get().lower()
        
        for btn in self.file_buttons:
            # Get the label text from the frame
            try:
                content = btn.winfo_children()[0]
                label = content.winfo_children()[0]
                text = label.cget("text").lower()
                
                if search_term in text:
                    btn.pack(fill="x", pady=3, padx=2)
                else:
                    btn.pack_forget()
            except Exception:
                pass
    
    def _open_file(self):
        """Apre un file JSON tramite dialog"""
        file_path = filedialog.askopenfilename(
            title="Seleziona Report JSON",
            initialdir=str(self.analysis_path),
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if file_path:
            self._load_file(Path(file_path))
    
    def _open_folder(self):
        """Apre la cartella dei report"""
        try:
            import subprocess
            if os.name == 'nt':
                os.startfile(self.analysis_path)
            else:
                subprocess.run(['xdg-open', str(self.analysis_path)], check=False)
        except Exception:
            messagebox.showerror("Errore", f"Impossibile aprire: {self.analysis_path}")
    
    def _load_file(self, file_path: Path):
        """Carica e visualizza un file JSON"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.current_file = file_path
            self.current_data = data
            
            # Update header
            target = data.get("target", file_path.stem)
            self.file_title.configure(text=f"🎯 {target}")
            
            scan_date = data.get("scan_date", "N/A")
            ip = data.get("ip", "N/A")
            self.file_info.configure(text=f"IP: {ip} | Scansione: {scan_date}")
            
            # Update tabs
            self._update_overview(data)
            self._update_vulnerabilities(data)
            self._update_ports(data)
            self._update_attacks(data)
            self._update_geo(data)
            self._update_raw(data)
            
        except json.JSONDecodeError:
            messagebox.showerror("Errore", "File JSON non valido")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore caricamento: {str(e)}")
    
    def _clear_frame(self, frame):
        """Pulisce un frame"""
        for widget in frame.winfo_children():
            widget.destroy()
    
    def _update_overview(self, data: dict):
        """Aggiorna la tab Overview"""
        self._clear_frame(self.overview_frame)
        
        # Stats
        vulns = data.get("vulnerabilities", [])
        ports = data.get("open_ports", [])
        
        vuln_counts = {
            "CRITICA": len([v for v in vulns if v.get("severity") == "CRITICA"]),
            "ALTA": len([v for v in vulns if v.get("severity") == "ALTA"]),
            "MEDIA": len([v for v in vulns if v.get("severity") == "MEDIA"]),
            "BASSA": len([v for v in vulns if v.get("severity") == "BASSA"])
        }
        
        # Stats cards
        stats_frame = ctk.CTkFrame(self.overview_frame, fg_color="transparent")
        stats_frame.pack(fill="x", pady=10, padx=10)
        
        stats = [
            ("Porte Aperte", len(ports), self.colors["info"]),
            ("Critiche", vuln_counts["CRITICA"], self.colors["critical"]),
            ("Alte", vuln_counts["ALTA"], self.colors["high"]),
            ("Medie", vuln_counts["MEDIA"], self.colors["medium"]),
            ("Basse", vuln_counts["BASSA"], self.colors["low"])
        ]
        
        for label, count, color in stats:
            card = ctk.CTkFrame(stats_frame, fg_color="#2D2D3D", width=100)
            card.pack(side="left", padx=5, pady=5, fill="y")
            card.pack_propagate(False)
            
            ctk.CTkLabel(
                card,
                text=str(count),
                font=ctk.CTkFont(size=28, weight="bold"),
                text_color=color
            ).pack(pady=(15, 5))
            
            ctk.CTkLabel(
                card,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color=self.colors["muted"]
            ).pack(pady=(0, 15))
        
        # Risk level
        if vuln_counts["CRITICA"] > 0:
            risk = "CRITICO"
            risk_color = self.colors["critical"]
        elif vuln_counts["ALTA"] > 0:
            risk = "ALTO"
            risk_color = self.colors["high"]
        elif vuln_counts["MEDIA"] > 0:
            risk = "MEDIO"
            risk_color = self.colors["medium"]
        else:
            risk = "BASSO"
            risk_color = self.colors["low"]
        
        risk_card = ctk.CTkFrame(self.overview_frame, fg_color="#2D2D3D")
        risk_card.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            risk_card,
            text=f"LIVELLO DI RISCHIO: {risk}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=risk_color
        ).pack(pady=15)
        
        # Info sections
        self._add_info_section(self.overview_frame, "📋 Informazioni Scansione", [
            ("Target", data.get("target", "N/A")),
            ("IP", data.get("ip", "N/A")),
            ("Data", data.get("scan_date", "N/A")),
            ("Versione Scanner", data.get("scanner_version", "N/A"))
        ])
        
        # Hosting
        hosting = data.get("hosting", {})
        if hosting:
            self._add_info_section(self.overview_frame, "🏢 Hosting", [
                ("È Hosting", "✅ Sì" if hosting.get("is_hosting") else "❌ No"),
                ("Provider", hosting.get("provider", "N/A")),
                ("Datacenter", hosting.get("datacenter", "N/A")),
                ("È Proxy", "✅ Sì" if hosting.get("is_proxy") else "❌ No")
            ])
        
        # SSL
        ssl_info = data.get("ssl_info", {})
        if ssl_info and ssl_info.get("protocol_version"):
            self._add_info_section(self.overview_frame, "🔐 SSL/TLS", [
                ("Protocollo", ssl_info.get("protocol_version", "N/A")),
                ("Cipher", ssl_info.get("cipher", "N/A")),
                ("Bits", str(ssl_info.get("cipher_bits", "N/A")))
            ])
    
    def _update_vulnerabilities(self, data: dict):
        """Aggiorna la tab Vulnerabilità"""
        self._clear_frame(self.vuln_frame)
        
        vulns = data.get("vulnerabilities", [])
        
        if not vulns:
            ctk.CTkLabel(
                self.vuln_frame,
                text="✅ Nessuna vulnerabilità rilevata",
                font=ctk.CTkFont(size=16),
                text_color=self.colors["success"]
            ).pack(pady=50)
            return
        
        # Sort by severity
        severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3}
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get("severity", ""), 4))
        
        for vuln in sorted_vulns:
            self._add_vuln_card(vuln)
    
    def _add_vuln_card(self, vuln: dict):
        """Aggiunge una card vulnerabilità"""
        severity = vuln.get("severity", "")
        colors_map = {
            "CRITICA": self.colors["critical"],
            "ALTA": self.colors["high"],
            "MEDIA": self.colors["medium"],
            "BASSA": self.colors["low"]
        }
        color = colors_map.get(severity, self.colors["muted"])
        
        card = ctk.CTkFrame(self.vuln_frame, fg_color="#2D2D3D")
        card.pack(fill="x", pady=5, padx=10)
        
        # Header
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(
            header,
            text=severity,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=color,
            fg_color="#1a1a2e",
            corner_radius=4
        ).pack(side="left", ipadx=8, ipady=2)
        
        ctk.CTkLabel(
            header,
            text=vuln.get("title", ""),
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left", padx=10)
        
        if vuln.get("cve"):
            ctk.CTkLabel(
                header,
                text=vuln["cve"],
                font=ctk.CTkFont(size=10),
                text_color="#FF6B6B",
                fg_color="#2a1a1a",
                corner_radius=4
            ).pack(side="right", ipadx=6, ipady=2)
        
        # Description
        ctk.CTkLabel(
            card,
            text=vuln.get("description", ""),
            font=ctk.CTkFont(size=12),
            text_color=self.colors["muted"],
            anchor="w",
            wraplength=600
        ).pack(fill="x", padx=15, pady=(0, 5))
        
        # CVE desc
        if vuln.get("cve_desc"):
            ctk.CTkLabel(
                card,
                text=f"ℹ️ {vuln['cve_desc']}",
                font=ctk.CTkFont(size=11),
                text_color="#FF9999",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 5))
        
        # Remediation
        ctk.CTkLabel(
            card,
            text=f"→ Rimedio: {vuln.get('remediation', '')}",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["info"],
            anchor="w",
            wraplength=600
        ).pack(fill="x", padx=15, pady=(0, 15))
    
    def _update_ports(self, data: dict):
        """Aggiorna la tab Porte"""
        self._clear_frame(self.ports_frame)
        
        ports = data.get("open_ports", [])
        
        if not ports:
            ctk.CTkLabel(
                self.ports_frame,
                text="Nessuna porta aperta rilevata",
                font=ctk.CTkFont(size=14),
                text_color=self.colors["muted"]
            ).pack(pady=50)
            return
        
        # Header
        header = ctk.CTkFrame(self.ports_frame, fg_color="#2D2D3D")
        header.pack(fill="x", pady=5, padx=10)
        
        header_content = ctk.CTkFrame(header, fg_color="transparent")
        header_content.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            header_content,
            text="Stato",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=80
        ).pack(side="left")
        
        ctk.CTkLabel(
            header_content,
            text="Porta",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=100
        ).pack(side="left")
        
        ctk.CTkLabel(
            header_content,
            text="Servizio",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left")
        
        # Port rows
        for port_info in ports:
            self._add_port_row(port_info)
    
    def _add_port_row(self, port_info: dict):
        """Aggiunge una riga porta"""
        row = ctk.CTkFrame(self.ports_frame, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=2)
        
        content = ctk.CTkFrame(row, fg_color="#2D2D3D")
        content.pack(fill="x")
        
        inner = ctk.CTkFrame(content, fg_color="transparent")
        inner.pack(fill="x", padx=15, pady=8)
        
        ctk.CTkLabel(
            inner,
            text="● APERTA",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["success"],
            width=80
        ).pack(side="left")
        
        ctk.CTkLabel(
            inner,
            text=str(port_info.get("port", "")),
            font=ctk.CTkFont(size=13, weight="bold"),
            width=100
        ).pack(side="left")
        
        ctk.CTkLabel(
            inner,
            text=port_info.get("service", ""),
            font=ctk.CTkFont(size=13),
            text_color=self.colors["muted"]
        ).pack(side="left")
    
    def _update_attacks(self, data: dict):
        """Aggiorna la tab Attacchi"""
        self._clear_frame(self.attacks_frame)
        
        attacks = data.get("possible_attacks", [])
        
        if not attacks:
            ctk.CTkLabel(
                self.attacks_frame,
                text="✅ Nessun attacco identificato per le vulnerabilità rilevate",
                font=ctk.CTkFont(size=14),
                text_color=self.colors["low"]
            ).pack(pady=50)
            return
        
        # Header
        header = ctk.CTkFrame(self.attacks_frame, fg_color="#1a1a2e")
        header.pack(fill="x", pady=(0, 10), padx=5)
        ctk.CTkLabel(
            header,
            text=f"🎯 {len(attacks)} ATTACCHI POSSIBILI IDENTIFICATI",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#FF6B6B"
        ).pack(pady=15, padx=15)
        
        severity_colors = {
            "CRITICA": self.colors["critical"],
            "ALTA": self.colors["high"],
            "MEDIA": self.colors["medium"],
            "BASSA": self.colors["low"]
        }
        
        for i, attack in enumerate(attacks[:3], 1):
            card = ctk.CTkFrame(self.attacks_frame, fg_color="#2D2D3D")
            card.pack(fill="x", pady=5, padx=5)
            
            # Header card
            card_header = ctk.CTkFrame(card, fg_color="transparent")
            card_header.pack(fill="x", padx=15, pady=(15, 10))
            
            severity = attack.get("severity", "MEDIA")
            color = severity_colors.get(severity, self.colors["warning"])
            
            # Numero attacco
            ctk.CTkLabel(
                card_header,
                text=f"#{i}",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color=color
            ).pack(side="left", padx=(0, 10))
            
            # Nome attacco
            ctk.CTkLabel(
                card_header,
                text=attack.get("name", ""),
                font=ctk.CTkFont(size=15, weight="bold")
            ).pack(side="left")
            
            # Badge severity
            ctk.CTkLabel(
                card_header,
                text=severity,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=color,
                fg_color="#1a1a2e",
                corner_radius=4
            ).pack(side="right", ipadx=8, ipady=2)
            
            # Tipo attacco
            ctk.CTkLabel(
                card,
                text=f"Tipo: {attack.get('type', '')}",
                font=ctk.CTkFont(size=12),
                text_color="#60A5FA",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 5))
            
            # Descrizione
            ctk.CTkLabel(
                card,
                text=attack.get("description", ""),
                font=ctk.CTkFont(size=12),
                text_color="#9CA3AF",
                anchor="w",
                wraplength=500,
                justify="left"
            ).pack(fill="x", padx=15, pady=(0, 5))
            
            # Tools
            ctk.CTkLabel(
                card,
                text=f"🔧 Tools: {attack.get('tools', '')}",
                font=ctk.CTkFont(size=11),
                text_color="#FFB800",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 5))
            
            # Impact
            ctk.CTkLabel(
                card,
                text=f"💥 Impatto: {attack.get('impact', '')}",
                font=ctk.CTkFont(size=11),
                text_color="#FF6B6B",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 15))
    
    def _update_geo(self, data: dict):
        """Aggiorna la tab Geolocalizzazione"""
        self._clear_frame(self.geo_frame)
        
        geo = data.get("geolocation", {})
        network = data.get("network_info", {})
        hosting = data.get("hosting", {})
        
        if not geo and not network:
            ctk.CTkLabel(
                self.geo_frame,
                text="Informazioni di geolocalizzazione non disponibili",
                font=ctk.CTkFont(size=14),
                text_color=self.colors["muted"]
            ).pack(pady=50)
            return
        
        # Geolocation
        if geo:
            self._add_info_section(self.geo_frame, "🌍 Posizione Geografica", [
                ("Paese", f"{geo.get('country', 'N/A')} ({geo.get('country_code', '')})"),
                ("Regione", geo.get("region_name", "N/A")),
                ("Città", geo.get("city", "N/A")),
                ("CAP", geo.get("zip_code", "N/A")),
                ("Latitudine", str(geo.get("latitude", "N/A"))),
                ("Longitudine", str(geo.get("longitude", "N/A"))),
                ("Timezone", geo.get("timezone", "N/A"))
            ])
            
            # Map link
            lat = geo.get("latitude", 0)
            lon = geo.get("longitude", 0)
            if lat and lon:
                map_card = ctk.CTkFrame(self.geo_frame, fg_color="#2D2D3D")
                map_card.pack(fill="x", pady=10, padx=10)
                
                ctk.CTkLabel(
                    map_card,
                    text=f"📍 Coordinate: {lat}, {lon}",
                    font=ctk.CTkFont(size=12),
                    text_color=self.colors["info"]
                ).pack(pady=15)
        
        # Network
        if network:
            self._add_info_section(self.geo_frame, "🌐 Informazioni Rete", [
                ("ISP", network.get("isp", "N/A")),
                ("Organizzazione", network.get("organization", "N/A")),
                ("ASN", network.get("asn", "N/A")),
                ("ASN Name", network.get("asn_name", "N/A")),
                ("Reverse DNS", network.get("reverse_dns", "N/A"))
            ])
        
        # Hosting
        if hosting:
            self._add_info_section(self.geo_frame, "🏢 Informazioni Hosting", [
                ("È un Hosting", "✅ Sì" if hosting.get("is_hosting") else "❌ No"),
                ("È un Proxy", "✅ Sì" if hosting.get("is_proxy") else "❌ No"),
                ("È Mobile", "✅ Sì" if hosting.get("is_mobile") else "❌ No"),
                ("Provider", hosting.get("provider", "N/A")),
                ("Datacenter", hosting.get("datacenter", "N/A"))
            ])
    
    def _add_info_section(self, parent, title: str, items: list):
        """Aggiunge una sezione informativa"""
        section = ctk.CTkFrame(parent, fg_color="#2D2D3D")
        section.pack(fill="x", pady=5, padx=10)
        
        ctk.CTkLabel(
            section,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors["info"]
        ).pack(anchor="w", padx=15, pady=(15, 10))
        
        for label, value in items:
            row = ctk.CTkFrame(section, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=2)
            
            ctk.CTkLabel(
                row,
                text=f"{label}:",
                font=ctk.CTkFont(size=12),
                text_color=self.colors["muted"]
            ).pack(side="left")
            
            ctk.CTkLabel(
                row,
                text=str(value),
                font=ctk.CTkFont(size=12)
            ).pack(side="right")
        
        ctk.CTkFrame(section, fg_color="transparent", height=10).pack()
    
    def _update_raw(self, data: dict):
        """Aggiorna la tab JSON Raw"""
        self.raw_text.delete("1.0", END)
        
        try:
            formatted = json.dumps(data, indent=2, ensure_ascii=False)
            self.raw_text.insert("1.0", formatted)
        except Exception as e:
            self.raw_text.insert("1.0", f"Errore formattazione: {str(e)}")


def main():
    app = JSONViewerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
