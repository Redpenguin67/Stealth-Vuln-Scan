#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    STEALTH VULNERABILITY SCANNER v3.2 GUI                      ║
║                                                                                 ║
║  Scanner stealth con:                                                          ║
║  - Rilevazione Hosting Provider                                                ║
║  - Geolocalizzazione Completa                                                  ║
║  - Analisi Attacchi Distruttivi (3) e Probabili (5)                           ║
║  - Integrazione AI Gemini per analisi avanzata                                 ║
║  - Export JSON, HTML, TXT                                                      ║
║                                                                                 ║
║  Autore: Red-Penguin                                                           ║
║  Versione: 3.2                                                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
from tkinter import messagebox, END
import threading
import socket
import subprocess
import ssl
import re
import os
import json
import base64
import configparser
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Import opzionali
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class Config:
    """Configurazione dello scanner"""
    VERSION = "3.2 GUI"
    TIMEOUT = 5
    TIMEOUT_FAST = 2
    OUTPUT_FOLDER = "Analisi"
    CONFIG_FILE = "config.ini"
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    CVE_DATABASE = {
        "ftp_anonymous": {"cve": "CWE-284", "desc": "Improper Access Control"},
        "telnet": {"cve": "CWE-319", "desc": "Cleartext Transmission"},
        "redis_noauth": {"cve": "CVE-2022-0543", "desc": "Redis Sandbox Escape"},
        "smb_exposed": {"cve": "CVE-2017-0144", "desc": "EternalBlue RCE"},
        "rdp_exposed": {"cve": "CVE-2019-0708", "desc": "BlueKeep RCE"},
        "mysql_exposed": {"cve": "CVE-2012-2122", "desc": "Auth Bypass"},
        "postgres_exposed": {"cve": "CVE-2019-9193", "desc": "Command Exec"},
        "mongodb_exposed": {"cve": "CVE-2017-2665", "desc": "Unauth Access"},
        "vnc_exposed": {"cve": "CVE-2019-15678", "desc": "Buffer Overflow"},
        "ssh_weak": {"cve": "CVE-2023-38408", "desc": "OpenSSH Vuln"},
        "hsts_missing": {"cve": "CWE-319", "desc": "Missing HSTS"},
        "xframe_missing": {"cve": "CWE-1021", "desc": "Clickjacking"},
        "csp_missing": {"cve": "CWE-693", "desc": "XSS Risk"},
        "mssql_exposed": {"cve": "CVE-2020-0618", "desc": "MSSQL RCE"},
        "ssl_weak": {"cve": "CWE-326", "desc": "Weak SSL/TLS"},
        "git_exposed": {"cve": "CWE-538", "desc": "Source Code Leak"},
        "env_exposed": {"cve": "CWE-200", "desc": "Information Exposure"},
        "phpinfo_exposed": {"cve": "CWE-200", "desc": "Information Disclosure"}
    }
    
    # API per geolocalizzazione e hosting (gratuiti, no API key)
    GEOIP_APIS = [
        "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
        "https://ipwho.is/{ip}",
        "https://ipinfo.io/{ip}/json"
    ]
    
    # Modelli Gemini disponibili (aggiornato Febbraio 2026)
    GEMINI_MODELS = [
        "gemini-2.5-flash",       # Consigliato - veloce e potente
        "gemini-2.5-pro",         # Più potente
        "gemini-2.0-flash",       # Stabile
        "gemini-2.0-flash-lite",  # Leggero
        "gemini-1.5-flash",       # Legacy
        "gemini-1.5-pro"          # Legacy potente
    ]
    
    # ==================== DATABASE ATTACCHI DISTRUTTIVI ====================
    # I 3 attacchi più devastanti che possono compromettere completamente il sistema
    DESTRUCTIVE_ATTACKS = {
        "smb_exposed": {
            "name": "EternalBlue / WannaCry",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Sfruttamento della vulnerabilità SMBv1 per esecuzione codice remoto. Utilizzato nei ransomware WannaCry e NotPetya.",
            "tools": "Metasploit (ms17_010_eternalblue), nmap --script smb-vuln-ms17-010",
            "impact": "Compromissione totale del sistema, movimento laterale nella rete, deploy ransomware",
            "time_to_exploit": "< 5 minuti"
        },
        "rdp_exposed": {
            "name": "BlueKeep RCE Attack",
            "type": "Remote Code Execution", 
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Vulnerabilità pre-auth in RDP che permette esecuzione codice senza credenziali. Wormable.",
            "tools": "Metasploit (cve_2019_0708_bluekeep), rdpscan",
            "impact": "Accesso completo al sistema, possibilità di propagazione automatica",
            "time_to_exploit": "< 10 minuti"
        },
        "redis_noauth": {
            "name": "Redis Unauthorized RCE",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Redis senza autenticazione permette scrittura file e esecuzione comandi tramite moduli o SSH key injection.",
            "tools": "redis-cli, redis-rogue-server, redis-exploit",
            "impact": "Esecuzione comandi come utente redis, escalation a root, ransomware",
            "time_to_exploit": "< 3 minuti"
        },
        "mongodb_exposed": {
            "name": "MongoDB Ransomware Attack",
            "type": "Data Theft / Ransomware",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Database MongoDB esposto senza autenticazione. Attaccanti possono rubare/cancellare dati e richiedere riscatto.",
            "tools": "mongosh, nosqlmap, mongodump",
            "impact": "Furto completo dei dati, cancellazione database, estorsione",
            "time_to_exploit": "< 2 minuti"
        },
        "mssql_exposed": {
            "name": "MSSQL xp_cmdshell RCE",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "SQL Server esposto può permettere esecuzione comandi OS tramite xp_cmdshell con privilegi SYSTEM.",
            "tools": "impacket-mssqlclient, sqlcmd, Metasploit",
            "impact": "Esecuzione comandi NT AUTHORITY\\SYSTEM, dominio compromesso",
            "time_to_exploit": "< 15 minuti"
        }
    }
    
    # ==================== DATABASE ATTACCHI PROBABILI ====================
    # Attacchi realistici che un attaccante userebbe per persistenza e accesso
    PROBABLE_ATTACKS = {
        "ssh_key_injection": {
            "name": "SSH Key Injection (Backdoor)",
            "type": "Persistence / Backdoor",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Iniezione di chiave SSH pubblica in authorized_keys per accesso persistente senza password.",
            "tools": "redis-cli (via Redis), FTP upload, web shell",
            "impact": "Accesso SSH permanente, sopravvive a reboot, difficile da rilevare",
            "time_to_exploit": "< 1 minuto",
            "triggered_by": ["redis_noauth", "ftp_anonymous", "git_exposed"]
        },
        "webshell_upload": {
            "name": "Webshell Upload",
            "type": "Remote Access / Backdoor",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Upload di shell PHP/ASP/JSP per controllo remoto del server web.",
            "tools": "weevely, b374k, c99, China Chopper",
            "impact": "Esecuzione comandi via web, esfiltrazione dati, pivot point",
            "time_to_exploit": "< 5 minuti",
            "triggered_by": ["ftp_anonymous", "git_exposed", "env_exposed"]
        },
        "reverse_shell": {
            "name": "Reverse Shell Connection",
            "type": "Remote Access",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Connessione reverse per bypass firewall. Il target si connette all'attaccante.",
            "tools": "nc, bash, python, powershell, msfvenom",
            "impact": "Shell interattiva, bypass firewall ingress, accesso completo",
            "time_to_exploit": "< 2 minuti",
            "triggered_by": ["redis_noauth", "postgres_exposed", "mssql_exposed", "mysql_exposed"]
        },
        "credential_harvesting": {
            "name": "Credential Harvesting",
            "type": "Credential Theft",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Estrazione credenziali da file config, .env, database, memory dump.",
            "tools": "mimikatz, LaZagne, truffleHog, git-secrets",
            "impact": "Accesso ad altri sistemi, escalation privilegi, movimento laterale",
            "time_to_exploit": "< 10 minuti",
            "triggered_by": ["env_exposed", "git_exposed", "phpinfo_exposed", "ftp_anonymous"]
        },
        "cron_backdoor": {
            "name": "Cron/Task Scheduler Backdoor",
            "type": "Persistence",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Persistenza tramite cron job (Linux) o Task Scheduler (Windows) per esecuzione periodica.",
            "tools": "crontab, schtasks, at",
            "impact": "Persistenza garantita, riconnessione automatica, difficile rilevamento",
            "time_to_exploit": "< 3 minuti",
            "triggered_by": ["redis_noauth", "ssh_weak", "postgres_exposed"]
        },
        "cryptominer_deploy": {
            "name": "Cryptominer Deployment",
            "type": "Resource Hijacking",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Installazione di cryptominer (XMRig, etc.) per mining Monero usando risorse del server.",
            "tools": "xmrig, cryptonight, coinhive",
            "impact": "Consumo CPU/GPU, costi elettrici, degrado performance",
            "time_to_exploit": "< 5 minuti",
            "triggered_by": ["redis_noauth", "mongodb_exposed", "ssh_weak"]
        },
        "lateral_movement": {
            "name": "Lateral Movement Preparation",
            "type": "Reconnaissance / Pivot",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Scansione rete interna per identificare altri target. Preparazione per movimento laterale.",
            "tools": "nmap, masscan, crackmapexec, BloodHound",
            "impact": "Mappatura rete interna, identificazione domain controller, escalation",
            "time_to_exploit": "10-30 minuti",
            "triggered_by": ["smb_exposed", "rdp_exposed", "ssh_weak"]
        },
        "log_tampering": {
            "name": "Log Tampering / Anti-Forensics",
            "type": "Evasion",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Cancellazione o modifica log per nascondere tracce dell'intrusione.",
            "tools": "shred, wevtutil, clearev (meterpreter)",
            "impact": "Evasione detection, complicazione forensics, permanenza prolungata",
            "time_to_exploit": "< 5 minuti",
            "triggered_by": ["redis_noauth", "ssh_weak", "postgres_exposed", "mysql_exposed"]
        },
        "data_exfiltration": {
            "name": "Data Exfiltration",
            "type": "Data Theft",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Esfiltrazione dati sensibili via DNS tunneling, HTTPS, o canali nascosti.",
            "tools": "dnscat2, iodine, HTTPTunnel, rclone",
            "impact": "Furto dati sensibili, violazione GDPR, danno reputazionale",
            "time_to_exploit": "variabile",
            "triggered_by": ["mongodb_exposed", "mysql_exposed", "postgres_exposed", "ftp_anonymous"]
        },
        "privilege_escalation": {
            "name": "Privilege Escalation",
            "type": "Escalation",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Escalation da utente limitato a root/SYSTEM sfruttando misconfiguration o kernel exploit.",
            "tools": "linpeas, winpeas, linux-exploit-suggester, BeRoot",
            "impact": "Controllo completo del sistema, accesso a tutti i dati",
            "time_to_exploit": "5-30 minuti",
            "triggered_by": ["ssh_weak", "redis_noauth", "ftp_anonymous"]
        }
    }
    
    # Database attacchi legacy (per retrocompatibilità)
    ATTACK_DATABASE = {
        "smb_exposed": DESTRUCTIVE_ATTACKS["smb_exposed"],
        "rdp_exposed": DESTRUCTIVE_ATTACKS["rdp_exposed"],
        "redis_noauth": DESTRUCTIVE_ATTACKS["redis_noauth"],
        "mongodb_exposed": DESTRUCTIVE_ATTACKS["mongodb_exposed"],
        "mssql_exposed": DESTRUCTIVE_ATTACKS["mssql_exposed"],
        "mysql_exposed": {
            "name": "MySQL Authentication Bypass",
            "type": "Authentication Bypass",
            "severity": "ALTA",
            "category": "DISTRUTTIVO",
            "description": "Tentativo di bypass autenticazione MySQL tramite race condition o credenziali deboli.",
            "tools": "hydra, medusa, nmap --script mysql-brute",
            "impact": "Accesso ai database, esfiltrazione dati sensibili"
        },
        "postgres_exposed": {
            "name": "PostgreSQL Command Injection",
            "type": "Command Execution",
            "severity": "ALTA",
            "category": "DISTRUTTIVO",
            "description": "PostgreSQL esposto può permettere esecuzione comandi OS tramite funzioni come COPY o estensioni.",
            "tools": "pgcli, SQLMAP con --os-shell",
            "impact": "Esecuzione comandi sul server, lettura/scrittura file"
        },
        "ftp_anonymous": {
            "name": "FTP Anonymous Access",
            "type": "Information Disclosure / Upload",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Accesso anonimo FTP permette download file sensibili e potenziale upload di webshell.",
            "tools": "ftp client, wget, curl",
            "impact": "Furto credenziali, upload malware, accesso a backup"
        },
        "vnc_exposed": {
            "name": "VNC Brute Force",
            "type": "Unauthorized Access",
            "severity": "ALTA",
            "category": "DISTRUTTIVO",
            "description": "Server VNC esposto vulnerabile a brute force o bypass autenticazione.",
            "tools": "hydra, crowbar, vncviewer",
            "impact": "Controllo remoto completo del desktop"
        },
        "git_exposed": {
            "name": "Git Repository Extraction",
            "type": "Source Code Disclosure",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Directory .git esposta permette download completo del codice sorgente.",
            "tools": "git-dumper, GitTools",
            "impact": "Accesso codice sorgente, credenziali hardcoded"
        },
        "env_exposed": {
            "name": "Environment File Extraction",
            "type": "Credential Disclosure",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "File .env esposto contiene credenziali database, API keys.",
            "tools": "curl, wget, browser",
            "impact": "Accesso a database, servizi cloud, API"
        },
        "telnet": {
            "name": "Telnet Credential Sniffing",
            "type": "Man-in-the-Middle",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Traffico Telnet in chiaro può essere intercettato.",
            "tools": "Wireshark, tcpdump, ettercap",
            "impact": "Intercettazione credenziali"
        },
        "hsts_missing": {
            "name": "SSL Stripping Attack",
            "type": "Man-in-the-Middle",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Senza HSTS, attaccante può forzare downgrade a HTTP.",
            "tools": "sslstrip, bettercap, mitmproxy",
            "impact": "Intercettazione sessioni, furto cookie"
        },
        "xframe_missing": {
            "name": "Clickjacking Attack",
            "type": "UI Redressing",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Pagina può essere inclusa in iframe malevolo.",
            "tools": "Burp Suite, iframe HTML",
            "impact": "Azioni non autorizzate"
        },
        "csp_missing": {
            "name": "Cross-Site Scripting (XSS)",
            "type": "Script Injection",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Assenza di CSP facilita attacchi XSS.",
            "tools": "XSStrike, dalfox, Burp Suite",
            "impact": "Furto sessioni, keylogging"
        },
        "ssl_weak": {
            "name": "SSL/TLS Downgrade Attack",
            "type": "Cryptographic Attack",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Protocolli SSL/TLS deboli permettono attacchi POODLE, BEAST.",
            "tools": "testssl.sh, sslyze",
            "impact": "Decrittazione traffico"
        },
        "phpinfo_exposed": {
            "name": "PHPInfo Information Gathering",
            "type": "Information Disclosure",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "phpinfo() espone configurazione server.",
            "tools": "Browser, curl",
            "impact": "Raccolta info per attacchi mirati"
        },
        "ssh_weak": {
            "name": "SSH Brute Force Attack",
            "type": "Brute Force",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "SSH esposto è target per brute force.",
            "tools": "hydra, medusa, ncrack",
            "impact": "Accesso shell remota"
        }
    }


class ConfigManager:
    """Gestisce la configurazione da file config.ini"""
    
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_path = Path(__file__).parent / "config.ini"
        self.load()
    
    def load(self):
        """Carica la configurazione dal file"""
        if self.config_path.exists():
            self.config.read(self.config_path, encoding='utf-8')
    
    def get(self, section: str, key: str, fallback: str = "") -> str:
        """Ottiene un valore dalla configurazione"""
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Ottiene un valore booleano dalla configurazione"""
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """Ottiene un valore intero dalla configurazione"""
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    @property
    def gemini_api_key(self) -> str:
        key = self.get("GEMINI", "api_key", "")
        if key == "YOUR_GEMINI_API_KEY_HERE":
            return ""
        return key
    
    @property
    def gemini_model(self) -> str:
        return self.get("GEMINI", "model", "gemini-2.0-flash-exp")
    
    @property
    def gemini_timeout(self) -> int:
        return self.get_int("GEMINI", "timeout", 30)
    
    @property
    def language(self) -> str:
        return self.get("GEMINI", "language", "it")


class GeminiAnalyzer:
    """Analizzatore AI con Google Gemini"""
    
    def __init__(self, api_key: str = None, model: str = None):
        self.config_mgr = ConfigManager()
        self.api_key = api_key or self.config_mgr.gemini_api_key
        self.model = model or self.config_mgr.gemini_model
        self.timeout = self.config_mgr.gemini_timeout
        self.language = self.config_mgr.language
        self.last_analysis = None
        self.last_error = None
    
    @property
    def is_configured(self) -> bool:
        """Verifica se l'API key è configurata"""
        return bool(self.api_key and self.api_key != "YOUR_GEMINI_API_KEY_HERE")
    
    def analyze(self, scan_data: dict) -> dict:
        """Esegue l'analisi AI dei risultati della scansione"""
        if not self.is_configured:
            return {"error": "API key Gemini non configurata. Modifica config.ini"}
        
        if not HAS_REQUESTS:
            return {"error": "Modulo 'requests' non disponibile"}
        
        try:
            # Prepara il prompt
            prompt = self._build_prompt(scan_data)
            
            # Chiama l'API Gemini
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
            
            headers = {"Content-Type": "application/json"}
            data = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.7,
                    "maxOutputTokens": 2048
                }
            }
            
            response = requests.post(url, headers=headers, json=data, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                
                analysis = self._parse_response(text)
                self.last_analysis = analysis
                return analysis
            elif response.status_code == 403:
                # Errore di autorizzazione
                self.last_error = "API key non valida o non autorizzata. Verifica la chiave in config.ini e assicurati che sia abilitata per Gemini API su https://aistudio.google.com"
                return {"error": self.last_error}
            elif response.status_code == 429:
                self.last_error = "Rate limit superato. Attendi qualche minuto e riprova."
                return {"error": self.last_error}
            elif response.status_code == 404:
                self.last_error = f"Modello '{self.model}' non trovato. Verifica il nome del modello in config.ini"
                return {"error": self.last_error}
            else:
                # Prova a estrarre messaggio di errore JSON
                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", f"Errore HTTP {response.status_code}")
                except:
                    # Se la risposta non è JSON (es. HTML), mostra un messaggio generico
                    error_msg = f"Errore API Gemini: HTTP {response.status_code}. La risposta non è in formato JSON. Verifica l'API key."
                self.last_error = error_msg
                return {"error": error_msg}
                
        except requests.exceptions.Timeout:
            self.last_error = "Timeout nella richiesta a Gemini"
            return {"error": self.last_error}
        except Exception as e:
            self.last_error = str(e)
            return {"error": str(e)}
    
    def _build_prompt(self, scan_data: dict) -> str:
        """Costruisce il prompt per Gemini"""
        lang = "italiano" if self.language == "it" else "English"
        
        vulns_text = ""
        for v in scan_data.get("vulnerabilities", []):
            vulns_text += f"- [{v.get('severity')}] {v.get('title')}: {v.get('description')}\n"
        
        ports_text = ""
        for p in scan_data.get("open_ports", []):
            if isinstance(p, dict):
                ports_text += f"- Porta {p.get('port')}: {p.get('service')}\n"
            else:
                ports_text += f"- Porta {p}\n"
        
        geo = scan_data.get("geolocation", {})
        hosting = scan_data.get("hosting", {})
        
        prompt = f"""Sei un esperto di cybersecurity e penetration testing. Analizza i seguenti risultati di una scansione di vulnerabilità e fornisci un'analisi dettagliata in {lang}.

TARGET: {scan_data.get('target', 'N/A')}
IP: {scan_data.get('ip', 'N/A')}
LOCATION: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}
HOSTING: {hosting.get('provider', 'N/A')} ({'Hosting/Cloud' if hosting.get('is_hosting') else 'Residenziale'})

PORTE APERTE:
{ports_text or 'Nessuna porta aperta rilevata'}

VULNERABILITÀ RILEVATE:
{vulns_text or 'Nessuna vulnerabilità rilevata'}

Fornisci l'analisi nel seguente formato JSON (SOLO JSON, nessun testo prima o dopo):
{{
    "risk_score": <numero da 1 a 10>,
    "risk_level": "<CRITICO|ALTO|MEDIO|BASSO>",
    "executive_summary": "<breve sommario per dirigenti, 2-3 frasi>",
    "attack_chain": [
        {{"step": 1, "action": "<descrizione>", "tool": "<tool suggerito>"}},
        {{"step": 2, "action": "<descrizione>", "tool": "<tool suggerito>"}},
        ...
    ],
    "most_likely_scenario": "<descrizione dello scenario di attacco più probabile>",
    "time_to_compromise": "<stima tempo per compromissione>",
    "priority_actions": [
        "<azione prioritaria 1>",
        "<azione prioritaria 2>",
        "<azione prioritaria 3>"
    ],
    "detailed_recommendations": [
        {{"issue": "<problema>", "solution": "<soluzione dettagliata>", "priority": "<ALTA|MEDIA|BASSA>"}}
    ],
    "threat_actors": "<tipi di attori malevoli interessati a questo target>",
    "business_impact": "<impatto potenziale sul business>"
}}
"""
        return prompt
    
    def _parse_response(self, text: str) -> dict:
        """Parsa la risposta di Gemini con gestione robusta del JSON"""
        import re
        
        if not text:
            return {"parse_error": True, "error_msg": "Risposta vuota"}
        
        original_text = text
        text = text.strip()
        
        # Rimuovi eventuali backtick markdown (vari formati)
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```JSON"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        
        if text.endswith("```"):
            text = text[:-3]
        
        text = text.strip()
        
        # Metodo 1: Prova parsing diretto
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError as e:
            pass  # Continua con altri metodi
        
        # Metodo 2: Cerca JSON completo con regex
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            try:
                result = json.loads(json_match.group())
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass
        
        # Metodo 3: JSON potrebbe essere incompleto - prova a chiuderlo
        # Conta le parentesi graffe
        open_braces = text.count('{')
        close_braces = text.count('}')
        
        if open_braces > close_braces:
            # Mancano parentesi di chiusura
            fixed_text = text
            # Chiudi eventuali stringhe aperte
            if fixed_text.count('"') % 2 != 0:
                fixed_text += '"'
            # Chiudi eventuali array aperti
            open_brackets = fixed_text.count('[')
            close_brackets = fixed_text.count(']')
            fixed_text += ']' * (open_brackets - close_brackets)
            # Chiudi le parentesi graffe
            fixed_text += '}' * (open_braces - close_braces)
            
            try:
                result = json.loads(fixed_text)
                if isinstance(result, dict):
                    result["_json_repaired"] = True
                    return result
            except json.JSONDecodeError:
                pass
        
        # Metodo 4: Estrai i campi singolarmente con regex
        extracted = {}
        
        # Risk score
        score_match = re.search(r'"risk_score"\s*:\s*(\d+)', text)
        if score_match:
            extracted["risk_score"] = int(score_match.group(1))
        
        # Risk level
        level_match = re.search(r'"risk_level"\s*:\s*"([^"]+)"', text)
        if level_match:
            extracted["risk_level"] = level_match.group(1)
        
        # Executive summary
        summary_match = re.search(r'"executive_summary"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text)
        if summary_match:
            extracted["executive_summary"] = summary_match.group(1).replace('\\"', '"').replace('\\n', '\n')
        else:
            # Prova un pattern più permissivo
            summary_match = re.search(r'"executive_summary"\s*:\s*"(.{50,500}?)(?:"|,\s*")', text, re.DOTALL)
            if summary_match:
                extracted["executive_summary"] = summary_match.group(1)
        
        # Most likely scenario
        scenario_match = re.search(r'"most_likely_scenario"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text)
        if scenario_match:
            extracted["most_likely_scenario"] = scenario_match.group(1).replace('\\"', '"').replace('\\n', '\n')
        
        # Time to compromise
        ttc_match = re.search(r'"time_to_compromise"\s*:\s*"([^"]+)"', text)
        if ttc_match:
            extracted["time_to_compromise"] = ttc_match.group(1)
        
        # Business impact
        impact_match = re.search(r'"business_impact"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text)
        if impact_match:
            extracted["business_impact"] = impact_match.group(1).replace('\\"', '"').replace('\\n', '\n')
        
        # Threat actors
        actors_match = re.search(r'"threat_actors"\s*:\s*"([^"]+)"', text)
        if actors_match:
            extracted["threat_actors"] = actors_match.group(1)
        
        # Priority actions (array)
        actions_match = re.search(r'"priority_actions"\s*:\s*\[(.*?)\]', text, re.DOTALL)
        if actions_match:
            actions_text = actions_match.group(1)
            actions = re.findall(r'"([^"]+)"', actions_text)
            if actions:
                extracted["priority_actions"] = actions
        
        # Attack chain (array of objects)
        chain_match = re.search(r'"attack_chain"\s*:\s*\[(.*?)\]', text, re.DOTALL)
        if chain_match:
            chain_text = chain_match.group(1)
            # Estrai ogni step
            steps = []
            step_matches = re.findall(r'\{[^}]+\}', chain_text)
            for step_text in step_matches:
                step = {}
                step_num = re.search(r'"step"\s*:\s*(\d+)', step_text)
                if step_num:
                    step["step"] = int(step_num.group(1))
                action = re.search(r'"action"\s*:\s*"([^"]+)"', step_text)
                if action:
                    step["action"] = action.group(1)
                tool = re.search(r'"tool"\s*:\s*"([^"]+)"', step_text)
                if tool:
                    step["tool"] = tool.group(1)
                if step:
                    steps.append(step)
            if steps:
                extracted["attack_chain"] = steps
        
        # Detailed recommendations
        recs_match = re.search(r'"detailed_recommendations"\s*:\s*\[(.*?)\]', text, re.DOTALL)
        if recs_match:
            recs_text = recs_match.group(1)
            recs = []
            rec_matches = re.findall(r'\{[^}]+\}', recs_text)
            for rec_text in rec_matches:
                rec = {}
                issue = re.search(r'"issue"\s*:\s*"([^"]+)"', rec_text)
                if issue:
                    rec["issue"] = issue.group(1)
                solution = re.search(r'"solution"\s*:\s*"([^"]+)"', rec_text)
                if solution:
                    rec["solution"] = solution.group(1)
                priority = re.search(r'"priority"\s*:\s*"([^"]+)"', rec_text)
                if priority:
                    rec["priority"] = priority.group(1)
                if rec:
                    recs.append(rec)
            if recs:
                extracted["detailed_recommendations"] = recs
        
        # Se abbiamo estratto almeno risk_score o risk_level, consideriamo il parsing riuscito
        if extracted.get("risk_score") or extracted.get("risk_level"):
            extracted["_partial_parse"] = True
            return extracted
        
        # Fallback finale: restituisci i dati grezzi
        return {
            "raw_response": original_text,
            "risk_score": 0,
            "risk_level": "SCONOSCIUTO",
            "executive_summary": text[:500] if len(text) > 500 else text,
            "parse_error": True,
            "error_msg": "Impossibile estrarre dati strutturati dal JSON"
        }


class GeoHostingInfo:
    """Informazioni di geolocalizzazione e hosting"""
    
    def __init__(self):
        self.ip = ""
        self.country = ""
        self.country_code = ""
        self.region = ""
        self.region_name = ""
        self.city = ""
        self.zip_code = ""
        self.latitude = 0.0
        self.longitude = 0.0
        self.timezone = ""
        self.isp = ""
        self.organization = ""
        self.asn = ""
        self.asn_name = ""
        self.reverse_dns = ""
        self.is_mobile = False
        self.is_proxy = False
        self.is_hosting = False
        self.hosting_provider = ""
        self.datacenter = ""
    
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "geolocation": {
                "country": self.country,
                "country_code": self.country_code,
                "region": self.region,
                "region_name": self.region_name,
                "city": self.city,
                "zip_code": self.zip_code,
                "latitude": self.latitude,
                "longitude": self.longitude,
                "timezone": self.timezone
            },
            "network": {
                "isp": self.isp,
                "organization": self.organization,
                "asn": self.asn,
                "asn_name": self.asn_name,
                "reverse_dns": self.reverse_dns
            },
            "hosting": {
                "is_hosting": self.is_hosting,
                "is_proxy": self.is_proxy,
                "is_mobile": self.is_mobile,
                "provider": self.hosting_provider,
                "datacenter": self.datacenter
            }
        }
    
    @staticmethod
    def fetch(ip: str) -> 'GeoHostingInfo':
        """Recupera informazioni di geolocalizzazione e hosting"""
        info = GeoHostingInfo()
        info.ip = ip
        
        if not HAS_REQUESTS:
            return info
        
        # Prova ip-api.com (più completo)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    info.country = data.get("country", "")
                    info.country_code = data.get("countryCode", "")
                    info.region = data.get("region", "")
                    info.region_name = data.get("regionName", "")
                    info.city = data.get("city", "")
                    info.zip_code = data.get("zip", "")
                    info.latitude = data.get("lat", 0.0)
                    info.longitude = data.get("lon", 0.0)
                    info.timezone = data.get("timezone", "")
                    info.isp = data.get("isp", "")
                    info.organization = data.get("org", "")
                    info.asn = data.get("as", "")
                    info.asn_name = data.get("asname", "")
                    info.reverse_dns = data.get("reverse", "")
                    info.is_mobile = data.get("mobile", False)
                    info.is_proxy = data.get("proxy", False)
                    info.is_hosting = data.get("hosting", False)
                    
                    # Determina hosting provider
                    if info.is_hosting:
                        info.hosting_provider = info.organization or info.isp
                        info._detect_hosting_provider()
                    
                    return info
        except Exception:
            pass
        
        # Fallback: ipwho.is
        try:
            url = f"https://ipwho.is/{ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("success", True):
                    info.country = data.get("country", "")
                    info.country_code = data.get("country_code", "")
                    info.region = data.get("region", "")
                    info.region_name = data.get("region", "")
                    info.city = data.get("city", "")
                    info.zip_code = data.get("postal", "")
                    info.latitude = data.get("latitude", 0.0)
                    info.longitude = data.get("longitude", 0.0)
                    info.timezone = data.get("timezone", {}).get("id", "")
                    
                    conn = data.get("connection", {})
                    info.isp = conn.get("isp", "")
                    info.organization = conn.get("org", "")
                    info.asn = f"AS{conn.get('asn', '')}"
                    
                    # Controllo hosting
                    security = data.get("security", {})
                    info.is_proxy = security.get("proxy", False)
                    info.is_hosting = data.get("type", "") == "hosting"
                    
                    info._detect_hosting_provider()
                    return info
        except Exception:
            pass
        
        return info
    
    def _detect_hosting_provider(self):
        """Rileva il provider di hosting dal nome organizzazione/ISP"""
        org_lower = (self.organization + " " + self.isp + " " + self.asn_name).lower()
        
        hosting_providers = {
            "amazon": ("Amazon Web Services (AWS)", "AWS Datacenter"),
            "aws": ("Amazon Web Services (AWS)", "AWS Datacenter"),
            "google": ("Google Cloud Platform", "Google Datacenter"),
            "gcp": ("Google Cloud Platform", "Google Datacenter"),
            "microsoft": ("Microsoft Azure", "Azure Datacenter"),
            "azure": ("Microsoft Azure", "Azure Datacenter"),
            "digitalocean": ("DigitalOcean", "DO Datacenter"),
            "linode": ("Linode (Akamai)", "Linode Datacenter"),
            "vultr": ("Vultr", "Vultr Datacenter"),
            "ovh": ("OVH", "OVH Datacenter"),
            "hetzner": ("Hetzner", "Hetzner Datacenter"),
            "cloudflare": ("Cloudflare", "Cloudflare Edge"),
            "fastly": ("Fastly", "Fastly Edge"),
            "akamai": ("Akamai", "Akamai Edge"),
            "godaddy": ("GoDaddy", "GoDaddy Hosting"),
            "hostgator": ("HostGator", "HostGator"),
            "bluehost": ("Bluehost", "Bluehost"),
            "namecheap": ("Namecheap", "Namecheap Hosting"),
            "ionos": ("IONOS", "IONOS Datacenter"),
            "scaleway": ("Scaleway", "Scaleway Datacenter"),
            "contabo": ("Contabo", "Contabo Datacenter"),
            "aruba": ("Aruba", "Aruba Datacenter"),
            "oracle": ("Oracle Cloud", "Oracle Datacenter"),
            "ibm": ("IBM Cloud", "IBM Datacenter"),
            "rackspace": ("Rackspace", "Rackspace Datacenter"),
            "alibaba": ("Alibaba Cloud", "Alibaba Datacenter"),
            "tencent": ("Tencent Cloud", "Tencent Datacenter"),
            "leaseweb": ("Leaseweb", "Leaseweb Datacenter"),
            "hostinger": ("Hostinger", "Hostinger"),
            "siteground": ("SiteGround", "SiteGround")
        }
        
        for keyword, (provider, datacenter) in hosting_providers.items():
            if keyword in org_lower:
                self.hosting_provider = provider
                self.datacenter = datacenter
                return
        
        # Se non trovato ma è hosting
        if self.is_hosting:
            self.hosting_provider = self.organization or self.isp or "Unknown Hosting"
            self.datacenter = "Unknown Datacenter"


class SSLInfo:
    """Informazioni certificato SSL"""
    
    def __init__(self):
        self.version = ""
        self.cipher = ""
        self.cipher_bits = 0
        self.issuer = ""
        self.subject = ""
        self.valid_from = ""
        self.valid_to = ""
        self.is_expired = False
        self.san = []
        self.errors = []
    
    def to_dict(self) -> dict:
        return {
            "protocol_version": self.version,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "issuer": self.issuer,
            "subject": self.subject,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "is_expired": self.is_expired,
            "san": self.san,
            "errors": self.errors
        }
    
    @staticmethod
    def fetch(target: str, port: int = 443) -> 'SSLInfo':
        """Recupera informazioni SSL/TLS"""
        info = SSLInfo()
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=Config.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    info.version = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        info.cipher = cipher[0]
                        info.cipher_bits = cipher[2] if len(cipher) > 2 else 0
                    
                    # Ottieni certificato
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        try:
                            import ssl as ssl_module
                            cert_decoded = ssl_module.DER_cert_to_PEM_cert(cert)
                            # Parse del certificato
                            peer_cert = ssock.getpeercert()
                            if peer_cert:
                                # Issuer
                                issuer_parts = []
                                for item in peer_cert.get("issuer", []):
                                    for key, value in item:
                                        issuer_parts.append(f"{key}={value}")
                                info.issuer = ", ".join(issuer_parts)
                                
                                # Subject
                                subject_parts = []
                                for item in peer_cert.get("subject", []):
                                    for key, value in item:
                                        subject_parts.append(f"{key}={value}")
                                info.subject = ", ".join(subject_parts)
                                
                                # Validità
                                info.valid_from = peer_cert.get("notBefore", "")
                                info.valid_to = peer_cert.get("notAfter", "")
                                
                                # SAN
                                san = peer_cert.get("subjectAltName", [])
                                info.san = [item[1] for item in san if item[0] == "DNS"]
                        except Exception:
                            pass
        except ssl.SSLCertVerificationError as e:
            info.errors.append(f"Certificate verification failed: {str(e)}")
        except Exception as e:
            info.errors.append(str(e))
        
        return info


class WebTechInfo:
    """Informazioni tecnologie web"""
    
    def __init__(self):
        self.server = ""
        self.powered_by = ""
        self.cms = ""
        self.framework = ""
        self.cookies = []
        self.security_headers = {}
        self.missing_headers = []
    
    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "powered_by": self.powered_by,
            "cms": self.cms,
            "framework": self.framework,
            "cookies": self.cookies,
            "security_headers": self.security_headers,
            "missing_headers": self.missing_headers
        }
    
    @staticmethod
    def fetch(target: str, port: int = 443, https: bool = True) -> 'WebTechInfo':
        """Rileva tecnologie web"""
        info = WebTechInfo()
        
        if not HAS_REQUESTS:
            return info
        
        protocol = "https" if https else "http"
        port_str = "" if (https and port == 443) or (not https and port == 80) else f":{port}"
        url = f"{protocol}://{target}{port_str}"
        
        try:
            response = requests.get(url, timeout=Config.TIMEOUT, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Server
            info.server = headers.get("Server", "")
            
            # X-Powered-By
            info.powered_by = headers.get("X-Powered-By", "")
            
            # Security headers
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "Content-Security-Policy": "CSP",
                "X-XSS-Protection": "X-XSS-Protection",
                "Referrer-Policy": "Referrer-Policy",
                "Permissions-Policy": "Permissions-Policy"
            }
            
            for header, name in security_headers.items():
                if header in headers:
                    info.security_headers[name] = headers[header]
                else:
                    info.missing_headers.append(name)
            
            # Cookies
            for cookie in response.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("httponly") or "httponly" in str(cookie).lower(),
                    "samesite": cookie.get_nonstandard_attr("samesite", "None")
                }
                info.cookies.append(cookie_info)
            
            # Rileva CMS/Framework dal contenuto
            text = response.text.lower()
            
            if "wp-content" in text or "wp-includes" in text:
                info.cms = "WordPress"
            elif "joomla" in text:
                info.cms = "Joomla"
            elif "drupal" in text:
                info.cms = "Drupal"
            elif "magento" in text:
                info.cms = "Magento"
            elif "prestashop" in text:
                info.cms = "PrestaShop"
            elif "shopify" in text:
                info.cms = "Shopify"
            
            # Framework detection
            if "laravel" in text or "laravel" in info.powered_by.lower():
                info.framework = "Laravel"
            elif "django" in text:
                info.framework = "Django"
            elif "express" in info.powered_by.lower():
                info.framework = "Express.js"
            elif "asp.net" in info.powered_by.lower():
                info.framework = "ASP.NET"
            elif "php" in info.powered_by.lower():
                info.framework = "PHP"
            elif "ruby" in info.powered_by.lower():
                info.framework = "Ruby"
            elif "next" in text:
                info.framework = "Next.js"
            elif "nuxt" in text:
                info.framework = "Nuxt.js"
                
        except Exception:
            pass
        
        return info


class NetworkChecker:
    """Verifica configurazione rete"""
    
    def __init__(self):
        self.interfaces = []
        self.gateway = None
        self.dns_servers = []
        self.public_ip = None
        self.tor_status = {
            "active": False, 
            "process_running": False, 
            "socks_port_open": False,
            "control_port_open": False, 
            "exit_node": None, 
            "control_type": None
        }
    
    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return ""
    
    def check_all(self):
        self._get_interfaces()
        self._get_gateway()
        self._get_dns()
        self._check_tor()
        self._get_public_ip()
    
    def _get_interfaces(self):
        self.interfaces = []
        try:
            output = self._run_command(["ip", "addr", "show"])
            if output:
                current_iface = None
                for line in output.split('\n'):
                    iface_match = re.match(r'^\d+:\s+(\S+?)[@:].*state\s+(\w+)', line)
                    if iface_match:
                        name, state = iface_match.groups()
                        current_iface = {"name": name, "addresses": []} if state == "UP" and name != "lo" else None
                    elif current_iface and "inet " in line and "inet6" not in line:
                        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', line)
                        if match:
                            current_iface["addresses"].append(match.group(1))
                            if current_iface not in self.interfaces:
                                self.interfaces.append(current_iface)
        except Exception:
            pass
    
    def _get_gateway(self):
        try:
            output = self._run_command(["ip", "route", "show", "default"])
            if output:
                match = re.search(r'default via (\S+)', output)
                if match:
                    self.gateway = match.group(1)
        except Exception:
            pass
    
    def _get_dns(self):
        self.dns_servers = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('nameserver'):
                        parts = line.split()
                        if len(parts) >= 2:
                            self.dns_servers.append(parts[1])
        except Exception:
            pass
    
    def _get_public_ip(self):
        if HAS_REQUESTS:
            try:
                response = requests.get("https://api.ipify.org?format=json", timeout=5)
                if response.status_code == 200:
                    self.public_ip = response.json().get("ip")
            except Exception:
                pass
    
    def _check_tor(self):
        self.tor_status = {
            "active": False, 
            "process_running": False, 
            "socks_port_open": False,
            "control_port_open": False, 
            "exit_node": None, 
            "control_type": None
        }
        
        try:
            output = self._run_command(["pgrep", "-x", "tor"])
            if output:
                self.tor_status["process_running"] = True
                self.tor_status["tor_pid"] = output.strip().split('\n')[0]
        except Exception:
            pass
        
        for port in [9050, 9150]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    self.tor_status["socks_port_open"] = True
                    self.tor_status["tor_browser"] = (port == 9150)
                sock.close()
                if self.tor_status["socks_port_open"]:
                    break
            except Exception:
                pass
        
        for port in [9051, 9151]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    self.tor_status["control_port_open"] = True
                    self.tor_status["control_type"] = f"TCP:{port}"
                sock.close()
                if self.tor_status["control_port_open"]:
                    break
            except Exception:
                pass
        
        if not self.tor_status["control_port_open"]:
            for path in ["/var/run/tor/control", "/run/tor/control"]:
                if os.path.exists(path):
                    try:
                        import stat
                        if stat.S_ISSOCK(os.stat(path).st_mode):
                            self.tor_status["control_port_open"] = True
                            self.tor_status["control_type"] = f"Unix:{path}"
                            break
                    except Exception:
                        pass
        
        if self.tor_status["process_running"] and self.tor_status["socks_port_open"]:
            self.tor_status["active"] = True
        
        if HAS_REQUESTS and self.tor_status["socks_port_open"]:
            try:
                socks_port = 9150 if self.tor_status.get("tor_browser") else 9050
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socks_port}", 
                    "https": f"socks5h://127.0.0.1:{socks_port}"
                }
                response = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("IsTor"):
                        self.tor_status["exit_node"] = data.get("IP")
            except Exception:
                pass
    
    def to_dict(self) -> dict:
        return {
            "interfaces": self.interfaces,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "public_ip": self.public_ip,
            "tor_status": self.tor_status
        }


class HTMLReportGenerator:
    """Generatore di report HTML professionali"""
    
    @staticmethod
    def generate(scan_data: dict) -> str:
        """Genera un report HTML professionale"""
        
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        target = scan_data.get("target", "N/A")
        ip = scan_data.get("ip", "N/A")
        
        # Conteggio vulnerabilità per severità
        vulns = scan_data.get("vulnerabilities", [])
        vuln_counts = {
            "CRITICA": len([v for v in vulns if v.get("severity") == "CRITICA"]),
            "ALTA": len([v for v in vulns if v.get("severity") == "ALTA"]),
            "MEDIA": len([v for v in vulns if v.get("severity") == "MEDIA"]),
            "BASSA": len([v for v in vulns if v.get("severity") == "BASSA"])
        }
        
        # Determina livello di rischio - usa AI se disponibile
        ai_analysis = scan_data.get("ai_analysis")
        ai_risk_level = None
        if ai_analysis:
            ai_rl = ai_analysis.get("risk_level")
            if ai_rl and ai_rl not in ["SCONOSCIUTO", "ERRORE", "N/A", None]:
                ai_risk_level = ai_rl
        
        if ai_risk_level:
            risk_level = ai_risk_level
            risk_source = "AI"
            # Colore basato sul livello AI
            if risk_level == "CRITICO":
                risk_color = "#FF3B3B"
            elif risk_level == "ALTO":
                risk_color = "#FF8C00"
            elif risk_level == "MEDIO":
                risk_color = "#FFB800"
            else:
                risk_color = "#00D26A"
        elif vuln_counts["CRITICA"] > 0:
            risk_level = "CRITICO"
            risk_color = "#FF3B3B"
        elif vuln_counts["ALTA"] > 0:
            risk_level = "ALTO"
            risk_color = "#FF8C00"
        elif vuln_counts["MEDIA"] > 0:
            risk_level = "MEDIO"
            risk_color = "#FFB800"
        elif vuln_counts["BASSA"] > 0:
            risk_level = "BASSO"
            risk_color = "#00D26A"
        else:
            risk_level = "MINIMO"
            risk_color = "#00D26A"
        
        # Dati geolocalizzazione
        geo = scan_data.get("geolocation", {})
        hosting = scan_data.get("hosting", {})
        network = scan_data.get("network_info", {})
        
        # HTML Template
        html = f'''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Vulnerabilità - {target}</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #ffffff;
            --text-secondary: #a0a0a0;
            --accent: #0ea5e9;
            --success: #00d26a;
            --warning: #ffb800;
            --danger: #ff3b3b;
            --danger-alt: #ff8c00;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--danger), var(--warning), var(--success));
        }}
        
        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .header-title h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #fff, var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .header-title p {{
            color: var(--text-secondary);
            font-size: 1.1em;
        }}
        
        .risk-badge {{
            background: {risk_color};
            color: #000;
            padding: 15px 30px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 1.2em;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }}
        
        .risk-badge span {{
            display: block;
            font-size: 0.7em;
            opacity: 0.8;
            margin-bottom: 5px;
        }}
        
        /* Info Grid */
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .info-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        
        .info-card h3 {{
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .info-card h3::before {{
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent);
            border-radius: 2px;
        }}
        
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.03);
        }}
        
        .info-row:last-child {{
            border-bottom: none;
        }}
        
        .info-label {{
            color: var(--text-secondary);
        }}
        
        .info-value {{
            color: var(--text-primary);
            font-weight: 500;
            text-align: right;
            max-width: 60%;
            word-break: break-all;
        }}
        
        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid;
        }}
        
        .stat-card.critical {{ border-color: var(--danger); }}
        .stat-card.high {{ border-color: var(--danger-alt); }}
        .stat-card.medium {{ border-color: var(--warning); }}
        .stat-card.low {{ border-color: var(--success); }}
        .stat-card.ports {{ border-color: var(--accent); }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .stat-number {{ color: var(--danger); }}
        .stat-card.high .stat-number {{ color: var(--danger-alt); }}
        .stat-card.medium .stat-number {{ color: var(--warning); }}
        .stat-card.low .stat-number {{ color: var(--success); }}
        .stat-card.ports .stat-number {{ color: var(--accent); }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        
        /* Sections */
        .section {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        
        .section h2 {{
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        /* Vulnerability Cards */
        .vuln-card {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        
        .vuln-card.CRITICA {{ border-color: var(--danger); }}
        .vuln-card.ALTA {{ border-color: var(--danger-alt); }}
        .vuln-card.MEDIA {{ border-color: var(--warning); }}
        .vuln-card.BASSA {{ border-color: var(--success); }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .vuln-title {{
            font-size: 1.2em;
            font-weight: 600;
        }}
        
        .vuln-badges {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .severity-badge.CRITICA {{ background: var(--danger); color: #fff; }}
        .severity-badge.ALTA {{ background: var(--danger-alt); color: #000; }}
        .severity-badge.MEDIA {{ background: var(--warning); color: #000; }}
        .severity-badge.BASSA {{ background: var(--success); color: #000; }}
        
        .cve-badge {{
            background: rgba(255,107,107,0.2);
            color: #ff6b6b;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.8em;
            font-family: monospace;
        }}
        
        .vuln-description {{
            color: var(--text-secondary);
            margin-bottom: 10px;
        }}
        
        .vuln-remediation {{
            color: var(--accent);
            font-style: italic;
        }}
        
        .vuln-remediation::before {{
            content: "→ Rimedio: ";
            font-weight: bold;
            font-style: normal;
        }}
        
        /* Port Table */
        .port-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .port-table th,
        .port-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        
        .port-table th {{
            background: var(--bg-secondary);
            color: var(--accent);
            font-weight: 600;
        }}
        
        .port-table tr:hover {{
            background: rgba(255,255,255,0.02);
        }}
        
        .port-status {{
            display: inline-block;
            width: 10px;
            height: 10px;
            background: var(--success);
            border-radius: 50%;
            margin-right: 8px;
        }}
        
        /* Map placeholder */
        .map-container {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        
        .coordinates {{
            font-family: monospace;
            color: var(--accent);
            font-size: 1.1em;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            border-top: 1px solid rgba(255,255,255,0.05);
            margin-top: 30px;
        }}
        
        .footer-logo {{
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--text-primary);
        }}
        
        /* Hosting Badge */
        .hosting-badge {{
            display: inline-block;
            background: rgba(14, 165, 233, 0.2);
            color: var(--accent);
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 500;
            margin-top: 10px;
        }}
        
        /* Print styles */
        @media print {{
            body {{ background: #fff; color: #000; }}
            .header {{ background: #f0f0f0; }}
            .info-card, .section {{ background: #f8f8f8; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="header-title">
                    <h1>🔒 Report Vulnerabilità</h1>
                    <p>Analisi di sicurezza per <strong>{target}</strong></p>
                    <p style="font-size: 0.9em; margin-top: 10px;">📅 {timestamp}</p>
                </div>
                <div class="risk-badge">
                    <span>LIVELLO DI RISCHIO</span>
                    {risk_level}
                </div>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">{vuln_counts['CRITICA']}</div>
                <div class="stat-label">Critiche</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{vuln_counts['ALTA']}</div>
                <div class="stat-label">Alte</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{vuln_counts['MEDIA']}</div>
                <div class="stat-label">Medie</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{vuln_counts['BASSA']}</div>
                <div class="stat-label">Basse</div>
            </div>
            <div class="stat-card ports">
                <div class="stat-number">{len(scan_data.get('open_ports', []))}</div>
                <div class="stat-label">Porte Aperte</div>
            </div>
        </div>
        
        <!-- Info Grid -->
        <div class="info-grid">
            <!-- Target Info -->
            <div class="info-card">
                <h3>Informazioni Target</h3>
                <div class="info-row">
                    <span class="info-label">Dominio/Host</span>
                    <span class="info-value">{target}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Indirizzo IP</span>
                    <span class="info-value">{ip}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Reverse DNS</span>
                    <span class="info-value">{network.get('reverse_dns', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Data Scansione</span>
                    <span class="info-value">{timestamp}</span>
                </div>
            </div>
            
            <!-- Geolocation -->
            <div class="info-card">
                <h3>Geolocalizzazione</h3>
                <div class="info-row">
                    <span class="info-label">Paese</span>
                    <span class="info-value">{geo.get('country', 'N/A')} ({geo.get('country_code', '')})</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Regione</span>
                    <span class="info-value">{geo.get('region_name', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Città</span>
                    <span class="info-value">{geo.get('city', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">CAP</span>
                    <span class="info-value">{geo.get('zip_code', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Coordinate</span>
                    <span class="info-value">{geo.get('latitude', 0)}, {geo.get('longitude', 0)}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Timezone</span>
                    <span class="info-value">{geo.get('timezone', 'N/A')}</span>
                </div>
            </div>
            
            <!-- Network Info -->
            <div class="info-card">
                <h3>Informazioni Rete</h3>
                <div class="info-row">
                    <span class="info-label">ISP</span>
                    <span class="info-value">{network.get('isp', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Organizzazione</span>
                    <span class="info-value">{network.get('organization', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">ASN</span>
                    <span class="info-value">{network.get('asn', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">ASN Name</span>
                    <span class="info-value">{network.get('asn_name', 'N/A')}</span>
                </div>
            </div>
            
            <!-- Hosting Info -->
            <div class="info-card">
                <h3>Hosting</h3>
                <div class="info-row">
                    <span class="info-label">È Hosting</span>
                    <span class="info-value">{"✅ Sì" if hosting.get('is_hosting') else "❌ No"}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">È Proxy</span>
                    <span class="info-value">{"✅ Sì" if hosting.get('is_proxy') else "❌ No"}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Provider</span>
                    <span class="info-value">{hosting.get('provider', 'N/A')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Datacenter</span>
                    <span class="info-value">{hosting.get('datacenter', 'N/A')}</span>
                </div>
            </div>
        </div>
'''
        
        # Sezione Porte Aperte
        open_ports = scan_data.get("open_ports", [])
        if open_ports:
            html += '''
        <!-- Open Ports -->
        <div class="section">
            <h2>🔌 Porte Aperte</h2>
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Stato</th>
                        <th>Porta</th>
                        <th>Servizio</th>
                        <th>Protocollo</th>
                    </tr>
                </thead>
                <tbody>
'''
            for port_info in open_ports:
                port = port_info.get("port", "")
                service = port_info.get("service", "")
                html += f'''
                    <tr>
                        <td><span class="port-status"></span>Aperta</td>
                        <td><strong>{port}</strong></td>
                        <td>{service}</td>
                        <td>TCP</td>
                    </tr>
'''
            html += '''
                </tbody>
            </table>
        </div>
'''
        
        # Sezione SSL/TLS
        ssl_info = scan_data.get("ssl_info", {})
        if ssl_info and ssl_info.get("protocol_version"):
            html += f'''
        <!-- SSL/TLS Info -->
        <div class="section">
            <h2>🔐 Configurazione SSL/TLS</h2>
            <div class="info-grid" style="grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));">
                <div class="info-card" style="margin-bottom: 0;">
                    <div class="info-row">
                        <span class="info-label">Protocollo</span>
                        <span class="info-value">{ssl_info.get('protocol_version', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Cipher Suite</span>
                        <span class="info-value">{ssl_info.get('cipher', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Bits</span>
                        <span class="info-value">{ssl_info.get('cipher_bits', 'N/A')}</span>
                    </div>
                </div>
                <div class="info-card" style="margin-bottom: 0;">
                    <div class="info-row">
                        <span class="info-label">Issuer</span>
                        <span class="info-value">{ssl_info.get('issuer', 'N/A')[:50]}...</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Valido dal</span>
                        <span class="info-value">{ssl_info.get('valid_from', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Valido fino</span>
                        <span class="info-value">{ssl_info.get('valid_to', 'N/A')}</span>
                    </div>
                </div>
            </div>
        </div>
'''
        
        # Sezione Web Technologies
        web_tech = scan_data.get("web_technologies", {})
        if web_tech and (web_tech.get("server") or web_tech.get("cms")):
            html += f'''
        <!-- Web Technologies -->
        <div class="section">
            <h2>🌐 Tecnologie Web Rilevate</h2>
            <div class="info-grid" style="grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));">
                <div class="info-card" style="margin-bottom: 0;">
                    <div class="info-row">
                        <span class="info-label">Server</span>
                        <span class="info-value">{web_tech.get('server', 'N/A')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Powered By</span>
                        <span class="info-value">{web_tech.get('powered_by', 'N/A') or 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">CMS</span>
                        <span class="info-value">{web_tech.get('cms', 'N/A') or 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Framework</span>
                        <span class="info-value">{web_tech.get('framework', 'N/A') or 'N/A'}</span>
                    </div>
                </div>
            </div>
'''
            # Security headers
            missing = web_tech.get("missing_headers", [])
            if missing:
                html += f'''
            <div style="margin-top: 20px;">
                <h4 style="color: var(--warning); margin-bottom: 10px;">⚠️ Header di sicurezza mancanti:</h4>
                <p style="color: var(--text-secondary);">{", ".join(missing)}</p>
            </div>
'''
            html += '''
        </div>
'''
        
        # Sezione Vulnerabilità
        if vulns:
            html += '''
        <!-- Vulnerabilities -->
        <div class="section">
            <h2>⚠️ Vulnerabilità Rilevate</h2>
'''
            # Ordina per severità
            severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3}
            sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get("severity", ""), 4))
            
            for vuln in sorted_vulns:
                severity = vuln.get("severity", "")
                title = vuln.get("title", "")
                description = vuln.get("description", "")
                remediation = vuln.get("remediation", "")
                cve = vuln.get("cve", "")
                cve_desc = vuln.get("cve_desc", "")
                
                html += f'''
            <div class="vuln-card {severity}">
                <div class="vuln-header">
                    <span class="vuln-title">{title}</span>
                    <div class="vuln-badges">
                        <span class="severity-badge {severity}">{severity}</span>
'''
                if cve:
                    html += f'''
                        <span class="cve-badge">{cve}</span>
'''
                html += f'''
                    </div>
                </div>
                <p class="vuln-description">{description}</p>
'''
                if cve_desc:
                    html += f'''
                <p style="color: #ff9999; font-size: 0.9em; margin-bottom: 10px;">ℹ️ {cve_desc}</p>
'''
                html += f'''
                <p class="vuln-remediation">{remediation}</p>
            </div>
'''
            html += '''
        </div>
'''
        else:
            html += '''
        <!-- No Vulnerabilities -->
        <div class="section" style="text-align: center; padding: 40px;">
            <h2 style="color: var(--success);">✅ Nessuna Vulnerabilità Critica Rilevata</h2>
            <p style="color: var(--text-secondary); margin-top: 10px;">Il target sembra essere configurato correttamente.</p>
        </div>
'''
        
        # Sezione Attacchi Possibili
        attacks = scan_data.get("possible_attacks", [])
        attacks_data = scan_data.get("attacks", {})
        destructive_attacks = attacks_data.get("destructive_attacks", []) if attacks_data else []
        probable_attacks = attacks_data.get("probable_attacks", []) if attacks_data else []
        
        # Se abbiamo il nuovo formato con attacchi separati
        if destructive_attacks or probable_attacks:
            severity_colors = {"CRITICA": "#FF3B3B", "ALTA": "#FF8C00", "MEDIA": "#FFB800", "BASSA": "#00D26A"}
            
            # Attacchi Distruttivi
            if destructive_attacks:
                html += '''
        <!-- Destructive Attacks -->
        <div class="section">
            <h2>💀 Attacchi Distruttivi (Compromissione Totale)</h2>
            <p style="color: var(--danger); margin-bottom: 20px; font-weight: 500;">
                ⚠️ Attacchi che permettono la compromissione completa del sistema:
            </p>
'''
                for i, attack in enumerate(destructive_attacks, 1):
                    name = attack.get("name", "")
                    attack_type = attack.get("type", "")
                    severity = attack.get("severity", "CRITICA")
                    description = attack.get("description", "")
                    tools = attack.get("tools", "")
                    impact = attack.get("impact", "")
                    time_exploit = attack.get("time_to_exploit", "N/A")
                    color = severity_colors.get(severity, "#FF3B3B")
                    
                    html += f'''
            <div class="vuln-card" style="border-left-color: {color}; border-left-width: 4px;">
                <div class="vuln-header">
                    <span class="vuln-severity" style="background: {color}; color: #000;">💀 DISTRUTTIVO #{i}</span>
                    <span class="vuln-title">{name}</span>
                    <span class="vuln-cve" style="background: #2a1a3a; color: {color};">{severity}</span>
                </div>
                <p style="color: #60A5FA; font-size: 0.95em; margin-bottom: 8px;">📌 Tipo: {attack_type}</p>
                <p class="vuln-desc">{description}</p>
                <p style="color: #FFB800; font-size: 0.9em; margin-bottom: 8px;">🔧 Tools: {tools}</p>
                <p style="color: #FF6B6B; font-size: 0.9em; margin-bottom: 8px;">💥 Impatto: {impact}</p>
                <p style="color: #E879F9; font-size: 0.9em;">⏱️ Tempo exploit: {time_exploit}</p>
            </div>
'''
                html += '''
        </div>
'''
            
            # Attacchi Probabili
            if probable_attacks:
                html += '''
        <!-- Probable Attacks -->
        <div class="section">
            <h2>🎯 Attacchi Probabili (Backdoor e Persistenza)</h2>
            <p style="color: var(--warning); margin-bottom: 20px; font-weight: 500;">
                ⚠️ Attacchi realistici che un attaccante userebbe per persistenza e accesso:
            </p>
'''
                for i, attack in enumerate(probable_attacks, 1):
                    name = attack.get("name", "")
                    attack_type = attack.get("type", "")
                    severity = attack.get("severity", "ALTA")
                    description = attack.get("description", "")
                    tools = attack.get("tools", "")
                    impact = attack.get("impact", "")
                    time_exploit = attack.get("time_to_exploit", "N/A")
                    color = severity_colors.get(severity, "#FF8C00")
                    
                    html += f'''
            <div class="vuln-card" style="border-left-color: {color}; border-left-width: 4px;">
                <div class="vuln-header">
                    <span class="vuln-severity" style="background: {color}; color: #000;">🎯 PROBABILE #{i}</span>
                    <span class="vuln-title">{name}</span>
                    <span class="vuln-cve" style="background: #2a1a3a; color: {color};">{severity}</span>
                </div>
                <p style="color: #60A5FA; font-size: 0.95em; margin-bottom: 8px;">📌 Tipo: {attack_type}</p>
                <p class="vuln-desc">{description}</p>
                <p style="color: #FFB800; font-size: 0.9em; margin-bottom: 8px;">🔧 Tools: {tools}</p>
                <p style="color: #FF6B6B; font-size: 0.9em; margin-bottom: 8px;">💥 Impatto: {impact}</p>
                <p style="color: #E879F9; font-size: 0.9em;">⏱️ Tempo exploit: {time_exploit}</p>
            </div>
'''
                html += '''
        </div>
'''
        
        # Fallback per il vecchio formato (retrocompatibilità)
        elif attacks:
            html += '''
        <!-- Possible Attacks (Legacy) -->
        <div class="section">
            <h2>🎯 Attacchi Possibili</h2>
            <p style="color: var(--danger); margin-bottom: 20px; font-weight: 500;">
                ⚠️ Basandosi sulle vulnerabilità rilevate, il server potrebbe essere soggetto ai seguenti attacchi:
            </p>
'''
            severity_colors = {"CRITICA": "#FF3B3B", "ALTA": "#FF8C00", "MEDIA": "#FFB800", "BASSA": "#00D26A"}
            
            for i, attack in enumerate(attacks, 1):
                name = attack.get("name", "")
                attack_type = attack.get("type", "")
                severity = attack.get("severity", "MEDIA")
                description = attack.get("description", "")
                tools = attack.get("tools", "")
                impact = attack.get("impact", "")
                color = severity_colors.get(severity, "#FFB800")
                
                html += f'''
            <div class="vuln-card" style="border-left-color: {color};">
                <div class="vuln-header">
                    <span class="vuln-severity" style="background: {color}; color: #000;">ATTACCO #{i}</span>
                    <span class="vuln-title">{name}</span>
                    <span class="vuln-cve" style="background: #2a1a3a; color: {color};">{severity}</span>
                </div>
                <p style="color: #60A5FA; font-size: 0.95em; margin-bottom: 8px;">📌 Tipo: {attack_type}</p>
                <p class="vuln-desc">{description}</p>
                <p style="color: #FFB800; font-size: 0.9em; margin-bottom: 8px;">🔧 Tools: {tools}</p>
                <p style="color: #FF6B6B; font-size: 0.9em; margin-bottom: 10px;">💥 Impatto: {impact}</p>
            </div>
'''
            html += '''
        </div>
'''
        
        # Sezione AI Analysis
        ai_analysis = scan_data.get("ai_analysis")
        # Mostra analisi AI se abbiamo dati validi (anche con parsing parziale)
        ai_has_data = ai_analysis and (
            ai_analysis.get("risk_score", 0) > 0 or 
            (ai_analysis.get("risk_level") and ai_analysis.get("risk_level") not in ["SCONOSCIUTO", "ERRORE", "N/A"])
        )
        if ai_has_data:
            risk_score = ai_analysis.get("risk_score", 0)
            risk_level = ai_analysis.get("risk_level", "N/A")
            
            # Colore basato sul risk score
            if risk_score >= 8:
                risk_color = "#FF3B3B"
                risk_bg = "rgba(255, 59, 59, 0.1)"
            elif risk_score >= 5:
                risk_color = "#FF8C00"
                risk_bg = "rgba(255, 140, 0, 0.1)"
            else:
                risk_color = "#00D26A"
                risk_bg = "rgba(0, 210, 106, 0.1)"
            
            html += f'''
        <!-- AI Analysis Section -->
        <div class="section" style="border: 2px solid {risk_color}; background: {risk_bg};">
            <h2 style="color: {risk_color};">🤖 Analisi AI Gemini</h2>
            
            <!-- Risk Score -->
            <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 25px; padding: 20px; background: var(--bg-secondary); border-radius: 12px;">
                <div style="text-align: center; min-width: 120px;">
                    <div style="font-size: 3em; font-weight: bold; color: {risk_color};">{risk_score}/10</div>
                    <div style="color: var(--text-secondary); font-size: 0.9em;">Risk Score</div>
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 1.3em; font-weight: bold; color: {risk_color}; margin-bottom: 5px;">
                        Livello di Rischio: {risk_level}
                    </div>
                    <div style="color: var(--text-secondary);">
                        Valutazione basata su porte aperte, vulnerabilità rilevate e potenziali vettori di attacco
                    </div>
                </div>
            </div>
'''
            
            # Executive Summary
            summary = ai_analysis.get("executive_summary", "")
            if summary:
                html += f'''
            <!-- Executive Summary -->
            <div style="margin-bottom: 25px;">
                <h3 style="color: var(--accent); margin-bottom: 15px;">📋 Sommario Esecutivo</h3>
                <p style="color: var(--text-primary); line-height: 1.8; padding: 15px; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid var(--accent);">
                    {summary}
                </p>
            </div>
'''
            
            # Most Likely Scenario
            scenario = ai_analysis.get("most_likely_scenario", "")
            if scenario:
                html += f'''
            <!-- Attack Scenario -->
            <div style="margin-bottom: 25px;">
                <h3 style="color: var(--warning); margin-bottom: 15px;">🎯 Scenario di Attacco più Probabile</h3>
                <p style="color: var(--text-primary); line-height: 1.8; padding: 15px; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid var(--warning);">
                    {scenario}
                </p>
            </div>
'''
            
            # Time to Compromise
            ttc = ai_analysis.get("time_to_compromise", "")
            if ttc:
                html += f'''
            <div style="margin-bottom: 25px; padding: 15px; background: rgba(255, 59, 59, 0.15); border-radius: 8px; border-left: 4px solid var(--danger);">
                <span style="color: var(--danger); font-weight: bold;">⏱️ Tempo stimato per compromissione:</span>
                <span style="color: var(--text-primary); margin-left: 10px;">{ttc}</span>
            </div>
'''
            
            # Attack Chain
            attack_chain = ai_analysis.get("attack_chain", [])
            if attack_chain:
                html += '''
            <!-- Attack Chain -->
            <div style="margin-bottom: 25px;">
                <h3 style="color: var(--warning); margin-bottom: 15px;">⛓️ Attack Chain (Sequenza di Attacco)</h3>
                <div style="background: var(--bg-secondary); border-radius: 8px; padding: 20px;">
'''
                for step in attack_chain:
                    step_num = step.get('step', '?')
                    action = step.get('action', 'N/A')
                    tool = step.get('tool', 'N/A')
                    html += f'''
                    <div style="display: flex; margin-bottom: 15px; align-items: flex-start;">
                        <div style="min-width: 40px; height: 40px; background: var(--warning); color: #000; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px;">
                            {step_num}
                        </div>
                        <div style="flex: 1;">
                            <div style="color: var(--text-primary); font-weight: 500;">{action}</div>
                            <div style="color: var(--accent); font-size: 0.9em; margin-top: 5px;">🔧 Tool: {tool}</div>
                        </div>
                    </div>
'''
                html += '''
                </div>
            </div>
'''
            
            # Priority Actions
            priority_actions = ai_analysis.get("priority_actions", [])
            if priority_actions:
                html += '''
            <!-- Priority Actions -->
            <div style="margin-bottom: 25px;">
                <h3 style="color: var(--danger); margin-bottom: 15px;">🚨 Azioni Prioritarie di Remediation</h3>
                <div style="background: var(--bg-secondary); border-radius: 8px; padding: 20px;">
'''
                for i, action in enumerate(priority_actions, 1):
                    html += f'''
                    <div style="display: flex; align-items: flex-start; margin-bottom: 12px; padding: 10px; background: rgba(255, 59, 59, 0.1); border-radius: 6px;">
                        <div style="min-width: 30px; height: 30px; background: var(--danger); color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 12px; font-size: 0.9em;">
                            {i}
                        </div>
                        <div style="color: var(--text-primary); flex: 1; line-height: 1.6;">{action}</div>
                    </div>
'''
                html += '''
                </div>
            </div>
'''
            
            # Detailed Recommendations
            recommendations = ai_analysis.get("detailed_recommendations", [])
            if recommendations:
                html += '''
            <!-- Detailed Recommendations -->
            <div style="margin-bottom: 25px;">
                <h3 style="color: var(--accent); margin-bottom: 15px;">📝 Raccomandazioni Dettagliate</h3>
'''
                priority_colors = {"ALTA": "#FF3B3B", "MEDIA": "#FFB800", "BASSA": "#00D26A"}
                for rec in recommendations:
                    issue = rec.get('issue', 'N/A')
                    solution = rec.get('solution', 'N/A')
                    priority = rec.get('priority', 'MEDIA')
                    color = priority_colors.get(priority, "#FFB800")
                    html += f'''
                <div style="margin-bottom: 15px; padding: 15px; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid {color};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="color: var(--text-primary); font-weight: bold;">⚠️ {issue}</span>
                        <span style="background: {color}; color: #000; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold;">{priority}</span>
                    </div>
                    <p style="color: var(--text-secondary); line-height: 1.6;">✅ {solution}</p>
                </div>
'''
                html += '''
            </div>
'''
            
            # Business Impact
            business_impact = ai_analysis.get("business_impact", "")
            if business_impact:
                html += f'''
            <!-- Business Impact -->
            <div style="margin-bottom: 15px;">
                <h3 style="color: var(--danger); margin-bottom: 15px;">💼 Impatto sul Business</h3>
                <p style="color: var(--text-primary); line-height: 1.8; padding: 15px; background: rgba(255, 59, 59, 0.1); border-radius: 8px; border-left: 4px solid var(--danger);">
                    {business_impact}
                </p>
            </div>
'''
            
            # Threat Actors
            threat_actors = ai_analysis.get("threat_actors", "")
            if threat_actors:
                html += f'''
            <!-- Threat Actors -->
            <div>
                <h3 style="color: var(--warning); margin-bottom: 15px;">👤 Attori Malevoli Interessati</h3>
                <p style="color: var(--text-primary); padding: 15px; background: var(--bg-secondary); border-radius: 8px;">
                    {threat_actors}
                </p>
            </div>
'''
            
            html += '''
        </div>
'''
        
        # Footer
        html += f'''
        <!-- Footer -->
        <div class="footer">
            <div class="footer-logo">🐧 Stealth Vulnerability Scanner</div>
            <p>Red-Penguin</p>
            <p style="margin-top: 10px;">Versione {Config.VERSION} | Report generato il {timestamp}</p>
        </div>
    </div>
    
    <script>
        // Smooth scroll for any anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({{
                    behavior: 'smooth'
                }});
            }});
        }});
    </script>
</body>
</html>
'''
        return html


class TextReport:
    """Generatore report in formato testo"""
    
    def __init__(self):
        self.lines = []
        self._add_header()
    
    def _add_header(self):
        self.lines.append("=" * 70)
        self.lines.append("           STEALTH VULNERABILITY SCANNER - REPORT")
        self.lines.append("              Red-Penguin")
        self.lines.append("=" * 70)
        self.lines.append("")
    
    def add_section(self, title: str):
        self.lines.append("")
        self.lines.append("-" * 70)
        self.lines.append(f"  {title.upper()}")
        self.lines.append("-" * 70)
    
    def add_info(self, label: str, value: str):
        self.lines.append(f"  {label}: {value}")
    
    def add_empty_line(self):
        self.lines.append("")
    
    def add_vulnerability(self, severity: str, title: str, description: str, 
                         remediation: str, cve: str = "", cve_desc: str = ""):
        self.lines.append("")
        self.lines.append(f"  [{severity}] {title}")
        if cve:
            self.lines.append(f"    CVE/CWE: {cve}")
        if cve_desc:
            self.lines.append(f"    Info: {cve_desc}")
        self.lines.append(f"    Problema: {description}")
        self.lines.append(f"    Rimedio: {remediation}")
    
    def add_port(self, port: int, service: str):
        self.lines.append(f"    [+] Porta {port} - {service} (APERTA)")
    
    def add_risk_level(self, risk: str):
        self.lines.append("")
        self.lines.append("=" * 70)
        self.lines.append(f"          LIVELLO DI RISCHIO COMPLESSIVO: {risk}")
        self.lines.append("=" * 70)
    
    def add_footer(self):
        self.lines.append("")
        self.lines.append("-" * 70)
        self.lines.append(f"  Report generato: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        self.lines.append(f"  Stealth Vulnerability Scanner v{Config.VERSION}")
        self.lines.append("-" * 70)
    
    def save(self, filepath: str):
        self.add_footer()
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.lines))


class StealthScannerGUI(ctk.CTk):
    """Interfaccia grafica principale dello scanner"""
    
    def __init__(self):
        super().__init__()
        
        self.title(f"Stealth Vulnerability Scanner v{Config.VERSION}")
        self.geometry("1300x900")
        self.minsize(1100, 750)
        
        self.network_checker = NetworkChecker()
        self.scan_running = False
        self.vulnerabilities = []
        self.open_ports = []
        self.scan_target = ""
        self.scan_ip = ""
        self.geo_hosting_info = None
        self.ssl_info = None
        self.web_tech_info = None
        self.possible_attacks = []
        
        self.colors = {
            "success": "#00D26A", 
            "warning": "#FFB800", 
            "danger": "#FF3B3B",
            "info": "#0EA5E9", 
            "muted": "#6B7280", 
            "card_bg": "#1E1E2E"
        }
        
        self.output_path = self._create_output_folder()
        
        self._create_ui()
        self.after(100, self._refresh_network_status)
    
    def _create_output_folder(self) -> Path:
        # Cartella Analisi nella stessa directory dello script
        script_dir = Path(__file__).parent.resolve()
        folder = script_dir / Config.OUTPUT_FOLDER
        try:
            folder.mkdir(parents=True, exist_ok=True)
            print(f"[INFO] Cartella output: {folder}")
        except Exception as e:
            print(f"[ERRORE] {e}")
            folder = Path.cwd() / Config.OUTPUT_FOLDER
            folder.mkdir(parents=True, exist_ok=True)
        return folder
    
    def _create_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._create_header()
        
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=2)
        content.grid_rowconfigure(0, weight=1)
        
        self._create_left_panel(content)
        self._create_right_panel(content)
    
    def _create_header(self):
        header = ctk.CTkFrame(self, height=80, fg_color=self.colors["card_bg"])
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        header.grid_propagate(False)
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=20, pady=15)
        
        ctk.CTkLabel(
            title_frame, 
            text="🐧 STEALTH VULNERABILITY SCANNER",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_frame, 
            text=f"Red-Penguin | v{Config.VERSION}",
            font=ctk.CTkFont(size=12), 
            text_color=self.colors["muted"]
        ).pack(anchor="w")
        
        ctk.CTkButton(
            header, 
            text="🔄 Aggiorna Rete", 
            width=140,
            command=self._refresh_network_status
        ).pack(side="right", padx=20, pady=20)
    
    def _create_left_panel(self, parent):
        left_panel = ctk.CTkFrame(parent, fg_color="transparent")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Card configurazione rete
        card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            card, 
            text="📡 Configurazione Rete", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=(15, 10))
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=(0, 15))
        
        self.iface_label = ctk.CTkLabel(content, text="Interfacce: --", font=ctk.CTkFont(size=13), anchor="w")
        self.iface_label.pack(fill="x", pady=2)
        self.gateway_label = ctk.CTkLabel(content, text="Gateway: --", font=ctk.CTkFont(size=13), anchor="w")
        self.gateway_label.pack(fill="x", pady=2)
        self.dns_label = ctk.CTkLabel(content, text="DNS: --", font=ctk.CTkFont(size=13), anchor="w")
        self.dns_label.pack(fill="x", pady=2)
        self.ip_label = ctk.CTkLabel(content, text="IP Pubblico: --", font=ctk.CTkFont(size=13), anchor="w")
        self.ip_label.pack(fill="x", pady=2)
        
        # Card TOR
        tor_card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        tor_card.pack(fill="x", pady=(0, 10))
        header = ctk.CTkFrame(tor_card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 10))
        ctk.CTkLabel(header, text="🧅 Stato Rete TOR", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w")
        self.tor_status_badge = ctk.CTkLabel(
            header, 
            text="NON ATTIVA", 
            font=ctk.CTkFont(size=14, weight="bold"), 
            text_color=self.colors["danger"]
        )
        self.tor_status_badge.pack(anchor="w", pady=(5, 0))
        content2 = ctk.CTkFrame(tor_card, fg_color="transparent")
        content2.pack(fill="x", padx=15, pady=(0, 15))
        self.tor_process_label = ctk.CTkLabel(content2, text="Processo TOR: Non attivo", font=ctk.CTkFont(size=13), anchor="w")
        self.tor_process_label.pack(fill="x", pady=2)
        self.tor_socks_label = ctk.CTkLabel(content2, text="Porta SOCKS: Chiusa", font=ctk.CTkFont(size=13), anchor="w")
        self.tor_socks_label.pack(fill="x", pady=2)
        self.tor_control_label = ctk.CTkLabel(content2, text="Controllo TOR: Non disponibile", font=ctk.CTkFont(size=13), anchor="w")
        self.tor_control_label.pack(fill="x", pady=2)
        self.tor_exit_label = ctk.CTkLabel(content2, text="", font=ctk.CTkFont(size=13), anchor="w")
        self.tor_exit_label.pack(fill="x", pady=2)
        
        # Card cartella report
        path_card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        path_card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            path_card, 
            text="📁 Cartella Report", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))
        ctk.CTkLabel(
            path_card, 
            text=str(self.output_path), 
            font=ctk.CTkFont(size=10), 
            text_color=self.colors["info"], 
            wraplength=280
        ).pack(anchor="w", padx=15, pady=(0, 10))
        
        # Card Geolocalizzazione (preview)
        self.geo_card = ctk.CTkFrame(left_panel, fg_color=self.colors["card_bg"])
        self.geo_card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            self.geo_card, 
            text="🌍 Geolocalizzazione Target", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))
        self.geo_content = ctk.CTkFrame(self.geo_card, fg_color="transparent")
        self.geo_content.pack(fill="x", padx=15, pady=(0, 10))
        self.geo_labels = {}
        for field in ["Paese", "Città", "ISP", "Hosting"]:
            lbl = ctk.CTkLabel(
                self.geo_content, 
                text=f"{field}: --", 
                font=ctk.CTkFont(size=11), 
                anchor="w"
            )
            lbl.pack(fill="x", pady=1)
            self.geo_labels[field] = lbl
    
    def _create_right_panel(self, parent):
        right_panel = ctk.CTkFrame(parent, fg_color="transparent")
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)
        
        # Card scanner
        scanner_card = ctk.CTkFrame(right_panel, fg_color=self.colors["card_bg"])
        scanner_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ctk.CTkLabel(
            scanner_card, 
            text="🔍 Scanner Vulnerabilità", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=(15, 10))
        
        input_frame = ctk.CTkFrame(scanner_card, fg_color="transparent")
        input_frame.pack(fill="x", padx=15, pady=(0, 15))
        ctk.CTkLabel(
            input_frame, 
            text="Target (IP o Dominio):", 
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w")
        
        target_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        target_frame.pack(fill="x", pady=(5, 10))
        self.target_entry = ctk.CTkEntry(
            target_frame, 
            placeholder_text="es. example.com o 192.168.1.1", 
            height=40, 
            font=ctk.CTkFont(size=14)
        )
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.scan_button = ctk.CTkButton(
            target_frame, 
            text="▶ Avvia Scansione", 
            height=40, 
            font=ctk.CTkFont(size=14, weight="bold"), 
            command=self._start_scan
        )
        self.scan_button.pack(side="right")
        
        # Opzioni
        options_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        options_frame.pack(fill="x")
        self.verify_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options_frame, 
            text="Verifica vulnerabilità", 
            variable=self.verify_var
        ).pack(side="left", padx=(0, 15))
        self.web_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options_frame, 
            text="Analisi Web", 
            variable=self.web_var
        ).pack(side="left", padx=(0, 15))
        self.geo_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options_frame, 
            text="Geolocalizzazione", 
            variable=self.geo_var
        ).pack(side="left", padx=(0, 15))
        
        # Checkbox per analisi AI Gemini
        self.ai_var = ctk.BooleanVar(value=False)
        self.ai_checkbox = ctk.CTkCheckBox(
            options_frame, 
            text="🤖 Analisi AI", 
            variable=self.ai_var,
            text_color="#A78BFA"
        )
        self.ai_checkbox.pack(side="left")
        
        # Verifica disponibilità AI
        self.ai_available = False
        self.ai_status_msg = ""
        
        if not HAS_REQUESTS:
            self.ai_checkbox.configure(state="disabled")
            self.ai_checkbox.configure(text="🤖 AI (no requests)")
            self.ai_status_msg = "Modulo 'requests' non installato"
        else:
            config_mgr = ConfigManager()
            if not config_mgr.gemini_api_key:
                self.ai_checkbox.configure(state="disabled")
                self.ai_checkbox.configure(text="🤖 AI (config.ini)")
                self.ai_status_msg = "API key non configurata in config.ini"
            else:
                self.ai_available = True
                self.ai_status_msg = f"Gemini pronto ({config_mgr.gemini_model})"
        
        self.progress = ctk.CTkProgressBar(scanner_card, mode="indeterminate")
        self.progress.pack(fill="x", padx=15, pady=(0, 15))
        self.progress.set(0)
        
        # Card risultati
        results_card = ctk.CTkFrame(right_panel, fg_color=self.colors["card_bg"])
        results_card.grid(row=1, column=0, sticky="nsew")
        results_card.grid_rowconfigure(1, weight=1)
        results_card.grid_columnconfigure(0, weight=1)
        
        results_header = ctk.CTkFrame(results_card, fg_color="transparent")
        results_header.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 10))
        ctk.CTkLabel(
            results_header, 
            text="📊 Risultati Scansione", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left")
        
        # Pulsanti export
        btn_frame = ctk.CTkFrame(results_header, fg_color="transparent")
        btn_frame.pack(side="right")
        
        self.export_json_btn = ctk.CTkButton(
            btn_frame, 
            text="📄 JSON", 
            width=80, 
            state="disabled", 
            command=self._export_json
        )
        self.export_json_btn.pack(side="left", padx=5)
        
        self.export_html_btn = ctk.CTkButton(
            btn_frame, 
            text="🌐 HTML", 
            width=80, 
            state="disabled", 
            command=self._export_html
        )
        self.export_html_btn.pack(side="left", padx=5)
        
        self.export_txt_btn = ctk.CTkButton(
            btn_frame, 
            text="📝 TXT", 
            width=80, 
            state="disabled", 
            command=self._export_txt
        )
        self.export_txt_btn.pack(side="left", padx=5)
        
        self.export_all_btn = ctk.CTkButton(
            btn_frame, 
            text="💾 Esporta Tutto", 
            width=120, 
            state="disabled", 
            fg_color="#00D26A",
            hover_color="#00B85C",
            command=self._export_all
        )
        self.export_all_btn.pack(side="left", padx=5)
        
        # Tabs
        self.tabview = ctk.CTkTabview(results_card)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        self.tab_log = self.tabview.add("📋 Log")
        self.log_text = ctk.CTkTextbox(self.tab_log, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_text.pack(fill="both", expand=True)
        
        self.tab_vuln = self.tabview.add("⚠️ Vulnerabilità")
        self.vuln_frame = ctk.CTkScrollableFrame(self.tab_vuln)
        self.vuln_frame.pack(fill="both", expand=True)
        
        self.tab_ports = self.tabview.add("🔌 Porte")
        self.ports_frame = ctk.CTkScrollableFrame(self.tab_ports)
        self.ports_frame.pack(fill="both", expand=True)
        
        self.tab_attacks = self.tabview.add("🎯 Attacchi")
        self.attacks_frame = ctk.CTkScrollableFrame(self.tab_attacks)
        self.attacks_frame.pack(fill="both", expand=True)
        
        self.tab_info = self.tabview.add("ℹ️ Info Target")
        self.info_frame = ctk.CTkScrollableFrame(self.tab_info)
        self.info_frame.pack(fill="both", expand=True)
    
    def _refresh_network_status(self):
        def check():
            self.network_checker.check_all()
            self.after(0, self._update_network_ui)
        threading.Thread(target=check, daemon=True).start()
    
    def _update_network_ui(self):
        nc = self.network_checker
        
        if nc.interfaces:
            ifaces = [f"{i['name']}: {', '.join(i['addresses'])}" for i in nc.interfaces]
            self.iface_label.configure(text=f"Interfacce: {'; '.join(ifaces)}")
        else:
            self.iface_label.configure(text="Interfacce: Non rilevate")
        
        self.gateway_label.configure(text=f"Gateway: {nc.gateway or 'Non rilevato'}")
        self.dns_label.configure(text=f"DNS: {', '.join(nc.dns_servers) if nc.dns_servers else 'Non rilevati'}")
        self.ip_label.configure(text=f"IP Pubblico: {nc.public_ip or 'Non verificabile'}")
        
        ts = nc.tor_status
        self.tor_status_badge.configure(
            text="ATTIVA" if ts["active"] else "NON ATTIVA",
            text_color=self.colors["success"] if ts["active"] else self.colors["danger"]
        )
        
        if ts["process_running"]:
            self.tor_process_label.configure(
                text=f"Processo TOR: Attivo (PID: {ts.get('tor_pid', '')})", 
                text_color=self.colors["success"]
            )
        else:
            self.tor_process_label.configure(text="Processo TOR: Non attivo", text_color=self.colors["danger"])
        
        if ts["socks_port_open"]:
            port = "9150" if ts.get("tor_browser") else "9050"
            self.tor_socks_label.configure(text=f"Porta SOCKS: Aperta (:{port})", text_color=self.colors["success"])
        else:
            self.tor_socks_label.configure(text="Porta SOCKS: Chiusa", text_color=self.colors["danger"])
        
        if ts["control_port_open"]:
            self.tor_control_label.configure(
                text=f"Controllo TOR: {ts.get('control_type', 'N/A')}", 
                text_color=self.colors["success"]
            )
        else:
            self.tor_control_label.configure(text="Controllo TOR: Non disponibile", text_color=self.colors["muted"])
        
        if ts.get("exit_node"):
            self.tor_exit_label.configure(text=f"Exit Node: {ts['exit_node']}", text_color=self.colors["info"])
        elif ts["active"]:
            self.tor_exit_label.configure(text="Installa 'pysocks' per exit node", text_color=self.colors["warning"])
        else:
            self.tor_exit_label.configure(text="")
    
    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        icons = {"info": "[i]", "success": "[+]", "warning": "[!]", "error": "[X]", "scan": "[>]"}
        self.log_text.insert(END, f"[{timestamp}] {icons.get(level, '[-]')} {message}\n")
        self.log_text.see(END)
    
    def _start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Attenzione", "Inserisci un target da scansionare")
            return
        
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target = urlparse(target).netloc
        
        self.scan_target = target
        self.log_text.delete("1.0", END)
        for w in self.vuln_frame.winfo_children(): 
            w.destroy()
        for w in self.ports_frame.winfo_children(): 
            w.destroy()
        for w in self.info_frame.winfo_children():
            w.destroy()
        
        self.vulnerabilities = []
        self.open_ports = []
        self.geo_hosting_info = None
        self.ssl_info = None
        self.web_tech_info = None
        
        self.scan_button.configure(state="disabled", text="⏳ Scansione...")
        self.target_entry.configure(state="disabled")
        self.export_json_btn.configure(state="disabled")
        self.export_html_btn.configure(state="disabled")
        self.export_txt_btn.configure(state="disabled")
        self.export_all_btn.configure(state="disabled")
        self.progress.start()
        self.scan_running = True
        
        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()
    
    def _run_scan(self, target: str):
        try:
            self.after(0, lambda: self._log(f"Inizio scansione: {target}", "info"))
            
            # Risoluzione DNS
            try:
                ip = socket.gethostbyname(target)
                self.scan_ip = ip
                self.after(0, lambda: self._log(f"IP risolto: {ip}", "success"))
            except socket.gaierror:
                self.after(0, lambda: self._log(f"Impossibile risolvere {target}", "error"))
                self._scan_complete()
                return
            
            # Geolocalizzazione e Hosting
            if self.geo_var.get():
                self.after(0, lambda: self._log("Recupero informazioni geolocalizzazione e hosting...", "scan"))
                self.geo_hosting_info = GeoHostingInfo.fetch(ip)
                self.after(0, self._update_geo_ui)
                self.after(0, lambda: self._log(f"Posizione: {self.geo_hosting_info.city}, {self.geo_hosting_info.country}", "success"))
                if self.geo_hosting_info.is_hosting:
                    self.after(0, lambda: self._log(f"Hosting: {self.geo_hosting_info.hosting_provider}", "info"))
            
            # Scansione porte
            self.after(0, lambda: self._log("Scansione porte in corso...", "scan"))
            
            for port, service in Config.COMMON_PORTS.items():
                if not self.scan_running:
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(Config.TIMEOUT_FAST)
                    if sock.connect_ex((ip, port)) == 0:
                        self.open_ports.append({"port": port, "service": service})
                        self.after(0, lambda p=port, s=service: self._log(f"Porta {p}/{s} APERTA", "success"))
                        self.after(0, lambda p=port, s=service: self._add_port_card(p, s))
                    sock.close()
                except Exception:
                    pass
            
            if not self.open_ports:
                self.after(0, lambda: self._log("Nessuna porta aperta trovata", "warning"))
            else:
                self.after(0, lambda: self._log(f"Trovate {len(self.open_ports)} porte aperte", "info"))
            
            # Verifica vulnerabilità
            if self.verify_var.get() and self.open_ports:
                self.after(0, lambda: self._log("Verifica vulnerabilità...", "scan"))
                self._verify_vulnerabilities(ip)
            
            # Analisi web
            if self.web_var.get() and HAS_REQUESTS:
                web_ports = [p["port"] for p in self.open_ports if p["port"] in [80, 443, 8080, 8443]]
                
                # SSL/TLS
                if any(p in [443, 8443] for p in web_ports):
                    self.after(0, lambda: self._log("Analisi SSL/TLS...", "scan"))
                    port = 443 if 443 in web_ports else 8443
                    self.ssl_info = SSLInfo.fetch(target, port)
                    if self.ssl_info.version:
                        self.after(0, lambda: self._log(f"SSL: {self.ssl_info.version} - {self.ssl_info.cipher}", "info"))
                        # Verifica protocolli deboli
                        if self.ssl_info.version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"]:
                            self._add_vulnerability("ALTA", f"Protocollo {self.ssl_info.version} Deprecato", 
                                                   "Protocollo SSL/TLS obsoleto e insicuro", 
                                                   "Aggiornare a TLSv1.2 o superiore", "ssl_weak")
                        elif self.ssl_info.version == "TLSv1.1":
                            self._add_vulnerability("MEDIA", "TLSv1.1 Deprecato", 
                                                   "TLSv1.1 è deprecato", 
                                                   "Aggiornare a TLSv1.2+", "ssl_weak")
                
                # Tecnologie web
                if web_ports:
                    self.after(0, lambda: self._log("Analisi tecnologie web...", "scan"))
                    https = any(p in [443, 8443] for p in web_ports)
                    port = 443 if 443 in web_ports else (8443 if 8443 in web_ports else (80 if 80 in web_ports else 8080))
                    self.web_tech_info = WebTechInfo.fetch(target, port, https)
                    
                    if self.web_tech_info.server:
                        self.after(0, lambda: self._log(f"Server: {self.web_tech_info.server}", "info"))
                    if self.web_tech_info.cms:
                        self.after(0, lambda: self._log(f"CMS: {self.web_tech_info.cms}", "info"))
                    
                    # Verifica security headers
                    self._check_web(target, web_ports)
                
                # File sensibili
                self.after(0, lambda: self._log("Verifica file sensibili...", "scan"))
                self._check_sensitive_files(target)
            
            # Aggiorna info panel
            self.after(0, self._update_info_panel)
            
            self.after(0, lambda: self._log("Scansione completata!", "success"))
            
        except Exception as e:
            self.after(0, lambda: self._log(f"Errore: {str(e)}", "error"))
        finally:
            self._scan_complete()
    
    def _update_geo_ui(self):
        """Aggiorna l'UI con le informazioni di geolocalizzazione"""
        if self.geo_hosting_info:
            geo = self.geo_hosting_info
            self.geo_labels["Paese"].configure(text=f"Paese: {geo.country} ({geo.country_code})")
            self.geo_labels["Città"].configure(text=f"Città: {geo.city}, {geo.region_name}")
            self.geo_labels["ISP"].configure(text=f"ISP: {geo.isp[:30]}..." if len(geo.isp) > 30 else f"ISP: {geo.isp}")
            if geo.is_hosting:
                self.geo_labels["Hosting"].configure(
                    text=f"Hosting: {geo.hosting_provider}", 
                    text_color=self.colors["info"]
                )
            else:
                self.geo_labels["Hosting"].configure(text="Hosting: No", text_color=self.colors["muted"])
    
    def _update_info_panel(self):
        """Aggiorna il pannello informazioni"""
        # Clear
        for w in self.info_frame.winfo_children():
            w.destroy()
        
        # Target info
        self._add_info_section("🎯 Target", [
            ("Dominio/Host", self.scan_target),
            ("Indirizzo IP", self.scan_ip),
            ("Data Scansione", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        ])
        
        # Geolocalizzazione
        if self.geo_hosting_info:
            geo = self.geo_hosting_info
            self._add_info_section("🌍 Geolocalizzazione", [
                ("Paese", f"{geo.country} ({geo.country_code})"),
                ("Regione", geo.region_name),
                ("Città", geo.city),
                ("CAP", geo.zip_code),
                ("Coordinate", f"{geo.latitude}, {geo.longitude}"),
                ("Timezone", geo.timezone)
            ])
            
            self._add_info_section("🌐 Rete", [
                ("ISP", geo.isp),
                ("Organizzazione", geo.organization),
                ("ASN", geo.asn),
                ("ASN Name", geo.asn_name),
                ("Reverse DNS", geo.reverse_dns)
            ])
            
            self._add_info_section("🏢 Hosting", [
                ("È Hosting", "✅ Sì" if geo.is_hosting else "❌ No"),
                ("È Proxy", "✅ Sì" if geo.is_proxy else "❌ No"),
                ("Provider", geo.hosting_provider or "N/A"),
                ("Datacenter", geo.datacenter or "N/A")
            ])
        
        # SSL Info
        if self.ssl_info and self.ssl_info.version:
            self._add_info_section("🔐 SSL/TLS", [
                ("Protocollo", self.ssl_info.version),
                ("Cipher", self.ssl_info.cipher),
                ("Bits", str(self.ssl_info.cipher_bits)),
                ("Valido dal", self.ssl_info.valid_from),
                ("Valido fino", self.ssl_info.valid_to)
            ])
        
        # Web Tech
        if self.web_tech_info:
            tech = self.web_tech_info
            self._add_info_section("💻 Tecnologie Web", [
                ("Server", tech.server or "N/A"),
                ("Powered By", tech.powered_by or "N/A"),
                ("CMS", tech.cms or "N/A"),
                ("Framework", tech.framework or "N/A")
            ])
    
    def _add_info_section(self, title: str, items: list):
        """Aggiunge una sezione al pannello info"""
        section = ctk.CTkFrame(self.info_frame, fg_color="#2D2D3D")
        section.pack(fill="x", pady=5, padx=5)
        
        ctk.CTkLabel(
            section, 
            text=title, 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors["info"]
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        for label, value in items:
            row = ctk.CTkFrame(section, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=f"{label}:", font=ctk.CTkFont(size=12), text_color=self.colors["muted"]).pack(side="left")
            ctk.CTkLabel(row, text=str(value), font=ctk.CTkFont(size=12)).pack(side="right")
        
        # Padding bottom
        ctk.CTkFrame(section, fg_color="transparent", height=10).pack()
    
    def _get_cve_info(self, key: str) -> dict:
        return Config.CVE_DATABASE.get(key, {"cve": "", "desc": ""})
    
    def _verify_vulnerabilities(self, ip: str):
        """Verifica le vulnerabilità sulle porte aperte"""
        for port_info in self.open_ports:
            port, service = port_info["port"], port_info["service"]
            
            if port == 21:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(Config.TIMEOUT)
                    sock.connect((ip, port))
                    sock.recv(1024)
                    sock.send(b"USER anonymous\r\n")
                    if "331" in sock.recv(1024).decode('utf-8', errors='ignore'):
                        sock.send(b"PASS anonymous@\r\n")
                        if "230" in sock.recv(1024).decode('utf-8', errors='ignore'):
                            self._add_vulnerability("CRITICA", "FTP Anonymous", 
                                                   "Login anonimo consentito", 
                                                   "Disabilitare accesso anonimo", "ftp_anonymous")
                    sock.close()
                except Exception:
                    pass
            
            elif port == 22:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(Config.TIMEOUT)
                    sock.connect((ip, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    if "SSH-1" in banner:
                        self._add_vulnerability("CRITICA", "SSH Protocol v1", 
                                               "Protocollo deprecato e insicuro", 
                                               "Aggiornare a SSH v2", "ssh_weak")
                except Exception:
                    pass
            
            elif port == 23:
                self._add_vulnerability("ALTA", "Telnet Attivo", 
                                       "Credenziali trasmesse in chiaro", 
                                       "Sostituire con SSH", "telnet")
            
            elif port == 445:
                self._add_vulnerability("ALTA", "SMB Esposto", 
                                       "Vulnerabile a EternalBlue/SMBGhost", 
                                       "Firewall, disabilitare SMBv1", "smb_exposed")
            
            elif port == 3389:
                self._add_vulnerability("ALTA", "RDP Esposto", 
                                       "Vulnerabile a BlueKeep", 
                                       "Usare VPN, abilitare NLA", "rdp_exposed")
            
            elif port == 3306:
                self._add_vulnerability("ALTA", "MySQL Esposto", 
                                       "Database accessibile dalla rete", 
                                       "Limitare con firewall", "mysql_exposed")
            
            elif port == 5432:
                self._add_vulnerability("ALTA", "PostgreSQL Esposto", 
                                       "Database accessibile dalla rete", 
                                       "Configurare pg_hba.conf", "postgres_exposed")
            
            elif port == 27017:
                self._add_vulnerability("CRITICA", "MongoDB Esposto", 
                                       "Database senza autenticazione", 
                                       "Abilitare autenticazione", "mongodb_exposed")
            
            elif port == 1433:
                self._add_vulnerability("ALTA", "MSSQL Esposto", 
                                       "SQL Server accessibile", 
                                       "Limitare con firewall", "mssql_exposed")
            
            elif port == 5900:
                self._add_vulnerability("ALTA", "VNC Esposto", 
                                       "Desktop remoto accessibile", 
                                       "Usare VPN, password forte", "vnc_exposed")
            
            elif port == 6379:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(Config.TIMEOUT)
                    sock.connect((ip, port))
                    sock.send(b"INFO\r\n")
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    if "redis_version" in response:
                        self._add_vulnerability("CRITICA", "Redis Senza Auth", 
                                               "Possibile esecuzione comandi", 
                                               "Configurare requirepass", "redis_noauth")
                    sock.close()
                except Exception:
                    pass
    
    def _check_web(self, target: str, ports: List[int]):
        """Controlla header di sicurezza web"""
        for port in ports:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{target}" + (f":{port}" if port not in [80, 443] else "")
            try:
                headers = requests.get(url, timeout=Config.TIMEOUT, verify=False).headers
                if "Strict-Transport-Security" not in headers:
                    self._add_vulnerability("MEDIA", "HSTS Mancante", 
                                           "Header Strict-Transport-Security assente", 
                                           "Aggiungere header HSTS", "hsts_missing")
                if "X-Frame-Options" not in headers:
                    self._add_vulnerability("MEDIA", "X-Frame-Options Mancante", 
                                           "Vulnerabile a Clickjacking", 
                                           "Aggiungere X-Frame-Options", "xframe_missing")
                if "Content-Security-Policy" not in headers:
                    self._add_vulnerability("MEDIA", "CSP Mancante", 
                                           "Rischio Cross-Site Scripting", 
                                           "Implementare CSP", "csp_missing")
                break  # Solo una volta
            except Exception:
                pass
    
    def _check_sensitive_files(self, target: str):
        """Verifica file sensibili esposti"""
        sensitive = [
            ("/.git/config", "Git Repository Esposto", "CRITICA", "git_exposed"),
            ("/.env", "File .env Esposto", "CRITICA", "env_exposed"),
            ("/phpinfo.php", "PHPInfo Esposto", "ALTA", "phpinfo_exposed"),
            ("/.htaccess", ".htaccess Accessibile", "MEDIA", ""),
            ("/wp-config.php.bak", "Backup WordPress", "CRITICA", ""),
            ("/server-status", "Apache Status", "MEDIA", ""),
            ("/.svn/entries", "SVN Esposto", "ALTA", ""),
            ("/backup.sql", "Backup SQL Esposto", "CRITICA", ""),
        ]
        
        for path, title, severity, cve_key in sensitive:
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{target}{path}"
                    response = requests.get(url, timeout=Config.TIMEOUT_FAST, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        if "404" not in response.text[:200].lower() and "not found" not in response.text[:200].lower():
                            self._add_vulnerability(severity, title, 
                                                   f"File sensibile accessibile: {path}", 
                                                   "Rimuovere o proteggere il file", cve_key)
                            break
                except Exception:
                    pass
    
    def _add_vulnerability(self, severity: str, title: str, description: str, remediation: str, cve_key: str = ""):
        cve_info = self._get_cve_info(cve_key)
        vuln = {
            "severity": severity, 
            "title": title, 
            "description": description,
            "remediation": remediation, 
            "cve": cve_info.get("cve", ""), 
            "cve_desc": cve_info.get("desc", "")
        }
        self.vulnerabilities.append(vuln)
        self.after(0, lambda: self._add_vuln_card(vuln))
        self.after(0, lambda: self._log(f"[{severity}] {title} - {cve_info.get('cve', 'N/A')}", "warning"))
    
    def _add_vuln_card(self, vuln: dict):
        colors = {"CRITICA": "#FF3B3B", "ALTA": "#FF8C00", "MEDIA": "#FFB800", "BASSA": "#00D26A"}
        card = ctk.CTkFrame(self.vuln_frame, fg_color="#2D2D3D")
        card.pack(fill="x", pady=5, padx=5)
        
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(10, 5))
        ctk.CTkLabel(
            header, 
            text=vuln['severity'], 
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=colors.get(vuln["severity"], "#6B7280"), 
            fg_color="#1a1a2e", 
            corner_radius=4
        ).pack(side="left", padx=(0, 10), ipadx=8, ipady=2)
        ctk.CTkLabel(header, text=vuln["title"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        
        if vuln.get("cve"):
            ctk.CTkLabel(
                header, 
                text=vuln["cve"], 
                font=ctk.CTkFont(size=10), 
                text_color="#FF6B6B", 
                fg_color="#2a1a1a", 
                corner_radius=4
            ).pack(side="right", ipadx=6, ipady=2)
        
        ctk.CTkLabel(
            card, 
            text=vuln["description"], 
            font=ctk.CTkFont(size=12), 
            text_color="#9CA3AF", 
            anchor="w"
        ).pack(fill="x", padx=10, pady=(0, 3))
        
        if vuln.get("cve_desc"):
            ctk.CTkLabel(
                card, 
                text=f"Info: {vuln['cve_desc']}", 
                font=ctk.CTkFont(size=11), 
                text_color="#FF9999", 
                anchor="w"
            ).pack(fill="x", padx=10, pady=(0, 3))
        
        ctk.CTkLabel(
            card, 
            text=f"→ Rimedio: {vuln['remediation']}", 
            font=ctk.CTkFont(size=11), 
            text_color="#60A5FA", 
            anchor="w"
        ).pack(fill="x", padx=10, pady=(0, 10))
    
    def _add_port_card(self, port: int, service: str):
        card = ctk.CTkFrame(self.ports_frame, fg_color="#2D2D3D")
        card.pack(fill="x", pady=3, padx=5)
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(content, text="●", font=ctk.CTkFont(size=14), text_color=self.colors["success"]).pack(side="left")
        ctk.CTkLabel(content, text=f"Porta {port}", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=(5, 10))
        ctk.CTkLabel(content, text=service, font=ctk.CTkFont(size=13), text_color="#9CA3AF").pack(side="left")
    
    def _get_possible_attacks(self) -> dict:
        """Determina gli attacchi distruttivi (3) e probabili (5) basati sulle vulnerabilità"""
        destructive = []
        probable = []
        severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3}
        
        # Set per tracciare le chiavi di vulnerabilità rilevate
        detected_vuln_keys = set()
        
        # Mappa le vulnerabilità alle chiavi
        for vuln in self.vulnerabilities:
            title_lower = vuln["title"].lower()
            cve_key = None
            
            # Trova la chiave CVE corrispondente
            if "mongodb" in title_lower:
                cve_key = "mongodb_exposed"
            elif "redis" in title_lower:
                cve_key = "redis_noauth"
            elif "smb" in title_lower or "eternalblue" in title_lower:
                cve_key = "smb_exposed"
            elif "rdp" in title_lower or "bluekeep" in title_lower:
                cve_key = "rdp_exposed"
            elif "mysql" in title_lower:
                cve_key = "mysql_exposed"
            elif "postgres" in title_lower:
                cve_key = "postgres_exposed"
            elif "mssql" in title_lower or "sql server" in title_lower:
                cve_key = "mssql_exposed"
            elif "ftp" in title_lower and "anon" in title_lower:
                cve_key = "ftp_anonymous"
            elif "vnc" in title_lower:
                cve_key = "vnc_exposed"
            elif "telnet" in title_lower:
                cve_key = "telnet"
            elif ".git" in title_lower or "git repo" in title_lower:
                cve_key = "git_exposed"
            elif ".env" in title_lower:
                cve_key = "env_exposed"
            elif "hsts" in title_lower:
                cve_key = "hsts_missing"
            elif "x-frame" in title_lower or "clickjack" in title_lower:
                cve_key = "xframe_missing"
            elif "csp" in title_lower or "content-security" in title_lower:
                cve_key = "csp_missing"
            elif "ssl" in title_lower or "tls" in title_lower:
                cve_key = "ssl_weak"
            elif "phpinfo" in title_lower:
                cve_key = "phpinfo_exposed"
            elif "ssh" in title_lower:
                cve_key = "ssh_weak"
            
            if cve_key:
                detected_vuln_keys.add(cve_key)
                
                # Attacchi distruttivi
                if cve_key in Config.DESTRUCTIVE_ATTACKS:
                    attack_info = Config.DESTRUCTIVE_ATTACKS[cve_key].copy()
                    attack_info["vuln_key"] = cve_key
                    attack_info["vuln_severity"] = vuln["severity"]
                    destructive.append(attack_info)
                
                # Attacchi standard dal database legacy
                if cve_key in Config.ATTACK_DATABASE:
                    attack_info = Config.ATTACK_DATABASE[cve_key].copy()
                    attack_info["vuln_key"] = cve_key
                    attack_info["vuln_severity"] = vuln["severity"]
                    if attack_info.get("category") != "DISTRUTTIVO":
                        probable.append(attack_info)
        
        # Aggiungi attacchi probabili basati sulle vulnerabilità rilevate
        for attack_key, attack_info in Config.PROBABLE_ATTACKS.items():
            triggered_by = attack_info.get("triggered_by", [])
            if any(t in detected_vuln_keys for t in triggered_by):
                attack_copy = attack_info.copy()
                attack_copy["vuln_key"] = attack_key
                attack_copy["vuln_severity"] = "ALTA"  # Default
                probable.append(attack_copy)
        
        # Rimuovi duplicati e ordina
        def deduplicate_and_sort(attacks, limit):
            seen = set()
            unique = []
            for attack in attacks:
                key = attack.get("vuln_key") or attack.get("name")
                if key not in seen:
                    seen.add(key)
                    unique.append(attack)
            unique.sort(key=lambda x: (
                severity_order.get(x.get("vuln_severity", "MEDIA"), 4),
                severity_order.get(x.get("severity", "MEDIA"), 4)
            ))
            return unique[:limit]
        
        return {
            "destructive": deduplicate_and_sort(destructive, 3),
            "probable": deduplicate_and_sort(probable, 5)
        }
    
    def _update_attacks_ui(self):
        """Aggiorna la UI con gli attacchi distruttivi e probabili"""
        # Pulisce il frame
        for widget in self.attacks_frame.winfo_children():
            widget.destroy()
        
        self.possible_attacks = self._get_possible_attacks()
        destructive = self.possible_attacks.get("destructive", [])
        probable = self.possible_attacks.get("probable", [])
        
        total_attacks = len(destructive) + len(probable)
        
        if total_attacks == 0:
            ctk.CTkLabel(
                self.attacks_frame,
                text="✅ Nessun attacco identificato per le vulnerabilità rilevate",
                font=ctk.CTkFont(size=14),
                text_color=self.colors["success"]
            ).pack(pady=20)
            return
        
        severity_colors = {"CRITICA": "#FF3B3B", "ALTA": "#FF8C00", "MEDIA": "#FFB800", "BASSA": "#00D26A"}
        
        # ==================== SEZIONE ATTACCHI DISTRUTTIVI ====================
        if destructive:
            header_dest = ctk.CTkFrame(self.attacks_frame, fg_color="#2D1515")
            header_dest.pack(fill="x", pady=(0, 10), padx=5)
            ctk.CTkLabel(
                header_dest,
                text=f"💀 {len(destructive)} ATTACCHI DISTRUTTIVI (Compromissione Totale)",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#FF3B3B"
            ).pack(pady=15, padx=15)
            
            for i, attack in enumerate(destructive, 1):
                self._create_attack_card(attack, i, severity_colors, "#3D1515", "💀")
        
        # ==================== SEZIONE ATTACCHI PROBABILI ====================
        if probable:
            header_prob = ctk.CTkFrame(self.attacks_frame, fg_color="#1a2a1a")
            header_prob.pack(fill="x", pady=(15, 10), padx=5)
            ctk.CTkLabel(
                header_prob,
                text=f"🎯 {len(probable)} ATTACCHI PROBABILI (Backdoor & Persistenza)",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#FFB800"
            ).pack(pady=15, padx=15)
            
            for i, attack in enumerate(probable, 1):
                self._create_attack_card(attack, i, severity_colors, "#2D2D3D", "🎯")
        
        # Log attacchi
        for attack in destructive:
            self._log(f"[DISTRUTTIVO] {attack['name']} - {attack['type']}", "error")
        for attack in probable:
            self._log(f"[PROBABILE] {attack['name']} - {attack['type']}", "warning")
    
    def _create_attack_card(self, attack: dict, index: int, severity_colors: dict, bg_color: str, icon: str):
        """Crea una card per un attacco"""
        card = ctk.CTkFrame(self.attacks_frame, fg_color=bg_color)
        card.pack(fill="x", pady=5, padx=5)
        
        # Header card
        card_header = ctk.CTkFrame(card, fg_color="transparent")
        card_header.pack(fill="x", padx=15, pady=(15, 10))
        
        # Numero e icona
        ctk.CTkLabel(
            card_header,
            text=f"{icon} #{index}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=severity_colors.get(attack.get("severity", "MEDIA"), "#6B7280")
        ).pack(side="left", padx=(0, 10))
        
        # Nome attacco
        ctk.CTkLabel(
            card_header,
            text=attack["name"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")
        
        # Badge severity
        ctk.CTkLabel(
            card_header,
            text=attack.get("severity", "N/A"),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=severity_colors.get(attack.get("severity", "MEDIA"), "#6B7280"),
            fg_color="#1a1a2e",
            corner_radius=4
        ).pack(side="right", ipadx=8, ipady=2)
        
        # Categoria badge
        category = attack.get("category", "")
        if category:
            cat_color = "#FF3B3B" if category == "DISTRUTTIVO" else "#FFB800"
            ctk.CTkLabel(
                card_header,
                text=category,
                font=ctk.CTkFont(size=9),
                text_color=cat_color,
                fg_color="#1a1a2e",
                corner_radius=4
            ).pack(side="right", ipadx=6, ipady=2, padx=(0, 5))
        
        # Tipo attacco
        ctk.CTkLabel(
            card,
            text=f"Tipo: {attack.get('type', 'N/A')}",
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
            wraplength=600,
            justify="left"
        ).pack(fill="x", padx=15, pady=(0, 5))
        
        # Tools
        ctk.CTkLabel(
            card,
            text=f"🔧 Tools: {attack.get('tools', 'N/A')}",
            font=ctk.CTkFont(size=11),
            text_color="#FFB800",
            anchor="w"
        ).pack(fill="x", padx=15, pady=(0, 5))
        
        # Impact
        ctk.CTkLabel(
            card,
            text=f"💥 Impatto: {attack.get('impact', 'N/A')}",
            font=ctk.CTkFont(size=11),
            text_color="#FF6B6B",
            anchor="w"
        ).pack(fill="x", padx=15, pady=(0, 5))
        
        # Tempo di exploit (se disponibile)
        if attack.get("time_to_exploit"):
            ctk.CTkLabel(
                card,
                text=f"⏱️ Tempo stimato: {attack['time_to_exploit']}",
                font=ctk.CTkFont(size=11),
                text_color="#A78BFA",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 15))
        else:
            # Padding finale
            ctk.CTkFrame(card, height=10, fg_color="transparent").pack()
    
    def _run_ai_analysis(self):
        """Esegue l'analisi AI con Gemini"""
        if not hasattr(self, 'ai_var') or not self.ai_var.get():
            return
        
        self._log("🤖 Avvio analisi AI con Gemini...", "info")
        
        analyzer = GeminiAnalyzer()
        if not analyzer.is_configured:
            self._log("⚠️ API key Gemini non configurata in config.ini", "warning")
            return
        
        scan_data = self._get_scan_data()
        result = analyzer.analyze(scan_data)
        
        if "error" in result:
            self._log(f"❌ Errore AI: {result['error']}", "error")
            return
        
        self.ai_analysis = result
        self.after(0, self._update_ai_ui)
        self._log("✅ Analisi AI completata", "success")
    
    def _update_ai_ui(self):
        """Aggiorna la UI con l'analisi AI completa"""
        if not hasattr(self, 'ai_analysis') or not self.ai_analysis:
            return
        
        analysis = self.ai_analysis
        
        # Verifica se c'è stato un errore TOTALE di parsing (nessun dato estratto)
        if analysis.get('parse_error') and not analysis.get('risk_score') and analysis.get('risk_level') == 'SCONOSCIUTO':
            self._log("⚠️ Analisi AI: errore nel parsing della risposta", "warning")
            raw = analysis.get('raw_response', '')
            if raw:
                self._log(f"   Risposta grezza: {raw[:300]}...", "info")
            return
        
        # Separatore visivo
        self._log("=" * 50, "info")
        self._log("🤖 ANALISI AI GEMINI", "success")
        self._log("=" * 50, "info")
        
        # Notifica se il parsing è stato parziale o riparato
        if analysis.get('_partial_parse'):
            self._log("ℹ️ Nota: analisi estratta da JSON parziale", "info")
        if analysis.get('_json_repaired'):
            self._log("ℹ️ JSON riparato automaticamente", "info")
        
        # Risk Score con indicatore visivo
        risk_score = analysis.get('risk_score', 0)
        risk_level = analysis.get('risk_level', 'N/A')
        
        if risk_score >= 8:
            risk_icon = "🔴"
            risk_type = "error"
        elif risk_score >= 5:
            risk_icon = "🟠"
            risk_type = "warning"
        else:
            risk_icon = "🟢"
            risk_type = "success"
        
        self._log(f"{risk_icon} Risk Score: {risk_score}/10 - Livello: {risk_level}", risk_type)
        
        # Executive Summary completo
        summary = analysis.get('executive_summary', '')
        if summary:
            self._log("", "info")
            self._log("📋 SOMMARIO ESECUTIVO:", "info")
            # Dividi in righe per leggibilità
            words = summary.split()
            line = "   "
            for word in words:
                if len(line) + len(word) > 80:
                    self._log(line, "info")
                    line = "   " + word + " "
                else:
                    line += word + " "
            if line.strip():
                self._log(line, "info")
        
        # Scenario più probabile
        scenario = analysis.get('most_likely_scenario', '')
        if scenario:
            self._log("", "info")
            self._log("🎯 SCENARIO DI ATTACCO PIÙ PROBABILE:", "warning")
            for i in range(0, len(scenario), 75):
                self._log(f"   {scenario[i:i+75]}", "warning")
        
        # Tempo di compromissione
        ttc = analysis.get('time_to_compromise', '')
        if ttc:
            self._log("", "info")
            self._log(f"⏱️ Tempo stimato per compromissione: {ttc}", "error")
        
        # Attack Chain dettagliata
        attack_chain = analysis.get('attack_chain', [])
        if attack_chain:
            self._log("", "info")
            self._log("⛓️ ATTACK CHAIN (sequenza di attacco):", "warning")
            for step in attack_chain:
                step_num = step.get('step', '?')
                action = step.get('action', 'N/A')
                tool = step.get('tool', 'N/A')
                self._log(f"   [{step_num}] {action}", "warning")
                self._log(f"       └─ Tool: {tool}", "info")
        
        # Azioni prioritarie
        priority_actions = analysis.get('priority_actions', [])
        if priority_actions:
            self._log("", "info")
            self._log("🚨 AZIONI PRIORITARIE DI REMEDIATION:", "error")
            for i, action in enumerate(priority_actions, 1):
                self._log(f"   {i}. {action}", "error")
        
        # Raccomandazioni dettagliate
        recommendations = analysis.get('detailed_recommendations', [])
        if recommendations:
            self._log("", "info")
            self._log("📝 RACCOMANDAZIONI DETTAGLIATE:", "info")
            for rec in recommendations[:5]:
                issue = rec.get('issue', 'N/A')
                solution = rec.get('solution', 'N/A')
                priority = rec.get('priority', 'N/A')
                self._log(f"   • [{priority}] {issue}", "warning")
                self._log(f"     Soluzione: {solution}", "info")
        
        # Threat Actors
        threat_actors = analysis.get('threat_actors', '')
        if threat_actors:
            self._log("", "info")
            self._log(f"👤 Attori malevoli interessati: {threat_actors}", "warning")
        
        # Business Impact
        business_impact = analysis.get('business_impact', '')
        if business_impact:
            self._log("", "info")
            self._log("💼 IMPATTO SUL BUSINESS:", "error")
            for i in range(0, len(business_impact), 75):
                self._log(f"   {business_impact[i:i+75]}", "error")
        
        self._log("", "info")
        self._log("=" * 50, "info")
        self._log("✅ Analisi AI completata", "success")
    
    def _scan_complete(self):
        self.scan_running = False
        self.after(0, lambda: self.progress.stop())
        self.after(0, lambda: self.progress.set(0))
        self.after(0, lambda: self.scan_button.configure(state="normal", text="▶ Avvia Scansione"))
        self.after(0, lambda: self.target_entry.configure(state="normal"))
        # Aggiorna gli attacchi possibili
        self.after(0, self._update_attacks_ui)
        
        # Esegui analisi AI se richiesta
        if hasattr(self, 'ai_var') and self.ai_var.get():
            threading.Thread(target=self._run_ai_analysis, daemon=True).start()
        
        if self.vulnerabilities or self.open_ports:
            self.after(0, lambda: self.export_json_btn.configure(state="normal"))
            self.after(0, lambda: self.export_html_btn.configure(state="normal"))
            self.after(0, lambda: self.export_txt_btn.configure(state="normal"))
            self.after(0, lambda: self.export_all_btn.configure(state="normal"))
    
    def _get_scan_data(self) -> dict:
        """Prepara i dati della scansione per l'export"""
        # Prepara gli attacchi nel formato corretto
        attacks_data = {
            "destructive_attacks": [],
            "probable_attacks": [],
            "total_attacks": 0
        }
        
        if self.possible_attacks:
            attacks_data["destructive_attacks"] = self.possible_attacks.get("destructive", [])
            attacks_data["probable_attacks"] = self.possible_attacks.get("probable", [])
            attacks_data["total_attacks"] = len(attacks_data["destructive_attacks"]) + len(attacks_data["probable_attacks"])
        
        data = {
            "scanner_version": Config.VERSION,
            "scan_timestamp": datetime.now().isoformat(),
            "scan_date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "target": self.scan_target,
            "ip": self.scan_ip,
            "open_ports": self.open_ports,
            "vulnerabilities": self.vulnerabilities,
            "attacks": attacks_data,
            "possible_attacks": attacks_data["destructive_attacks"] + attacks_data["probable_attacks"],  # Retrocompatibilità
            "geolocation": {},
            "network_info": {},
            "hosting": {},
            "ssl_info": {},
            "web_technologies": {},
            "network_status": self.network_checker.to_dict(),
            "ai_analysis": getattr(self, 'ai_analysis', None)
        }
        
        if self.geo_hosting_info:
            geo_dict = self.geo_hosting_info.to_dict()
            data["geolocation"] = geo_dict.get("geolocation", {})
            data["network_info"] = geo_dict.get("network", {})
            data["hosting"] = geo_dict.get("hosting", {})
        
        if self.ssl_info:
            data["ssl_info"] = self.ssl_info.to_dict()
        
        if self.web_tech_info:
            data["web_technologies"] = self.web_tech_info.to_dict()
        
        return data
    
    def _export_json(self):
        """Esporta report in formato JSON"""
        if not self.scan_target:
            messagebox.showwarning("Attenzione", "Nessuna scansione da esportare")
            return
        
        try:
            safe_target = re.sub(r'[^\w\-.]', '_', self.scan_target)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_target}_{timestamp}.json"
            filepath = self.output_path / filename
            
            self.output_path.mkdir(parents=True, exist_ok=True)
            
            data = self._get_scan_data()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self._log(f"JSON salvato: {filepath}", "success")
            messagebox.showinfo("Export JSON", f"Report JSON salvato:\n\n{filepath}")
            
            return filepath
            
        except Exception as e:
            self._log(f"Errore export JSON: {str(e)}", "error")
            messagebox.showerror("Errore", f"Errore esportazione JSON:\n{str(e)}")
            return None
    
    def _export_html(self):
        """Esporta report in formato HTML"""
        if not self.scan_target:
            messagebox.showwarning("Attenzione", "Nessuna scansione da esportare")
            return
        
        try:
            safe_target = re.sub(r'[^\w\-.]', '_', self.scan_target)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_target}_{timestamp}.html"
            filepath = self.output_path / filename
            
            self.output_path.mkdir(parents=True, exist_ok=True)
            
            data = self._get_scan_data()
            html_content = HTMLReportGenerator.generate(data)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self._log(f"HTML salvato: {filepath}", "success")
            messagebox.showinfo("Export HTML", f"Report HTML salvato:\n\n{filepath}")
            
            # Apri nel browser
            try:
                import webbrowser
                webbrowser.open(f"file://{filepath}")
            except Exception:
                pass
            
            return filepath
            
        except Exception as e:
            self._log(f"Errore export HTML: {str(e)}", "error")
            messagebox.showerror("Errore", f"Errore esportazione HTML:\n{str(e)}")
            return None
    
    def _export_txt(self):
        """Esporta report in formato TXT"""
        if not self.scan_target:
            messagebox.showwarning("Attenzione", "Nessuna scansione da esportare")
            return
        
        try:
            safe_target = re.sub(r'[^\w\-.]', '_', self.scan_target)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_target}_{timestamp}.txt"
            filepath = self.output_path / filename
            
            self.output_path.mkdir(parents=True, exist_ok=True)
            
            report = TextReport()
            
            # Info scansione
            report.add_section("Informazioni Scansione")
            report.add_info("Target", self.scan_target)
            report.add_info("IP", self.scan_ip)
            report.add_info("Data/Ora", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
            report.add_info("Porte aperte", str(len(self.open_ports)))
            report.add_info("Vulnerabilità rilevate", str(len(self.vulnerabilities)))
            
            # Geolocalizzazione
            if self.geo_hosting_info:
                geo = self.geo_hosting_info
                report.add_section("Geolocalizzazione")
                report.add_info("Paese", f"{geo.country} ({geo.country_code})")
                report.add_info("Regione", geo.region_name)
                report.add_info("Città", geo.city)
                report.add_info("Coordinate", f"{geo.latitude}, {geo.longitude}")
                report.add_info("ISP", geo.isp)
                report.add_info("Organizzazione", geo.organization)
                report.add_info("ASN", geo.asn)
                report.add_info("È Hosting", "Sì" if geo.is_hosting else "No")
                if geo.is_hosting:
                    report.add_info("Provider", geo.hosting_provider)
            
            # Configurazione rete
            report.add_section("Configurazione Rete")
            nc = self.network_checker
            if nc.interfaces:
                for iface in nc.interfaces:
                    report.add_info(f"Interfaccia {iface['name']}", ", ".join(iface["addresses"]) or "N/A")
            report.add_info("Gateway", nc.gateway or "Non rilevato")
            report.add_info("DNS", ", ".join(nc.dns_servers) if nc.dns_servers else "Non rilevati")
            report.add_info("IP Pubblico", nc.public_ip or "Non verificabile")
            report.add_info("Rete TOR", "ATTIVA" if nc.tor_status["active"] else "NON ATTIVA")
            
            # Porte aperte
            if self.open_ports:
                report.add_section("Porte Aperte")
                for p in self.open_ports:
                    report.add_port(p["port"], p["service"])
            
            # Vulnerabilità
            if self.vulnerabilities:
                report.add_section("Vulnerabilità Rilevate")
                severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3}
                for vuln in sorted(self.vulnerabilities, key=lambda x: severity_order.get(x["severity"], 4)):
                    report.add_vulnerability(
                        vuln["severity"], vuln["title"], vuln["description"],
                        vuln["remediation"], vuln.get("cve", ""), vuln.get("cve_desc", "")
                    )
            else:
                report.add_section("Vulnerabilità Rilevate")
                report.add_info("Stato", "Nessuna vulnerabilità critica rilevata")
            
            # Attacchi Possibili
            if self.possible_attacks:
                # Estrai attacchi dal dict
                destructive_attacks = self.possible_attacks.get("destructive", []) if isinstance(self.possible_attacks, dict) else []
                probable_attacks = self.possible_attacks.get("probable", []) if isinstance(self.possible_attacks, dict) else []
                
                # Attacchi Distruttivi
                if destructive_attacks:
                    report.add_section("Attacchi Distruttivi (Compromissione Totale)")
                    report.add_empty_line()
                    report.lines.append("  💀 Attacchi che permettono compromissione completa del sistema:")
                    report.add_empty_line()
                    
                    for i, attack in enumerate(destructive_attacks, 1):
                        report.add_empty_line()
                        report.lines.append(f"  [{attack.get('severity', 'CRITICA')}] ATTACCO DISTRUTTIVO #{i}: {attack.get('name', 'N/A')}")
                        report.lines.append(f"    Tipo: {attack.get('type', 'N/A')}")
                        report.lines.append(f"    Descrizione: {attack.get('description', 'N/A')}")
                        report.lines.append(f"    Tools: {attack.get('tools', 'N/A')}")
                        report.lines.append(f"    Impatto: {attack.get('impact', 'N/A')}")
                        report.lines.append(f"    Tempo exploit: {attack.get('time_to_exploit', 'N/A')}")
                
                # Attacchi Probabili
                if probable_attacks:
                    report.add_section("Attacchi Probabili (Backdoor e Persistenza)")
                    report.add_empty_line()
                    report.lines.append("  🎯 Attacchi realistici per accesso persistente:")
                    report.add_empty_line()
                    
                    for i, attack in enumerate(probable_attacks, 1):
                        report.add_empty_line()
                        report.lines.append(f"  [{attack.get('severity', 'ALTA')}] ATTACCO PROBABILE #{i}: {attack.get('name', 'N/A')}")
                        report.lines.append(f"    Tipo: {attack.get('type', 'N/A')}")
                        report.lines.append(f"    Descrizione: {attack.get('description', 'N/A')}")
                        report.lines.append(f"    Tools: {attack.get('tools', 'N/A')}")
                        report.lines.append(f"    Impatto: {attack.get('impact', 'N/A')}")
            
            # Analisi AI (se disponibile)
            ai_has_data = (
                hasattr(self, 'ai_analysis') and self.ai_analysis and (
                    self.ai_analysis.get("risk_score", 0) > 0 or 
                    (self.ai_analysis.get("risk_level") and self.ai_analysis.get("risk_level") not in ["SCONOSCIUTO", "ERRORE", "N/A"])
                )
            )
            if ai_has_data:
                ai = self.ai_analysis
                report.add_section("Analisi AI Gemini")
                report.add_empty_line()
                
                # Risk Score
                risk_score = ai.get('risk_score', 0)
                risk_level = ai.get('risk_level', 'N/A')
                report.lines.append(f"  🤖 RISK SCORE: {risk_score}/10 - Livello: {risk_level}")
                report.add_empty_line()
                
                # Executive Summary
                summary = ai.get('executive_summary', '')
                if summary:
                    report.lines.append("  📋 SOMMARIO ESECUTIVO:")
                    # Dividi in righe da ~70 caratteri
                    words = summary.split()
                    line = "     "
                    for word in words:
                        if len(line) + len(word) > 70:
                            report.lines.append(line)
                            line = "     " + word + " "
                        else:
                            line += word + " "
                    if line.strip():
                        report.lines.append(line)
                    report.add_empty_line()
                
                # Scenario
                scenario = ai.get('most_likely_scenario', '')
                if scenario:
                    report.lines.append("  🎯 SCENARIO DI ATTACCO PIÙ PROBABILE:")
                    words = scenario.split()
                    line = "     "
                    for word in words:
                        if len(line) + len(word) > 70:
                            report.lines.append(line)
                            line = "     " + word + " "
                        else:
                            line += word + " "
                    if line.strip():
                        report.lines.append(line)
                    report.add_empty_line()
                
                # Time to Compromise
                ttc = ai.get('time_to_compromise', '')
                if ttc:
                    report.lines.append(f"  ⏱️ TEMPO STIMATO PER COMPROMISSIONE: {ttc}")
                    report.add_empty_line()
                
                # Attack Chain
                attack_chain = ai.get('attack_chain', [])
                if attack_chain:
                    report.lines.append("  ⛓️ ATTACK CHAIN:")
                    for step in attack_chain:
                        step_num = step.get('step', '?')
                        action = step.get('action', 'N/A')
                        tool = step.get('tool', 'N/A')
                        report.lines.append(f"     [{step_num}] {action}")
                        report.lines.append(f"         Tool: {tool}")
                    report.add_empty_line()
                
                # Priority Actions
                priority_actions = ai.get('priority_actions', [])
                if priority_actions:
                    report.lines.append("  🚨 AZIONI PRIORITARIE DI REMEDIATION:")
                    for i, action in enumerate(priority_actions, 1):
                        report.lines.append(f"     {i}. {action}")
                    report.add_empty_line()
                
                # Detailed Recommendations
                recommendations = ai.get('detailed_recommendations', [])
                if recommendations:
                    report.lines.append("  📝 RACCOMANDAZIONI DETTAGLIATE:")
                    for rec in recommendations[:5]:
                        issue = rec.get('issue', 'N/A')
                        solution = rec.get('solution', 'N/A')
                        priority = rec.get('priority', 'N/A')
                        report.lines.append(f"     • [{priority}] {issue}")
                        report.lines.append(f"       Soluzione: {solution}")
                    report.add_empty_line()
                
                # Business Impact
                business_impact = ai.get('business_impact', '')
                if business_impact:
                    report.lines.append("  💼 IMPATTO SUL BUSINESS:")
                    words = business_impact.split()
                    line = "     "
                    for word in words:
                        if len(line) + len(word) > 70:
                            report.lines.append(line)
                            line = "     " + word + " "
                        else:
                            line += word + " "
                    if line.strip():
                        report.lines.append(line)
                    report.add_empty_line()
                
                # Threat Actors
                threat_actors = ai.get('threat_actors', '')
                if threat_actors:
                    report.lines.append(f"  👤 ATTORI MALEVOLI: {threat_actors}")
                    report.add_empty_line()
            
            # Riepilogo
            report.add_section("Riepilogo")
            counts = {s: len([v for v in self.vulnerabilities if v["severity"] == s]) 
                     for s in ["CRITICA", "ALTA", "MEDIA", "BASSA"]}
            for sev, cnt in counts.items():
                if cnt > 0:
                    report.add_info(f"Vulnerabilità {sev}", str(cnt))
            
            # Livello di rischio - usa quello dell'AI se disponibile, altrimenti calcola
            if ai_has_data and self.ai_analysis.get('risk_level') not in ["SCONOSCIUTO", "ERRORE", "N/A", None]:
                risk = self.ai_analysis.get('risk_level')
                risk_source = "(da Analisi AI)"
            else:
                risk = "CRITICO" if counts["CRITICA"] else "ALTO" if counts["ALTA"] else "MEDIO" if counts["MEDIA"] else "BASSO"
                risk_source = "(da vulnerabilità rilevate)"
            
            report.add_empty_line()
            report.lines.append(f"  Fonte valutazione: {risk_source}")
            report.add_risk_level(risk)
            
            # Salva
            report.save(str(filepath))
            
            self._log(f"TXT salvato: {filepath}", "success")
            messagebox.showinfo("Export TXT", f"Report TXT salvato:\n\n{filepath}")
            
            return filepath
            
        except Exception as e:
            self._log(f"Errore export TXT: {str(e)}", "error")
            messagebox.showerror("Errore", f"Errore esportazione TXT:\n{str(e)}")
            return None
    
    def _export_all(self):
        """Esporta report in tutti i formati"""
        if not self.scan_target:
            messagebox.showwarning("Attenzione", "Nessuna scansione da esportare")
            return
        
        try:
            self._log("Esportazione report in tutti i formati...", "info")
            
            json_path = self._export_json()
            html_path = self._export_html()
            txt_path = self._export_txt()
            
            # Apri cartella
            try:
                if os.name == 'nt':
                    os.startfile(self.output_path)
                else:
                    subprocess.run(['xdg-open', str(self.output_path)], check=False)
            except Exception:
                pass
            
            messagebox.showinfo(
                "Export Completato", 
                f"Report esportati in:\n\n{self.output_path}\n\n• JSON\n• HTML\n• TXT"
            )
            
        except Exception as e:
            self._log(f"Errore export: {str(e)}", "error")
            messagebox.showerror("Errore", f"Errore esportazione:\n{str(e)}")


def main():
    app = StealthScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
