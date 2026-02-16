#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    STEALTH VULNERABILITY SCANNER v3.1 CLI                      ║
║                                                                                 ║
║  Scanner stealth con:                                                          ║
║  - Verifica EFFETTIVA delle vulnerabilità                                      ║
║  - Rilevazione Hosting Provider                                                ║
║  - Geolocalizzazione Completa                                                  ║
║  - Analisi Attacchi Distruttivi (3) e Probabili (5)                           ║
║  - Integrazione AI Gemini per analisi avanzata                                 ║
║  - Export JSON, HTML, TXT                                                      ║
║                                                                                 ║
║  Autore: Red-Penguin                                                           ║
║  Versione: 3.1                                                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import socket
import ssl
import sys
import json
import re
import struct
import argparse
import subprocess
import concurrent.futures
import os
import configparser
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Any

# Gestione import opzionali
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ==================== CONFIGURAZIONE ====================

class Config:
    """Configurazione dello scanner"""
    VERSION = "3.1"
    TIMEOUT = 5
    TIMEOUT_FAST = 2
    MAX_THREADS = 5
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    OUTPUT_FOLDER = "Analisi"
    CONFIG_FILE = "config.ini"
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    DEFAULT_CREDS = {
        "ftp": [("anonymous", "anonymous@"), ("ftp", "ftp"), ("guest", "guest")],
        "mysql": [("root", ""), ("root", "root"), ("root", "password"), ("mysql", "mysql")],
        "postgres": [("postgres", ""), ("postgres", "postgres"), ("admin", "admin")],
        "redis": [None],
        "mongodb": [None],
        "vnc": [("", ""), ("", "password"), ("", "vnc")],
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
    
    GEMINI_MODELS = [
        "gemini-2.0-flash-exp", "gemini-1.5-flash", "gemini-1.5-flash-8b",
        "gemini-1.5-pro", "gemini-1.0-pro"
    ]
    
    # Database attacchi distruttivi
    DESTRUCTIVE_ATTACKS = {
        "smb_exposed": {
            "name": "EternalBlue / WannaCry",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Sfruttamento della vulnerabilità SMBv1 per esecuzione codice remoto.",
            "tools": "Metasploit (ms17_010_eternalblue), nmap --script smb-vuln-ms17-010",
            "impact": "Compromissione totale del sistema, movimento laterale, ransomware",
            "time_to_exploit": "< 5 minuti"
        },
        "rdp_exposed": {
            "name": "BlueKeep RCE Attack",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Vulnerabilità pre-auth in RDP che permette esecuzione codice senza credenziali.",
            "tools": "Metasploit (cve_2019_0708_bluekeep), rdpscan",
            "impact": "Accesso completo al sistema, possibilità di propagazione automatica",
            "time_to_exploit": "< 10 minuti"
        },
        "redis_noauth": {
            "name": "Redis Unauthorized RCE",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Redis senza autenticazione permette scrittura file e esecuzione comandi.",
            "tools": "redis-cli, redis-rogue-server, redis-exploit",
            "impact": "Esecuzione comandi come utente redis, escalation a root",
            "time_to_exploit": "< 3 minuti"
        },
        "mongodb_exposed": {
            "name": "MongoDB Ransomware Attack",
            "type": "Data Theft / Ransomware",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "Database MongoDB esposto senza autenticazione.",
            "tools": "mongosh, nosqlmap, mongodump",
            "impact": "Furto completo dei dati, cancellazione database, estorsione",
            "time_to_exploit": "< 2 minuti"
        },
        "mssql_exposed": {
            "name": "MSSQL xp_cmdshell RCE",
            "type": "Remote Code Execution",
            "severity": "CRITICA",
            "category": "DISTRUTTIVO",
            "description": "SQL Server esposto può permettere esecuzione comandi OS tramite xp_cmdshell.",
            "tools": "impacket-mssqlclient, sqlcmd, Metasploit",
            "impact": "Esecuzione comandi NT AUTHORITY\\SYSTEM",
            "time_to_exploit": "< 15 minuti"
        }
    }
    
    # Database attacchi probabili (backdoor, persistenza, ecc.)
    PROBABLE_ATTACKS = {
        "ssh_key_injection": {
            "name": "SSH Key Injection (Backdoor)",
            "type": "Persistence / Backdoor",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Iniezione di chiave SSH pubblica in authorized_keys per accesso persistente.",
            "tools": "redis-cli (via Redis), FTP upload, web shell",
            "impact": "Accesso SSH permanente, sopravvive a reboot",
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
            "impact": "Esecuzione comandi via web, esfiltrazione dati",
            "time_to_exploit": "< 5 minuti",
            "triggered_by": ["ftp_anonymous", "git_exposed", "env_exposed"]
        },
        "reverse_shell": {
            "name": "Reverse Shell Connection",
            "type": "Remote Access",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Connessione reverse per bypass firewall.",
            "tools": "nc, bash, python, powershell, msfvenom",
            "impact": "Shell interattiva, bypass firewall ingress",
            "time_to_exploit": "< 2 minuti",
            "triggered_by": ["redis_noauth", "postgres_exposed", "mssql_exposed", "mysql_exposed"]
        },
        "credential_harvesting": {
            "name": "Credential Harvesting",
            "type": "Credential Theft",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Estrazione credenziali da file config, .env, database.",
            "tools": "mimikatz, LaZagne, truffleHog",
            "impact": "Accesso ad altri sistemi, escalation privilegi",
            "time_to_exploit": "< 10 minuti",
            "triggered_by": ["env_exposed", "git_exposed", "phpinfo_exposed", "ftp_anonymous"]
        },
        "cron_backdoor": {
            "name": "Cron/Task Scheduler Backdoor",
            "type": "Persistence",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Persistenza tramite cron job o Task Scheduler.",
            "tools": "crontab, schtasks, at",
            "impact": "Persistenza garantita, riconnessione automatica",
            "time_to_exploit": "< 3 minuti",
            "triggered_by": ["redis_noauth", "ssh_weak", "postgres_exposed"]
        },
        "cryptominer_deploy": {
            "name": "Cryptominer Deployment",
            "type": "Resource Hijacking",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Installazione di cryptominer per mining Monero.",
            "tools": "xmrig, cryptonight, coinhive",
            "impact": "Consumo CPU/GPU, costi elettrici",
            "time_to_exploit": "< 5 minuti",
            "triggered_by": ["redis_noauth", "mongodb_exposed", "ssh_weak"]
        },
        "lateral_movement": {
            "name": "Lateral Movement Preparation",
            "type": "Reconnaissance / Pivot",
            "severity": "MEDIA",
            "category": "PROBABILE",
            "description": "Scansione rete interna per movimento laterale.",
            "tools": "nmap, masscan, crackmapexec, BloodHound",
            "impact": "Mappatura rete interna, identificazione domain controller",
            "time_to_exploit": "10-30 minuti",
            "triggered_by": ["smb_exposed", "rdp_exposed", "ssh_weak"]
        },
        "data_exfiltration": {
            "name": "Data Exfiltration",
            "type": "Data Theft",
            "severity": "ALTA",
            "category": "PROBABILE",
            "description": "Esfiltrazione dati via DNS tunneling, HTTPS, o canali nascosti.",
            "tools": "dnscat2, iodine, HTTPTunnel, rclone",
            "impact": "Furto dati sensibili, violazione GDPR",
            "time_to_exploit": "variabile",
            "triggered_by": ["mongodb_exposed", "mysql_exposed", "postgres_exposed", "ftp_anonymous"]
        }
    }
    
    # Database legacy per retrocompatibilità
    ATTACK_DATABASE = {
        "smb_exposed": DESTRUCTIVE_ATTACKS["smb_exposed"],
        "rdp_exposed": DESTRUCTIVE_ATTACKS["rdp_exposed"],
        "redis_noauth": DESTRUCTIVE_ATTACKS["redis_noauth"],
        "mongodb_exposed": DESTRUCTIVE_ATTACKS["mongodb_exposed"],
        "mssql_exposed": DESTRUCTIVE_ATTACKS["mssql_exposed"],
        "mysql_exposed": {"name": "MySQL Auth Bypass", "type": "Auth Bypass", "severity": "ALTA", "category": "DISTRUTTIVO", "description": "Bypass autenticazione MySQL.", "tools": "hydra, medusa", "impact": "Accesso ai database"},
        "postgres_exposed": {"name": "PostgreSQL Command Injection", "type": "Command Exec", "severity": "ALTA", "category": "DISTRUTTIVO", "description": "Esecuzione comandi OS.", "tools": "pgcli, SQLMAP", "impact": "Esecuzione comandi sul server"},
        "ftp_anonymous": {"name": "FTP Anonymous Access", "type": "Info Disclosure", "severity": "ALTA", "category": "PROBABILE", "description": "Accesso anonimo FTP.", "tools": "ftp, wget", "impact": "Furto file, upload malware"},
        "vnc_exposed": {"name": "VNC Brute Force", "type": "Unauth Access", "severity": "ALTA", "category": "DISTRUTTIVO", "description": "Brute force VNC.", "tools": "hydra, crowbar", "impact": "Controllo desktop remoto"},
        "git_exposed": {"name": "Git Repository Extraction", "type": "Source Disclosure", "severity": "ALTA", "category": "PROBABILE", "description": "Download codice sorgente.", "tools": "git-dumper", "impact": "Accesso codice, credenziali"},
        "env_exposed": {"name": "Environment File Extraction", "type": "Credential Disclosure", "severity": "ALTA", "category": "PROBABILE", "description": "File .env esposto.", "tools": "curl, wget", "impact": "Accesso credenziali"},
        "telnet": {"name": "Telnet Sniffing", "type": "MitM", "severity": "MEDIA", "category": "PROBABILE", "description": "Traffico in chiaro.", "tools": "Wireshark", "impact": "Intercettazione credenziali"},
        "hsts_missing": {"name": "SSL Stripping", "type": "MitM", "severity": "MEDIA", "category": "PROBABILE", "description": "Downgrade a HTTP.", "tools": "sslstrip", "impact": "Intercettazione sessioni"},
        "xframe_missing": {"name": "Clickjacking", "type": "UI Redressing", "severity": "MEDIA", "category": "PROBABILE", "description": "Iframe malevolo.", "tools": "Burp Suite", "impact": "Azioni non autorizzate"},
        "csp_missing": {"name": "XSS", "type": "Script Injection", "severity": "MEDIA", "category": "PROBABILE", "description": "Cross-Site Scripting.", "tools": "XSStrike", "impact": "Furto sessioni"},
        "ssl_weak": {"name": "SSL/TLS Downgrade", "type": "Crypto Attack", "severity": "MEDIA", "category": "PROBABILE", "description": "Protocolli deboli.", "tools": "testssl.sh", "impact": "Decrittazione traffico"},
        "phpinfo_exposed": {"name": "PHPInfo Exposure", "type": "Info Disclosure", "severity": "MEDIA", "category": "PROBABILE", "description": "Configurazione esposta.", "tools": "Browser", "impact": "Info gathering"},
        "ssh_weak": {"name": "SSH Brute Force", "type": "Brute Force", "severity": "MEDIA", "category": "PROBABILE", "description": "Attacco dizionario.", "tools": "hydra, medusa", "impact": "Accesso shell"}
    }


class ConfigManager:
    """Gestisce la configurazione da file config.ini"""
    
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_path = Path(__file__).parent / "config.ini"
        self.load()
    
    def load(self):
        if self.config_path.exists():
            self.config.read(self.config_path, encoding='utf-8')
    
    def get(self, section: str, key: str, fallback: str = "") -> str:
        try:
            return self.config.get(section, key)
        except:
            return fallback
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        try:
            return self.config.getint(section, key)
        except:
            return fallback
    
    @property
    def gemini_api_key(self) -> str:
        key = self.get("GEMINI", "api_key", "")
        return "" if key == "YOUR_GEMINI_API_KEY_HERE" else key
    
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
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    def analyze(self, scan_data: dict) -> dict:
        if not self.is_configured:
            return {"error": "API key Gemini non configurata in config.ini"}
        if not HAS_REQUESTS:
            return {"error": "Modulo 'requests' non disponibile"}
        
        try:
            prompt = self._build_prompt(scan_data)
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
            
            response = requests.post(url, json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.7, "maxOutputTokens": 2048}
            }, timeout=self.timeout)
            
            if response.status_code == 200:
                text = response.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return self._parse_response(text)
            else:
                return {"error": response.json().get("error", {}).get("message", f"HTTP {response.status_code}")}
        except Exception as e:
            return {"error": str(e)}
    
    def _build_prompt(self, scan_data: dict) -> str:
        lang = "italiano" if self.language == "it" else "English"
        vulns = "\n".join([f"- [{v.get('severity')}] {v.get('title')}" for v in scan_data.get("vulnerabilities", [])])
        ports = "\n".join([f"- Porta {p.get('port') if isinstance(p, dict) else p}" for p in scan_data.get("open_ports", [])])
        
        return f"""Sei un esperto di cybersecurity. Analizza i risultati della scansione in {lang}.

TARGET: {scan_data.get('target')} | IP: {scan_data.get('ip')}
PORTE APERTE:
{ports or 'Nessuna'}
VULNERABILITÀ:
{vulns or 'Nessuna'}

Rispondi SOLO in JSON:
{{"risk_score": <1-10>, "risk_level": "<CRITICO|ALTO|MEDIO|BASSO>", "executive_summary": "<sommario>", "attack_chain": [{{"step": 1, "action": "<desc>", "tool": "<tool>"}}], "most_likely_scenario": "<scenario>", "time_to_compromise": "<tempo>", "priority_actions": ["<azione1>", "<azione2>"], "business_impact": "<impatto>"}}"""
    
    def _parse_response(self, text: str) -> dict:
        try:
            text = text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except:
            return {"raw_response": text, "risk_score": 0, "risk_level": "SCONOSCIUTO"}


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
        
        if self.is_hosting:
            self.hosting_provider = self.organization or self.isp or "Unknown Hosting"
            self.datacenter = "Unknown Datacenter"


# ==================== NETWORK STATUS CHECKER ====================

class NetworkStatusChecker:
    """Verifica lo stato della rete e la connessione TOR"""
    
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.interfaces = []
        self.gateway = None
        self.dns_servers = []
        self.tor_status = {
            "active": False,
            "process_running": False,
            "socks_port_open": False,
            "exit_node": None,
            "ip_address": None
        }
    
    def check_all(self):
        """Esegue tutti i controlli di rete"""
        self._get_interfaces()
        self._get_gateway()
        self._get_dns()
        self._check_tor_status()
    
    def _run_command(self, cmd: List[str]) -> str:
        """Esegue un comando e restituisce l'output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return ""
    
    def _get_interfaces(self):
        """Ottiene le interfacce di rete attive"""
        try:
            # Metodo 1: ip addr (formato completo)
            output = self._run_command(["ip", "addr", "show"])
            if output:
                current_iface = None
                for line in output.split('\n'):
                    # Nuova interfaccia: "2: eth0: <BROADCAST,..."
                    iface_match = re.match(r'^\d+:\s+(\S+?)[@:].*state\s+(\w+)', line)
                    if iface_match:
                        name = iface_match.group(1)
                        state = iface_match.group(2)
                        if state == "UP" and name != "lo":
                            current_iface = {"name": name, "status": "UP", "addresses": []}
                        else:
                            current_iface = None
                    # Indirizzo IPv4: "    inet 192.168.1.100/24..."
                    elif current_iface and "inet " in line and "inet6" not in line:
                        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', line)
                        if match:
                            current_iface["addresses"].append(match.group(1))
                            if current_iface not in self.interfaces:
                                self.interfaces.append(current_iface)
                if self.interfaces:
                    return
            
            # Metodo 2: ip -br addr (formato breve)
            output = self._run_command(["ip", "-br", "addr"])
            if output:
                for line in output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "UP" and parts[0] != "lo":
                        iface = {
                            "name": parts[0],
                            "status": parts[1],
                            "addresses": parts[2:] if len(parts) > 2 else []
                        }
                        self.interfaces.append(iface)
                if self.interfaces:
                    return
            
            # Metodo 3: ifconfig (fallback)
            output = self._run_command(["ifconfig"])
            if output:
                current_iface = None
                for line in output.split('\n'):
                    if line and not line.startswith(' ') and not line.startswith('\t'):
                        parts = line.split(':')
                        if parts[0] != "lo":
                            current_iface = {"name": parts[0], "status": "UP", "addresses": []}
                    elif current_iface and "inet " in line:
                        match = re.search(r'inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            current_iface["addresses"].append(match.group(1))
                            if current_iface not in self.interfaces:
                                self.interfaces.append(current_iface)
            
            # Metodo 4: lettura diretta da /proc/net (ultimo fallback)
            if not self.interfaces:
                try:
                    with open('/proc/net/route', 'r') as f:
                        lines = f.readlines()[1:]  # Salta header
                        for line in lines:
                            parts = line.split()
                            if parts and parts[0] != "lo":
                                iface_name = parts[0]
                                if not any(i["name"] == iface_name for i in self.interfaces):
                                    self.interfaces.append({
                                        "name": iface_name,
                                        "status": "UP",
                                        "addresses": ["(rilevato da routing)"]
                                    })
                except:
                    pass
                    
        except Exception:
            pass
    
    def _get_gateway(self):
        """Ottiene il gateway predefinito"""
        try:
            output = self._run_command(["ip", "route", "show", "default"])
            if output:
                match = re.search(r'default via (\S+)', output)
                if match:
                    self.gateway = match.group(1)
                    return
            
            # Fallback: route -n
            output = self._run_command(["route", "-n"])
            if output:
                for line in output.split('\n'):
                    if line.startswith('0.0.0.0'):
                        parts = line.split()
                        if len(parts) >= 2:
                            self.gateway = parts[1]
                            return
        except Exception:
            pass
    
    def _get_dns(self):
        """Ottiene i server DNS configurati"""
        try:
            # Metodo 1: resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns = parts[1]
                                if dns not in self.dns_servers:
                                    self.dns_servers.append(dns)
            except:
                pass
            
            # Metodo 2: resolvectl (systemd-resolved)
            if not self.dns_servers:
                output = self._run_command(["resolvectl", "status"])
                if output:
                    for line in output.split('\n'):
                        if 'DNS Servers:' in line or 'Current DNS Server:' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                dns = parts[1].strip()
                                if dns and dns not in self.dns_servers:
                                    self.dns_servers.append(dns)
            
            # Metodo 3: nmcli (NetworkManager)
            if not self.dns_servers:
                output = self._run_command(["nmcli", "dev", "show"])
                if output:
                    for line in output.split('\n'):
                        if 'IP4.DNS' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                dns = parts[1].strip()
                                if dns and dns not in self.dns_servers:
                                    self.dns_servers.append(dns)
                                    
        except Exception:
            pass
    
    def _check_tor_status(self):
        """Verifica lo stato della rete TOR"""
        import os
        
        # 1. Verifica se il processo TOR è in esecuzione
        try:
            output = self._run_command(["pgrep", "-x", "tor"])
            if output:
                self.tor_status["process_running"] = True
                # Ottieni anche il PID
                self.tor_status["tor_pid"] = output.strip().split('\n')[0]
        except Exception:
            pass
        
        # 2. Verifica se la porta SOCKS (9050) è aperta
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9050))
            sock.close()
            if result == 0:
                self.tor_status["socks_port_open"] = True
        except Exception:
            pass
        
        # 2b. Verifica anche porta SOCKS alternativa (9150 per Tor Browser)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9150))
            sock.close()
            if result == 0:
                self.tor_status["socks_port_open"] = True
                self.tor_status["tor_browser_mode"] = True
        except Exception:
            pass
        
        # 3. Verifica porta controllo TOR (9051) via TCP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9051))
            sock.close()
            if result == 0:
                self.tor_status["control_port_open"] = True
                self.tor_status["control_type"] = "TCP:9051"
        except Exception:
            pass
        
        # 3b. Verifica porta controllo alternativa (9151 per Tor Browser)
        if not self.tor_status.get("control_port_open"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 9151))
                sock.close()
                if result == 0:
                    self.tor_status["control_port_open"] = True
                    self.tor_status["control_type"] = "TCP:9151"
                    self.tor_status["tor_browser_mode"] = True
            except Exception:
                pass
        
        # 3c. Verifica Socket Unix di controllo (se TCP non disponibile)
        if not self.tor_status.get("control_port_open"):
            control_sockets = [
                "/var/run/tor/control",
                "/run/tor/control",
                "/var/lib/tor/control_socket",
                "/tmp/tor-control"
            ]
            for socket_path in control_sockets:
                if os.path.exists(socket_path):
                    try:
                        # Verifica se è effettivamente un socket
                        import stat
                        mode = os.stat(socket_path).st_mode
                        if stat.S_ISSOCK(mode):
                            self.tor_status["control_port_open"] = True
                            self.tor_status["control_type"] = f"Unix:{socket_path}"
                            break
                    except Exception:
                        pass
        
        # 3d. Leggi configurazione torrc per capire come è configurato il controllo
        if not self.tor_status.get("control_port_open"):
            torrc_paths = ["/etc/tor/torrc", "/etc/torrc", "/usr/local/etc/tor/torrc"]
            for torrc_path in torrc_paths:
                try:
                    with open(torrc_path, 'r') as f:
                        content = f.read()
                        # Cerca ControlPort
                        if re.search(r'^\s*ControlPort\s+(\d+)', content, re.MULTILINE):
                            self.tor_status["control_configured"] = "TCP (in torrc)"
                        elif re.search(r'^\s*ControlSocket\s+(\S+)', content, re.MULTILINE):
                            match = re.search(r'^\s*ControlSocket\s+(\S+)', content, re.MULTILINE)
                            self.tor_status["control_configured"] = f"Unix:{match.group(1)}"
                        elif re.search(r'^\s*#\s*ControlPort', content, re.MULTILINE):
                            self.tor_status["control_configured"] = "Disabilitato (commentato)"
                        break
                except Exception:
                    pass
        
        # 4. Verifica IP pubblico e se passa attraverso TOR
        if HAS_REQUESTS:
            try:
                # Prima ottieni IP pubblico normale
                response = requests.get(
                    "https://api.ipify.org?format=json",
                    timeout=5
                )
                if response.status_code == 200:
                    self.tor_status["ip_address"] = response.json().get("ip", "N/A")
            except Exception:
                pass
            
            # Verifica tramite check.torproject.org
            socks_port = 9150 if self.tor_status.get("tor_browser_mode") else 9050
            try:
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socks_port}",
                    "https": f"socks5h://127.0.0.1:{socks_port}"
                }
                response = requests.get(
                    "https://check.torproject.org/api/ip",
                    proxies=proxies,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("IsTor", False):
                        self.tor_status["active"] = True
                        self.tor_status["exit_node"] = data.get("IP", "Unknown")
            except Exception:
                # Se SOCKS è aperto ma non riesce a connettersi, TOR potrebbe essere in avvio
                if self.tor_status["socks_port_open"]:
                    self.tor_status["active"] = False
        
        # 5. Verifica regole iptables per AnonSurf/Transparent Proxy
        try:
            output = self._run_command(["iptables", "-t", "nat", "-L", "-n"])
            if output:
                if "9040" in output:  # TOR TransPort
                    self.tor_status["transparent_proxy"] = True
                    self.tor_status["anonsurf_active"] = True
                    self.tor_status["active"] = True
                if "REDIRECT" in output and "tor" in output.lower():
                    self.tor_status["transparent_proxy"] = True
        except Exception:
            pass
        
        # 6. Verifica se AnonSurf è installato e attivo
        try:
            # Controlla processo anonsurf
            output = self._run_command(["pgrep", "-f", "anonsurf"])
            if output:
                self.tor_status["anonsurf_active"] = True
            
            # Controlla stato con comando anonsurf
            output = self._run_command(["anonsurf", "status"])
            if output and "started" in output.lower():
                self.tor_status["anonsurf_active"] = True
                self.tor_status["active"] = True
        except Exception:
            pass
    
    def display_status(self):
        """Visualizza lo stato della rete"""
        if HAS_RICH:
            self._display_rich()
        else:
            self._display_plain()
    
    def _display_rich(self):
        """Visualizza con Rich"""
        # Costruisci contenuto pannello rete
        network_info = []
        
        # Interfacce
        network_info.append("[bold cyan]╔═ Interfacce di Rete ═╗[/bold cyan]")
        if self.interfaces:
            for iface in self.interfaces:
                addrs = ", ".join(iface["addresses"]) if iface["addresses"] else "Nessun IP"
                network_info.append(f"  [green]●[/green] {iface['name']}: {addrs}")
        else:
            network_info.append("  [yellow]⚠[/yellow] Nessuna interfaccia attiva rilevata")
        
        # Gateway
        network_info.append("")
        network_info.append("[bold cyan]╔═ Gateway Predefinito ═╗[/bold cyan]")
        if self.gateway:
            network_info.append(f"  [green]●[/green] {self.gateway}")
        else:
            network_info.append("  [yellow]⚠[/yellow] Non rilevato")
        
        # DNS
        network_info.append("")
        network_info.append("[bold cyan]╔═ Server DNS ═╗[/bold cyan]")
        if self.dns_servers:
            for dns in self.dns_servers:
                network_info.append(f"  [green]●[/green] {dns}")
        else:
            network_info.append("  [yellow]⚠[/yellow] Non rilevati")
        
        # IP Pubblico
        network_info.append("")
        network_info.append("[bold cyan]╔═ IP Pubblico ═╗[/bold cyan]")
        if self.tor_status.get("ip_address"):
            network_info.append(f"  [green]●[/green] {self.tor_status['ip_address']}")
        else:
            network_info.append("  [yellow]⚠[/yellow] Non verificabile")
        
        network_panel = Panel(
            "\n".join(network_info),
            title="[bold white]🌐 Configurazione Rete[/bold white]",
            border_style="blue",
            box=box.ROUNDED
        )
        
        # Pannello TOR
        tor_info = []
        
        if self.tor_status["active"]:
            tor_info.append("[bold green]✓ RETE TOR ATTIVA[/bold green]")
            tor_info.append("")
            if self.tor_status.get("exit_node"):
                tor_info.append(f"  [cyan]Exit Node:[/cyan] {self.tor_status['exit_node']}")
            if self.tor_status.get("anonsurf_active"):
                tor_info.append("  [cyan]AnonSurf:[/cyan] [green]Attivo[/green]")
            if self.tor_status.get("transparent_proxy"):
                tor_info.append("  [cyan]Transparent Proxy:[/cyan] [green]Attivo[/green]")
            tor_status_style = "green"
        else:
            tor_info.append("[bold red]✗ RETE TOR NON ATTIVA[/bold red]")
            tor_info.append("")
            tor_status_style = "red"
        
        # Dettagli stato TOR
        tor_info.append("[dim]─── Dettagli ───[/dim]")
        
        # Processo TOR
        if self.tor_status["process_running"]:
            pid_info = f" (PID: {self.tor_status.get('tor_pid', '?')})" if self.tor_status.get('tor_pid') else ""
            proc_status = f"[green]●[/green] Attivo{pid_info}"
        else:
            proc_status = "[red]○[/red] Non attivo"
        tor_info.append(f"  Processo TOR: {proc_status}")
        
        # Porta SOCKS
        if self.tor_status["socks_port_open"]:
            socks_port = "9150" if self.tor_status.get("tor_browser_mode") else "9050"
            socks_status = f"[green]●[/green] Aperta (:{socks_port})"
            if self.tor_status.get("tor_browser_mode"):
                socks_status += " [dim](Tor Browser)[/dim]"
        else:
            socks_status = "[red]○[/red] Chiusa"
        tor_info.append(f"  Porta SOCKS: {socks_status}")
        
        # Porta/Socket Controllo
        if self.tor_status.get("control_port_open"):
            ctrl_type = self.tor_status.get("control_type", "TCP:9051")
            ctrl_status = f"[green]●[/green] Attivo ({ctrl_type})"
        else:
            ctrl_status = "[red]○[/red] Non disponibile"
            # Mostra info sulla configurazione se trovata
            if self.tor_status.get("control_configured"):
                ctrl_status += f" [dim]({self.tor_status['control_configured']})[/dim]"
        tor_info.append(f"  Controllo TOR: {ctrl_status}")
        
        # Suggerimenti se TOR non è attivo
        if not self.tor_status["active"] and not self.tor_status["process_running"]:
            tor_info.append("")
            tor_info.append("[dim yellow]Suggerimento: avvia TOR con 'sudo systemctl start tor'")
            tor_info.append("oppure usa AnonSurf: 'sudo anonsurf start'[/dim yellow]")
        elif self.tor_status["process_running"] and not self.tor_status.get("control_port_open"):
            tor_info.append("")
            tor_info.append("[dim yellow]Nota: Per abilitare il controllo, modifica /etc/tor/torrc:")
            tor_info.append("  ControlPort 9051")
            tor_info.append("  CookieAuthentication 1[/dim yellow]")
        
        tor_panel = Panel(
            "\n".join(tor_info),
            title="[bold white]🧅 Stato Rete TOR[/bold white]",
            border_style=tor_status_style,
            box=box.ROUNDED
        )
        
        # Stampa i pannelli
        self.console.print()
        self.console.print(network_panel)
        self.console.print(tor_panel)
        self.console.print()
    
    def _display_plain(self):
        """Visualizza senza Rich"""
        print("\n" + "=" * 60)
        print("  🌐 CONFIGURAZIONE RETE")
        print("=" * 60)
        
        print("\n  Interfacce di Rete:")
        if self.interfaces:
            for iface in self.interfaces:
                addrs = ", ".join(iface["addresses"]) if iface["addresses"] else "Nessun IP"
                print(f"    ● {iface['name']}: {addrs}")
        else:
            print("    ⚠ Nessuna interfaccia attiva")
        
        print(f"\n  Gateway: {self.gateway if self.gateway else 'Non rilevato'}")
        
        print("\n  Server DNS:")
        if self.dns_servers:
            for dns in self.dns_servers:
                print(f"    ● {dns}")
        else:
            print("    ⚠ Non rilevati")
        
        if self.tor_status.get("ip_address"):
            print(f"\n  IP Pubblico: {self.tor_status['ip_address']}")
        
        print("\n" + "=" * 60)
        print("  🧅 STATO RETE TOR")
        print("=" * 60)
        
        if self.tor_status["active"]:
            print("\n  [✓] RETE TOR ATTIVA")
            if self.tor_status.get("exit_node"):
                print(f"      Exit Node: {self.tor_status['exit_node']}")
            if self.tor_status.get("anonsurf_active"):
                print("      AnonSurf: Attivo")
            if self.tor_status.get("transparent_proxy"):
                print("      Transparent Proxy: Attivo")
        else:
            print("\n  [✗] RETE TOR NON ATTIVA")
        
        # Processo TOR
        if self.tor_status['process_running']:
            pid_info = f" (PID: {self.tor_status.get('tor_pid', '?')})" if self.tor_status.get('tor_pid') else ""
            print(f"\n  Processo TOR: Attivo{pid_info}")
        else:
            print("\n  Processo TOR: Non attivo")
        
        # Porta SOCKS
        if self.tor_status['socks_port_open']:
            socks_port = "9150" if self.tor_status.get("tor_browser_mode") else "9050"
            socks_info = f"Aperta (:{socks_port})"
            if self.tor_status.get("tor_browser_mode"):
                socks_info += " (Tor Browser)"
            print(f"  Porta SOCKS: {socks_info}")
        else:
            print("  Porta SOCKS: Chiusa")
        
        # Controllo TOR
        if self.tor_status.get("control_port_open"):
            ctrl_type = self.tor_status.get("control_type", "TCP:9051")
            print(f"  Controllo TOR: Attivo ({ctrl_type})")
        else:
            ctrl_info = "Non disponibile"
            if self.tor_status.get("control_configured"):
                ctrl_info += f" ({self.tor_status['control_configured']})"
            print(f"  Controllo TOR: {ctrl_info}")
        
        # Suggerimenti
        if not self.tor_status["active"] and not self.tor_status["process_running"]:
            print("\n  Suggerimento: avvia TOR con 'sudo systemctl start tor'")
            print("  oppure usa AnonSurf: 'sudo anonsurf start'")
        elif self.tor_status["process_running"] and not self.tor_status.get("control_port_open"):
            print("\n  Nota: Per abilitare il controllo, modifica /etc/tor/torrc:")
            print("    ControlPort 9051")
            print("    CookieAuthentication 1")
        
        print("=" * 60 + "\n")


# ==================== OUTPUT MANAGER ====================

class OutputManager:
    """Gestisce l'output con o senza Rich"""
    
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.vulnerabilities = []
        self.info = []
        self.warnings = []
        self.verified_vulns = []  # Vulnerabilità verificate come reali
        self.false_positives = []  # Falsi positivi
    
    def print_banner(self):
        banner = """
   _____ _             _ _   _       _____                                 
  / ____| |           | | | | |     / ____|                                
 | (___ | |_ ___  __ _| | |_| |__  | (___   ___ __ _ _ __  _ __   ___ _ __ 
  \\___ \\| __/ _ \\/ _` | | __| '_ \\  \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
  ____) | ||  __/ (_| | | |_| | | | ____) | (_| (_| | | | | | | |  __/ |   
 |_____/ \\__\\___|\\__,_|_|\\__|_| |_||_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                            v2.2 - VERIFY
        """
        if HAS_RICH:
            self.console.print(banner, style="bold green")
            self.console.print(Panel.fit(
                "[cyan]Scanner Vulnerabilità Stealth con Verifica[/cyan]\n"
                "[dim]Distingue tra porte aperte e vulnerabilità reali[/dim]",
                border_style="green"
            ))
        else:
            print(banner)
            print("=" * 70)
            print("  Scanner Vulnerabilità Stealth con Verifica")
            print("  Distingue tra porte aperte e vulnerabilità reali")
            print("=" * 70)
    
    def print_status(self, message: str, status: str = "info"):
        colors = {"info": "blue", "success": "green", "warning": "yellow", "error": "red", "verify": "magenta"}
        symbols = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗", "verify": "🔍"}
        
        if HAS_RICH:
            self.console.print(f"[{colors[status]}][{symbols[status]}] {message}[/{colors[status]}]")
        else:
            print(f"[{symbols[status]}] {message}")
    
    def add_vulnerability(self, severity: str, title: str, description: str, 
                         remediation: str = "", verified: bool = False, 
                         exploitable: bool = False, evidence: str = ""):
        vuln = {
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
            "verified": verified,
            "exploitable": exploitable,
            "evidence": evidence
        }
        self.vulnerabilities.append(vuln)
        
        if verified and exploitable:
            self.verified_vulns.append(vuln)
        elif verified and not exploitable:
            self.false_positives.append(vuln)
    
    def add_info(self, category: str, key: str, value: str):
        self.info.append({"category": category, "key": key, "value": value})
    
    def print_results(self, target: str):
        if HAS_RICH:
            self._print_results_rich(target)
        else:
            self._print_results_plain(target)
    
    def _print_results_rich(self, target: str):
        # Tabella informazioni
        if self.info:
            info_table = Table(title="📊 Informazioni Rilevate", box=box.ROUNDED)
            info_table.add_column("Categoria", style="cyan")
            info_table.add_column("Elemento", style="white")
            info_table.add_column("Valore", style="green")
            
            for item in self.info:
                info_table.add_row(item["category"], item["key"], str(item["value"])[:50])
            
            self.console.print(info_table)
            self.console.print()
        
        # Tabella vulnerabilità VERIFICATE (realmente sfruttabili)
        verified_exploitable = [v for v in self.vulnerabilities if v.get("verified") and v.get("exploitable")]
        if verified_exploitable:
            self.console.print(Panel.fit(
                "[bold red]⚠️  ATTENZIONE: VULNERABILITÀ CONFERMATE E SFRUTTABILI[/bold red]",
                border_style="red"
            ))
            
            vuln_table = Table(title="🔓 Vulnerabilità VERIFICATE", box=box.HEAVY)
            vuln_table.add_column("Severità", style="bold")
            vuln_table.add_column("Vulnerabilità", style="white")
            vuln_table.add_column("Evidenza", style="yellow")
            vuln_table.add_column("Rimedio", style="dim")
            
            severity_colors = {
                "CRITICA": "bold red",
                "ALTA": "red",
                "MEDIA": "yellow",
                "BASSA": "green",
                "INFO": "blue"
            }
            
            severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3, "INFO": 4}
            sorted_vulns = sorted(verified_exploitable, key=lambda x: severity_order.get(x["severity"], 5))
            
            for vuln in sorted_vulns:
                color = severity_colors.get(vuln["severity"], "white")
                vuln_table.add_row(
                    f"[{color}]{vuln['severity']}[/{color}]",
                    vuln["title"],
                    vuln.get("evidence", "")[:40],
                    vuln["remediation"]
                )
            
            self.console.print(vuln_table)
            self.console.print()
        
        # Tabella porte aperte ma NON sfruttabili (falsi positivi)
        false_pos = [v for v in self.vulnerabilities if v.get("verified") and not v.get("exploitable")]
        if false_pos:
            fp_table = Table(title="✅ Porte Aperte ma NON Vulnerabili (Falsi Positivi)", box=box.SIMPLE)
            fp_table.add_column("Servizio", style="cyan")
            fp_table.add_column("Stato", style="green")
            fp_table.add_column("Note", style="dim")
            
            for vuln in false_pos:
                fp_table.add_row(
                    vuln["title"],
                    "Protetto/Non accessibile",
                    vuln.get("evidence", "Accesso negato")[:50]
                )
            
            self.console.print(fp_table)
            self.console.print()
        
        # Vulnerabilità non verificate (solo rilevate)
        unverified = [v for v in self.vulnerabilities if not v.get("verified")]
        if unverified:
            uv_table = Table(title="❓ Potenziali Vulnerabilità (Non Verificate)", box=box.SIMPLE)
            uv_table.add_column("Severità", style="bold")
            uv_table.add_column("Vulnerabilità", style="white")
            uv_table.add_column("Descrizione", style="dim")
            
            for vuln in unverified:
                uv_table.add_row(vuln["severity"], vuln["title"], vuln["description"][:50])
            
            self.console.print(uv_table)
            self.console.print()
        
        # Riepilogo finale
        critical_verified = len([v for v in verified_exploitable if v["severity"] == "CRITICA"])
        high_verified = len([v for v in verified_exploitable if v["severity"] == "ALTA"])
        medium_verified = len([v for v in verified_exploitable if v["severity"] == "MEDIA"])
        total_fp = len(false_pos)
        
        risk_level = "🟢 BASSO"
        risk_color = "green"
        if critical_verified > 0:
            risk_level = "🔴 CRITICO"
            risk_color = "red"
        elif high_verified > 0:
            risk_level = "🟠 ALTO"
            risk_color = "red"
        elif medium_verified > 0:
            risk_level = "🟡 MEDIO"
            risk_color = "yellow"
        
        self.console.print(Panel.fit(
            f"[bold]📋 Riepilogo Scansione[/bold]\n\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Livello di Rischio: [{risk_color}]{risk_level}[/{risk_color}]\n\n"
            f"[bold]Vulnerabilità CONFERMATE:[/bold]\n"
            f"  [red]• {critical_verified} Critiche[/red]\n"
            f"  [orange3]• {high_verified} Alte[/orange3]\n"
            f"  [yellow]• {medium_verified} Medie[/yellow]\n\n"
            f"[green]Falsi Positivi identificati: {total_fp}[/green]\n\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="Report Finale",
            border_style=risk_color
        ))
    
    def _print_results_plain(self, target: str):
        print("\n" + "=" * 70)
        print("VULNERABILITÀ VERIFICATE")
        print("=" * 70)
        
        verified = [v for v in self.vulnerabilities if v.get("verified") and v.get("exploitable")]
        if verified:
            for vuln in verified:
                print(f"\n  [{vuln['severity']}] {vuln['title']}")
                print(f"    Evidenza: {vuln.get('evidence', 'N/A')}")
                print(f"    Rimedio: {vuln['remediation']}")
        else:
            print("  Nessuna vulnerabilità sfruttabile confermata")
        
        print("\n" + "=" * 70)
        print(f"Target: {target}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)


# ==================== VULNERABILITY VERIFIERS ====================

class VulnerabilityVerifier:
    """Verifica se le vulnerabilità sono realmente sfruttabili"""
    
    def __init__(self, target: str, ip: str, output: OutputManager):
        self.target = target
        self.ip = ip
        self.output = output
    
    def verify_ftp_anonymous(self, port: int = 21) -> Tuple[bool, str]:
        """Verifica se FTP accetta accesso anonimo"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # Leggi banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Prova login anonimo
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "331" in response:  # Password required
                sock.send(b"PASS anonymous@test.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if "230" in response:  # Login successful
                    # Prova a listare directory
                    sock.send(b"PWD\r\n")
                    pwd_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.send(b"QUIT\r\n")
                    sock.close()
                    return True, f"Login anonimo riuscito! Directory: {pwd_response.strip()}"
            
            sock.send(b"QUIT\r\n")
            sock.close()
            return False, "Accesso anonimo negato"
            
        except Exception as e:
            return False, f"Connessione fallita: {str(e)[:50]}"
    
    def verify_mysql_access(self, port: int = 3306) -> Tuple[bool, str]:
        """Verifica se MySQL accetta connessioni e credenziali di default"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # Leggi handshake packet
            packet = sock.recv(1024)
            
            if len(packet) < 5:
                sock.close()
                return False, "Risposta non valida"
            
            # Analizza il pacchetto MySQL
            # Byte 4: protocol version, seguito da server version string
            if packet[4:5] == b'\xff':
                # Error packet
                error_msg = packet[7:].decode('utf-8', errors='ignore').split('\x00')[0]
                sock.close()
                return False, f"Accesso negato: {error_msg[:50]}"
            
            # Estrai versione server
            version_end = packet.find(b'\x00', 5)
            if version_end > 5:
                version = packet[5:version_end].decode('utf-8', errors='ignore')
                sock.close()
                
                # Se arriviamo qui, il server risponde ma dobbiamo verificare auth
                # Proviamo una connessione con credenziali vuote
                return self._try_mysql_auth(port)
            
            sock.close()
            return False, "Handshake non riconosciuto"
            
        except socket.timeout:
            return False, "Connessione timeout - probabilmente filtrato"
        except ConnectionRefusedError:
            return False, "Connessione rifiutata"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def _try_mysql_auth(self, port: int) -> Tuple[bool, str]:
        """Tenta autenticazione MySQL con credenziali comuni"""
        try:
            # Usa socket raw per test base
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT_FAST)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            
            if result == 0:
                # Porta aperta, ma verifichiamo se accetta connessioni remote
                # Controlliamo se c'è un firewall applicativo
                return False, "MySQL risponde ma richiede autenticazione (verifica manuale consigliata)"
            return False, "Porta filtrata"
        except:
            return False, "Test autenticazione fallito"
    
    def verify_postgres_access(self, port: int = 5432) -> Tuple[bool, str]:
        """Verifica se PostgreSQL accetta connessioni"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # Invia startup message PostgreSQL
            # Version 3.0 protocol
            user = b"postgres"
            database = b"postgres"
            
            # Costruisci startup packet
            params = b"user\x00" + user + b"\x00database\x00" + database + b"\x00\x00"
            length = 4 + 4 + len(params)  # length + protocol version + params
            packet = struct.pack(">I", length) + struct.pack(">I", 196608) + params  # 196608 = 3.0
            
            sock.send(packet)
            response = sock.recv(1024)
            
            sock.close()
            
            if len(response) > 0:
                # R = Authentication request
                if response[0:1] == b'R':
                    auth_type = struct.unpack(">I", response[5:9])[0] if len(response) >= 9 else -1
                    if auth_type == 0:
                        return True, "Autenticazione non richiesta! (trust auth)"
                    elif auth_type == 3:
                        return False, "Richiede password in chiaro"
                    elif auth_type == 5:
                        return False, "Richiede password MD5"
                    elif auth_type == 10:
                        return False, "Richiede SASL authentication"
                    else:
                        return False, f"Richiede autenticazione (tipo {auth_type})"
                # E = Error
                elif response[0:1] == b'E':
                    error_msg = response[5:].decode('utf-8', errors='ignore').split('\x00')[0]
                    return False, f"Errore: {error_msg[:50]}"
            
            return False, "Risposta non riconosciuta"
            
        except socket.timeout:
            return False, "Timeout - probabilmente filtrato"
        except ConnectionRefusedError:
            return False, "Connessione rifiutata"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_redis_access(self, port: int = 6379) -> Tuple[bool, str]:
        """Verifica se Redis è accessibile senza autenticazione"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # Invia comando INFO
            sock.send(b"INFO\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            sock.close()
            
            if "redis_version" in response:
                # Estrai versione
                version_match = re.search(r'redis_version:(\S+)', response)
                version = version_match.group(1) if version_match else "unknown"
                return True, f"Redis APERTO senza auth! Versione: {version}"
            elif "NOAUTH" in response or "Authentication required" in response:
                return False, "Richiede autenticazione"
            elif "-ERR" in response:
                return False, f"Errore: {response[:50]}"
            
            return False, "Risposta non riconosciuta"
            
        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_mongodb_access(self, port: int = 27017) -> Tuple[bool, str]:
        """Verifica se MongoDB è accessibile senza autenticazione"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # MongoDB wire protocol - isMaster command
            # Costruisci un messaggio OP_MSG semplificato
            message = (
                b'\x00\x00\x00\x00'  # requestID
                b'\x00\x00\x00\x00'  # responseTo
                b'\xdd\x07\x00\x00'  # opCode = OP_MSG (2013)
                b'\x00\x00\x00\x00'  # flagBits
                b'\x00'              # section kind 0
                # BSON document for {isMaster: 1}
                b'\x13\x00\x00\x00'  # document size
                b'\x10isMaster\x00\x01\x00\x00\x00'  # int32 isMaster = 1
                b'\x00'              # document terminator
            )
            
            # Aggiungi lunghezza totale all'inizio
            full_message = struct.pack("<I", len(message) + 4) + message
            
            sock.send(full_message)
            response = sock.recv(4096)
            
            sock.close()
            
            if len(response) > 0:
                # Cerca pattern nella risposta
                if b"ismaster" in response.lower() or b"maxBsonObjectSize" in response:
                    return True, "MongoDB APERTO! Risponde a comandi"
                elif b"auth" in response.lower():
                    return False, "Richiede autenticazione"
            
            return False, "Risposta non riconosciuta"
            
        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_smb_access(self, port: int = 445) -> Tuple[bool, str]:
        """Verifica se SMB permette sessioni anonime"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # SMB Negotiate Protocol Request (SMBv1)
            negotiate = bytes([
                0x00, 0x00, 0x00, 0x85,  # NetBIOS header
                0xFF, 0x53, 0x4D, 0x42,  # SMB header
                0x72,                     # Command: Negotiate Protocol
                0x00, 0x00, 0x00, 0x00,  # Status
                0x18,                     # Flags
                0x53, 0xC8,              # Flags2
                0x00, 0x00,              # PID High
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
                0x00, 0x00,              # Reserved
                0x00, 0x00,              # TID
                0x00, 0x00,              # PID
                0x00, 0x00,              # UID
                0x00, 0x00,              # MID
                # Negotiate request
                0x00,                     # Word count
                0x62, 0x00,              # Byte count
            ])
            
            # Dialects
            dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
            
            sock.send(negotiate + dialects)
            response = sock.recv(1024)
            
            sock.close()
            
            if len(response) > 4:
                # Verifica se è una risposta SMB valida
                if response[4:8] == b'\xFFSMB' or response[4:8] == b'\xFESMB':
                    # Controlla se accetta la negoziazione
                    if response[4:8] == b'\xFESMB':
                        return False, "SMBv2/3 attivo - verifica manuale necessaria"
                    else:
                        return False, "SMBv1 attivo - verifica manuale per null session"
            
            return False, "Risposta non riconosciuta"
            
        except socket.timeout:
            return False, "Timeout - probabilmente filtrato"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_telnet_access(self, port: int = 23) -> Tuple[bool, str]:
        """Verifica se Telnet è accessibile e risponde"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # Leggi banner/prompt
            sock.setblocking(0)
            import select
            ready = select.select([sock], [], [], Config.TIMEOUT)
            
            if ready[0]:
                banner = b""
                while True:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        banner += chunk
                    except:
                        break
                
                sock.close()
                
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                
                if banner_text:
                    # Cerca indicatori di login prompt
                    if any(x in banner_text.lower() for x in ["login:", "username:", "password:", "user:"]):
                        return True, f"Telnet ATTIVO con prompt login! Banner: {banner_text[:50]}"
                    else:
                        return True, f"Telnet ATTIVO! Banner: {banner_text[:50]}"
                else:
                    return True, "Telnet risponde ma nessun banner"
            
            sock.close()
            return False, "Nessuna risposta dal server"
            
        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_rdp_access(self, port: int = 3389) -> Tuple[bool, str]:
        """Verifica se RDP è accessibile"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            # X.224 Connection Request
            x224_conn_req = bytes([
                0x03, 0x00,              # TPKT Header
                0x00, 0x2b,              # Length (43 bytes)
                0x26,                     # X.224 length
                0xe0,                     # X.224 Type: Connection Request
                0x00, 0x00,              # DST-REF
                0x00, 0x00,              # SRC-REF
                0x00,                     # Class
            ])
            
            # Cookie
            cookie = b"Cookie: mstshash=test\r\n"
            
            # RDP Negotiation Request
            rdp_neg_req = bytes([
                0x01,                     # Type: RDP Negotiation Request
                0x00,                     # Flags
                0x08, 0x00,              # Length
                0x03, 0x00, 0x00, 0x00,  # Requested protocols (TLS + CredSSP)
            ])
            
            packet = x224_conn_req + cookie + rdp_neg_req
            # Aggiorna lunghezza
            packet = packet[:2] + struct.pack(">H", len(packet)) + packet[4:]
            
            sock.send(packet)
            response = sock.recv(1024)
            
            sock.close()
            
            if len(response) > 0:
                # Verifica risposta X.224
                if response[0] == 0x03:  # TPKT
                    if len(response) >= 11:
                        response_type = response[5]
                        if response_type == 0xd0:  # Connection Confirm
                            return True, "RDP ATTIVO e accessibile!"
                        elif response_type == 0xe0:
                            return False, "RDP rifiuta la connessione"
                
                return True, "RDP risponde (verifica NLA)"
            
            return False, "Nessuna risposta"
            
        except socket.timeout:
            return False, "Timeout - probabilmente filtrato"
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}"
    
    def verify_ssh_security(self, port: int = 22) -> Tuple[bool, str, dict]:
        """Verifica configurazione SSH e versione"""
        details = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(Config.TIMEOUT)
            sock.connect((self.ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            details["banner"] = banner
            
            # Analizza vulnerabilità
            issues = []
            
            if "SSH-1" in banner:
                issues.append("Protocollo SSH v1 (CRITICO)")
            
            # Verifica versione OpenSSH
            match = re.search(r'OpenSSH[_\s](\d+)\.(\d+)', banner)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                details["version"] = f"{major}.{minor}"
                
                if major < 7:
                    issues.append(f"OpenSSH {major}.{minor} obsoleto (multiple CVE)")
                elif major == 7 and minor < 4:
                    issues.append(f"OpenSSH {major}.{minor} vulnerabile a CVE-2016-10009")
                elif major < 8:
                    issues.append(f"OpenSSH {major}.{minor} datato")
            
            # Verifica software vulnerabile
            if "dropbear" in banner.lower():
                match = re.search(r'dropbear[_\s](\d+\.\d+)', banner.lower())
                if match:
                    version = float(match.group(1))
                    if version < 2020.80:
                        issues.append(f"Dropbear {version} vulnerabile")
            
            if issues:
                return True, "; ".join(issues), details
            else:
                return False, "SSH configurato correttamente", details
                
        except Exception as e:
            return False, f"Errore: {str(e)[:50]}", {}


# ==================== MAIN SCANNER ====================

class StealthScanner:
    """Scanner principale con verifica"""
    
    def __init__(self, target: str, output: OutputManager):
        self.target = target
        self.output = output
        self.ip = None
        self.open_ports = []
        self.services = {}
        self.verifier = None
    
    def resolve_target(self) -> bool:
        """Risolve il target in IP"""
        try:
            self.ip = socket.gethostbyname(self.target)
            self.output.add_info("DNS", "IP Risolto", self.ip)
            self.verifier = VulnerabilityVerifier(self.target, self.ip, self.output)
            return True
        except socket.gaierror:
            self.output.print_status(f"Impossibile risolvere {self.target}", "error")
            return False
    
    def scan_ports(self):
        """Scansione porte stealth"""
        self.output.print_status("Scansione porte in corso...", "info")
        
        def check_port(port_info):
            port, service = port_info
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.TIMEOUT_FAST)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                return port, service, result == 0
            except:
                return port, service, False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = {executor.submit(check_port, (p, s)): p for p, s in Config.COMMON_PORTS.items()}
            
            for future in concurrent.futures.as_completed(futures):
                port, service, is_open = future.result()
                if is_open:
                    self.open_ports.append(port)
                    self.services[port] = service
                    self.output.print_status(f"Porta {port}/{service} APERTA", "success")
        
        self.output.add_info("Scansione", "Porte Aperte", len(self.open_ports))
    
    def verify_vulnerabilities(self):
        """Verifica le vulnerabilità per ogni porta aperta"""
        self.output.print_status("Verifica vulnerabilità effettive...", "verify")
        
        for port in self.open_ports:
            service = self.services.get(port, "")
            
            if port == 21 or service == "FTP":
                self.output.print_status(f"Verifica FTP ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_ftp_anonymous(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "INFO",
                    f"FTP su porta {port}",
                    "Servizio FTP rilevato",
                    "Disabilitare FTP o usare SFTP",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 22 or service == "SSH":
                self.output.print_status(f"Verifica SSH ({port})...", "verify")
                vulnerable, evidence, details = self.verifier.verify_ssh_security(port)
                if vulnerable:
                    self.output.add_vulnerability(
                        "ALTA",
                        f"SSH Vulnerabile ({port})",
                        evidence,
                        "Aggiornare OpenSSH",
                        verified=True,
                        exploitable=True,
                        evidence=details.get("banner", "")[:50]
                    )
                else:
                    self.output.add_info("SSH", f"Porta {port}", details.get("banner", "")[:50])
            
            elif port == 23 or service == "Telnet":
                self.output.print_status(f"Verifica Telnet ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_telnet_access(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "ALTA",
                    f"Telnet su porta {port}",
                    "Protocollo Telnet non sicuro",
                    "Disabilitare Telnet, usare SSH",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 3306 or service == "MySQL":
                self.output.print_status(f"Verifica MySQL ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_mysql_access(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "MEDIA",
                    f"MySQL su porta {port}",
                    "Database MySQL accessibile",
                    "Limitare accesso remoto, usare firewall",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 5432 or service == "PostgreSQL":
                self.output.print_status(f"Verifica PostgreSQL ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_postgres_access(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "MEDIA",
                    f"PostgreSQL su porta {port}",
                    "Database PostgreSQL accessibile",
                    "Configurare pg_hba.conf, usare password forti",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 6379 or service == "Redis":
                self.output.print_status(f"Verifica Redis ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_redis_access(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "MEDIA",
                    f"Redis su porta {port}",
                    "Redis accessibile",
                    "Configurare requirepass, bind localhost",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 27017 or service == "MongoDB":
                self.output.print_status(f"Verifica MongoDB ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_mongodb_access(port)
                self.output.add_vulnerability(
                    "CRITICA" if exploitable else "MEDIA",
                    f"MongoDB su porta {port}",
                    "MongoDB accessibile",
                    "Abilitare autenticazione, bind localhost",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 445 or service == "SMB":
                self.output.print_status(f"Verifica SMB ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_smb_access(port)
                self.output.add_vulnerability(
                    "ALTA" if exploitable else "MEDIA",
                    f"SMB su porta {port}",
                    "Servizio SMB rilevato",
                    "Disabilitare SMBv1, verificare condivisioni",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )
            
            elif port == 3389 or service == "RDP":
                self.output.print_status(f"Verifica RDP ({port})...", "verify")
                exploitable, evidence = self.verifier.verify_rdp_access(port)
                self.output.add_vulnerability(
                    "ALTA" if exploitable else "MEDIA",
                    f"RDP su porta {port}",
                    "Remote Desktop accessibile",
                    "Usare VPN, abilitare NLA",
                    verified=True,
                    exploitable=exploitable,
                    evidence=evidence
                )


# ==================== WEB SCANNER ====================

class WebScanner:
    """Scanner per vulnerabilità web"""
    
    def __init__(self, target: str, output: OutputManager):
        self.target = target
        self.output = output
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.headers['User-Agent'] = Config.USER_AGENT
            self.session.verify = False
    
    def check_http(self, port: int = 80, https: bool = False):
        """Analizza servizio HTTP/HTTPS"""
        if not HAS_REQUESTS:
            return
        
        protocol = "https" if https else "http"
        base_url = f"{protocol}://{self.target}"
        if port not in [80, 443]:
            base_url += f":{port}"
        
        try:
            response = self.session.get(base_url, timeout=Config.TIMEOUT, allow_redirects=True)
            
            self.output.add_info("HTTP", "Status", response.status_code)
            
            # Rileva server
            server = response.headers.get('Server', 'N/A')
            self.output.add_info("HTTP", "Server", server)
            
            # Verifica headers di sicurezza
            self._check_security_headers(response.headers)
            
            # Rileva tecnologie
            self._detect_technologies(response)
            
        except requests.exceptions.SSLError as e:
            self.output.add_vulnerability(
                "MEDIA",
                "Problema Certificato SSL",
                f"Errore SSL: {str(e)[:50]}",
                "Verificare configurazione certificato"
            )
        except:
            pass
    
    def _check_security_headers(self, headers):
        """Verifica security headers"""
        security_headers = {
            "Strict-Transport-Security": ("HSTS Mancante", "MEDIA"),
            "X-Content-Type-Options": ("X-Content-Type-Options Mancante", "BASSA"),
            "X-Frame-Options": ("X-Frame-Options Mancante", "MEDIA"),
            "Content-Security-Policy": ("CSP Mancante", "MEDIA"),
        }
        
        for header, (title, severity) in security_headers.items():
            if header not in headers:
                self.output.add_vulnerability(
                    severity,
                    title,
                    f"Header {header} non presente",
                    f"Aggiungere header {header}"
                )
            else:
                self.output.add_info("Security", header, "Presente ✓")
    
    def _detect_technologies(self, response):
        """Rileva tecnologie dal response"""
        text = response.text[:5000] if response.text else ""
        headers = response.headers
        
        # Rileva CMS/Framework
        if "wp-content" in text or "wp-includes" in text:
            self.output.add_info("Tech", "CMS", "WordPress")
        elif "Joomla" in text:
            self.output.add_info("Tech", "CMS", "Joomla")
        elif "Drupal" in text:
            self.output.add_info("Tech", "CMS", "Drupal")
        
        # Rileva framework
        if "X-Powered-By" in headers:
            self.output.add_info("Tech", "Powered By", headers["X-Powered-By"])
    
    def check_ssl(self, port: int = 443):
        """Verifica configurazione SSL/TLS"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=Config.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    self.output.add_info("SSL/TLS", "Protocollo", version)
                    self.output.add_info("SSL/TLS", "Cipher", cipher[0] if cipher else "N/A")
                    
                    if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"]:
                        self.output.add_vulnerability(
                            "ALTA",
                            f"Protocollo {version} Deprecato",
                            "Protocollo SSL/TLS obsoleto",
                            "Usare TLSv1.2 o superiore",
                            verified=True,
                            exploitable=True,
                            evidence=version
                        )
                    elif version == "TLSv1.1":
                        self.output.add_vulnerability(
                            "MEDIA",
                            "TLSv1.1 Deprecato",
                            "TLSv1.1 è deprecato",
                            "Aggiornare a TLSv1.2+",
                            verified=True,
                            exploitable=True,
                            evidence=version
                        )
        except:
            pass
    
    def check_sensitive_files(self):
        """Verifica file sensibili esposti"""
        if not HAS_REQUESTS:
            return
        
        sensitive = [
            ("/.git/config", "Git Repository Esposto", "CRITICA"),
            ("/.env", "File .env Esposto", "CRITICA"),
            ("/phpinfo.php", "PHPInfo Esposto", "ALTA"),
            ("/.htaccess", ".htaccess Accessibile", "MEDIA"),
            ("/wp-config.php.bak", "Backup WordPress", "CRITICA"),
            ("/server-status", "Apache Status", "MEDIA"),
            ("/.svn/entries", "SVN Esposto", "ALTA"),
            ("/backup.sql", "Backup SQL Esposto", "CRITICA"),
            ("/dump.sql", "Dump SQL Esposto", "CRITICA"),
        ]
        
        for path, title, severity in sensitive:
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{self.target}{path}"
                    response = self.session.get(url, timeout=Config.TIMEOUT_FAST, allow_redirects=False)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        # Verifica che non sia una pagina di errore personalizzata
                        if "404" not in response.text[:200].lower() and "not found" not in response.text[:200].lower():
                            self.output.add_vulnerability(
                                severity,
                                title,
                                f"File sensibile accessibile: {path}",
                                "Rimuovere o proteggere il file",
                                verified=True,
                                exploitable=True,
                                evidence=f"HTTP 200 - {len(response.content)} bytes"
                            )
                            break
                except:
                    pass


# ==================== ATTACK ANALYZER ====================

def get_possible_attacks(vulnerabilities: list) -> dict:
    """Determina gli attacchi distruttivi (3) e probabili (5) basati sulle vulnerabilità"""
    destructive = []
    probable = []
    severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3, "INFO": 4}
    detected_vuln_keys = set()
    
    for vuln in vulnerabilities:
        title_lower = vuln.get("title", "").lower()
        cve_key = None
        
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
                attack_info["vuln_severity"] = vuln.get("severity", "MEDIA")
                destructive.append(attack_info)
            
            # Attacchi dal database legacy
            if cve_key in Config.ATTACK_DATABASE:
                attack_info = Config.ATTACK_DATABASE[cve_key].copy()
                attack_info["vuln_key"] = cve_key
                attack_info["vuln_severity"] = vuln.get("severity", "MEDIA")
                if attack_info.get("category") != "DISTRUTTIVO":
                    probable.append(attack_info)
    
    # Aggiungi attacchi probabili basati sulle vulnerabilità
    for attack_key, attack_info in Config.PROBABLE_ATTACKS.items():
        triggered_by = attack_info.get("triggered_by", [])
        if any(t in detected_vuln_keys for t in triggered_by):
            attack_copy = attack_info.copy()
            attack_copy["vuln_key"] = attack_key
            attack_copy["vuln_severity"] = "ALTA"
            probable.append(attack_copy)
    
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


def display_attacks(attacks: dict, console=None):
    """Visualizza gli attacchi distruttivi e probabili"""
    if isinstance(attacks, list):
        # Retrocompatibilità
        attacks = {"destructive": attacks[:3], "probable": attacks[3:8]}
    
    destructive = attacks.get("destructive", [])
    probable = attacks.get("probable", [])
    total = len(destructive) + len(probable)
    
    if total == 0:
        if console:
            console.print("\n[green]✅ Nessun attacco identificato[/green]")
        else:
            print("\n✅ Nessun attacco identificato")
        return
    
    severity_colors = {"CRITICA": "red", "ALTA": "orange3", "MEDIA": "yellow", "BASSA": "green"}
    
    if HAS_RICH and console:
        # Attacchi distruttivi
        if destructive:
            console.print()
            console.print(f"[bold red]💀 {len(destructive)} ATTACCHI DISTRUTTIVI (Compromissione Totale)[/bold red]")
            for i, attack in enumerate(destructive, 1):
                color = severity_colors.get(attack.get("severity", "MEDIA"), "white")
                console.print(f"\n[bold {color}]💀 #{i} {attack['name']}[/bold {color}] [{color}][{attack.get('severity')}][/{color}]")
                console.print(f"   [cyan]Tipo:[/cyan] {attack.get('type')}")
                console.print(f"   {attack.get('description')}")
                console.print(f"   [yellow]🔧 Tools:[/yellow] {attack.get('tools')}")
                console.print(f"   [red]💥 Impatto:[/red] {attack.get('impact')}")
                if attack.get('time_to_exploit'):
                    console.print(f"   [magenta]⏱️ Tempo:[/magenta] {attack.get('time_to_exploit')}")
        
        # Attacchi probabili
        if probable:
            console.print()
            console.print(f"[bold yellow]🎯 {len(probable)} ATTACCHI PROBABILI (Backdoor & Persistenza)[/bold yellow]")
            for i, attack in enumerate(probable, 1):
                color = severity_colors.get(attack.get("severity", "MEDIA"), "white")
                console.print(f"\n[bold {color}]🎯 #{i} {attack['name']}[/bold {color}] [{color}][{attack.get('severity')}][/{color}]")
                console.print(f"   [cyan]Tipo:[/cyan] {attack.get('type')}")
                console.print(f"   {attack.get('description')}")
                console.print(f"   [yellow]🔧 Tools:[/yellow] {attack.get('tools')}")
                console.print(f"   [red]💥 Impatto:[/red] {attack.get('impact')}")
    else:
        if destructive:
            print("\n" + "=" * 70)
            print(f"💀 {len(destructive)} ATTACCHI DISTRUTTIVI")
            print("=" * 70)
            for i, attack in enumerate(destructive, 1):
                print(f"\n[{attack.get('severity')}] #{i} {attack['name']}")
                print(f"   Tipo: {attack.get('type')}")
                print(f"   {attack.get('description')}")
                print(f"   Tools: {attack.get('tools')}")
                print(f"   Impatto: {attack.get('impact')}")
        
        if probable:
            print("\n" + "=" * 70)
            print(f"🎯 {len(probable)} ATTACCHI PROBABILI")
            print("=" * 70)
            for i, attack in enumerate(probable, 1):
                print(f"\n[{attack.get('severity')}] #{i} {attack['name']}")
                print(f"   Tipo: {attack.get('type')}")
                print(f"   {attack.get('description')}")
                print(f"   Tools: {attack.get('tools')}")
                print(f"   Impatto: {attack.get('impact')}")


def display_ai_analysis(analysis: dict, console=None):
    """Visualizza l'analisi AI di Gemini"""
    if "error" in analysis:
        if console:
            console.print(f"\n[red]❌ Errore AI: {analysis['error']}[/red]")
        else:
            print(f"\n❌ Errore AI: {analysis['error']}")
        return
    
    if HAS_RICH and console:
        from rich.panel import Panel
        from rich import box
        
        risk_colors = {"CRITICO": "red", "ALTO": "orange3", "MEDIO": "yellow", "BASSO": "green"}
        risk_level = analysis.get("risk_level", "SCONOSCIUTO")
        risk_color = risk_colors.get(risk_level, "white")
        
        ai_text = f"""[bold {risk_color}]🤖 ANALISI AI - GEMINI[/bold {risk_color}]

[bold]Risk Score:[/bold] [{risk_color}]{analysis.get('risk_score', 'N/A')}/10[/{risk_color}]
[bold]Livello:[/bold] [{risk_color}]{risk_level}[/{risk_color}]
[bold]Tempo Compromissione:[/bold] {analysis.get('time_to_compromise', 'N/A')}

[bold cyan]Executive Summary:[/bold cyan]
{analysis.get('executive_summary', 'N/A')}

[bold yellow]Scenario Più Probabile:[/bold yellow]
{analysis.get('most_likely_scenario', 'N/A')}

[bold red]Impatto Business:[/bold red]
{analysis.get('business_impact', 'N/A')}"""
        
        console.print(Panel(ai_text, border_style=risk_color, box=box.ROUNDED))
        
        # Attack chain
        attack_chain = analysis.get("attack_chain", [])
        if attack_chain:
            console.print("\n[bold magenta]⛓️ Attack Chain:[/bold magenta]")
            for step in attack_chain:
                console.print(f"   [cyan]Step {step.get('step')}:[/cyan] {step.get('action')} [dim]({step.get('tool')})[/dim]")
        
        # Priority actions
        priority_actions = analysis.get("priority_actions", [])
        if priority_actions:
            console.print("\n[bold green]✅ Azioni Prioritarie:[/bold green]")
            for action in priority_actions:
                console.print(f"   → {action}")
    else:
        print("\n" + "=" * 70)
        print("🤖 ANALISI AI - GEMINI")
        print("=" * 70)
        print(f"Risk Score: {analysis.get('risk_score', 'N/A')}/10")
        print(f"Livello: {analysis.get('risk_level', 'N/A')}")
        print(f"\nSommario: {analysis.get('executive_summary', 'N/A')}")
        print(f"\nScenario: {analysis.get('most_likely_scenario', 'N/A')}")
        
        attack_chain = analysis.get("attack_chain", [])
        if attack_chain:
            print("\nAttack Chain:")
            for step in attack_chain:
                print(f"   Step {step.get('step')}: {step.get('action')} ({step.get('tool')})")
        
        priority_actions = analysis.get("priority_actions", [])
        if priority_actions:
            print("\nAzioni Prioritarie:")
            for action in priority_actions:
                print(f"   → {action}")


def display_geolocation(geo_info: GeoHostingInfo, console=None):
    """Visualizza le informazioni di geolocalizzazione"""
    if HAS_RICH and console:
        from rich.panel import Panel
        from rich import box
        
        geo_text = f"""[bold cyan]🌍 Geolocalizzazione[/bold cyan]
  Paese: {geo_info.country} ({geo_info.country_code})
  Regione: {geo_info.region_name}
  Città: {geo_info.city}
  Coordinate: {geo_info.latitude}, {geo_info.longitude}
  Timezone: {geo_info.timezone}

[bold cyan]📡 Informazioni Rete[/bold cyan]
  ISP: {geo_info.isp}
  Organizzazione: {geo_info.organization}
  ASN: {geo_info.asn} ({geo_info.asn_name})
  Reverse DNS: {geo_info.reverse_dns}

[bold cyan]🏢 Hosting[/bold cyan]
  È Hosting: {"[green]✓ Sì[/green]" if geo_info.is_hosting else "[red]✗ No[/red]"}
  È Proxy: {"[yellow]✓ Sì[/yellow]" if geo_info.is_proxy else "[green]✗ No[/green]"}
  Provider: {geo_info.hosting_provider or "N/A"}
  Datacenter: {geo_info.datacenter or "N/A"}"""
        
        console.print(Panel(geo_text, title="[bold white]Informazioni Target[/bold white]", border_style="blue", box=box.ROUNDED))
    else:
        print("\n" + "=" * 70)
        print("GEOLOCALIZZAZIONE E HOSTING")
        print("=" * 70)
        print(f"  Paese: {geo_info.country} ({geo_info.country_code})")
        print(f"  Città: {geo_info.city}")
        print(f"  ISP: {geo_info.isp}")
        print(f"  ASN: {geo_info.asn}")
        print(f"  È Hosting: {'Sì' if geo_info.is_hosting else 'No'}")
        if geo_info.hosting_provider:
            print(f"  Provider: {geo_info.hosting_provider}")


def generate_html_report(data: dict) -> str:
    """Genera un report HTML professionale"""
    timestamp = data.get("scan_date", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    target = data.get("target", "N/A")
    ip = data.get("ip", "N/A")
    
    vulns = data.get("vulnerabilities", [])
    vuln_counts = {
        "CRITICA": len([v for v in vulns if v.get("severity") == "CRITICA"]),
        "ALTA": len([v for v in vulns if v.get("severity") == "ALTA"]),
        "MEDIA": len([v for v in vulns if v.get("severity") == "MEDIA"]),
        "BASSA": len([v for v in vulns if v.get("severity") == "BASSA"])
    }
    
    if vuln_counts["CRITICA"] > 0:
        risk_level, risk_color = "CRITICO", "#FF3B3B"
    elif vuln_counts["ALTA"] > 0:
        risk_level, risk_color = "ALTO", "#FF8C00"
    elif vuln_counts["MEDIA"] > 0:
        risk_level, risk_color = "MEDIO", "#FFB800"
    else:
        risk_level, risk_color = "BASSO", "#00D26A"
    
    geo = data.get("geolocation", {})
    hosting = data.get("hosting", {})
    attacks = data.get("possible_attacks", [])
    
    html = f'''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Vulnerabilità - {target}</title>
    <style>
        :root {{ --bg: #0f0f23; --card: #1a1a2e; --text: #fff; --muted: #888; }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 16px; padding: 40px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .risk-badge {{ background: {risk_color}; color: #000; padding: 15px 30px; border-radius: 12px; font-weight: bold; display: inline-block; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat {{ background: var(--card); padding: 20px; border-radius: 12px; text-align: center; }}
        .stat-num {{ font-size: 2em; font-weight: bold; }}
        .section {{ background: var(--card); border-radius: 12px; padding: 25px; margin-bottom: 20px; }}
        .section h2 {{ color: #0EA5E9; margin-bottom: 20px; }}
        .vuln-card {{ background: #2D2D3D; border-left: 4px solid; padding: 15px; margin-bottom: 10px; border-radius: 8px; }}
        .severity-CRITICA {{ border-color: #FF3B3B; }} .severity-ALTA {{ border-color: #FF8C00; }}
        .severity-MEDIA {{ border-color: #FFB800; }} .severity-BASSA {{ border-color: #00D26A; }}
        .attack-card {{ background: #2D2D3D; border-left: 4px solid #FF3B3B; padding: 15px; margin-bottom: 10px; border-radius: 8px; }}
        .footer {{ text-align: center; padding: 30px; color: var(--muted); }}
        table {{ width: 100%; border-collapse: collapse; }} th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐧 Stealth Vulnerability Scanner</h1>
            <p style="color: #888;">Red-Penguin | v{Config.VERSION} | {timestamp}</p>
            <div style="margin-top: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div><strong>Target:</strong> {target}<br><strong>IP:</strong> {ip}</div>
                <div class="risk-badge">RISCHIO: {risk_level}</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat"><div class="stat-num" style="color:#0EA5E9">{len(data.get("open_ports", []))}</div>Porte Aperte</div>
            <div class="stat"><div class="stat-num" style="color:#FF3B3B">{vuln_counts["CRITICA"]}</div>Critiche</div>
            <div class="stat"><div class="stat-num" style="color:#FF8C00">{vuln_counts["ALTA"]}</div>Alte</div>
            <div class="stat"><div class="stat-num" style="color:#FFB800">{vuln_counts["MEDIA"]}</div>Medie</div>
            <div class="stat"><div class="stat-num" style="color:#00D26A">{vuln_counts["BASSA"]}</div>Basse</div>
        </div>'''
    
    # Geolocation
    if geo:
        html += f'''
        <div class="section">
            <h2>🌍 Geolocalizzazione & Hosting</h2>
            <table>
                <tr><td><strong>Paese</strong></td><td>{geo.get("country", "N/A")} ({geo.get("country_code", "")})</td></tr>
                <tr><td><strong>Città</strong></td><td>{geo.get("city", "N/A")}</td></tr>
                <tr><td><strong>ISP</strong></td><td>{data.get("network_info", {}).get("isp", "N/A")}</td></tr>
                <tr><td><strong>È Hosting</strong></td><td>{"✅ Sì" if hosting.get("is_hosting") else "❌ No"}</td></tr>
                <tr><td><strong>Provider</strong></td><td>{hosting.get("provider", "N/A")}</td></tr>
            </table>
        </div>'''
    
    # Vulnerabilità
    if vulns:
        html += '''
        <div class="section">
            <h2>⚠️ Vulnerabilità Rilevate</h2>'''
        for vuln in sorted(vulns, key=lambda x: {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3}.get(x.get("severity", ""), 4)):
            html += f'''
            <div class="vuln-card severity-{vuln.get("severity", "")}">
                <strong>[{vuln.get("severity", "")}] {vuln.get("title", "")}</strong>
                <p style="color:#888; margin: 5px 0;">{vuln.get("description", "")}</p>
                <p style="color:#60A5FA;">→ Rimedio: {vuln.get("remediation", "")}</p>
            </div>'''
        html += '</div>'
    
    # Attacchi
    if attacks:
        html += '''
        <div class="section">
            <h2>🎯 Attacchi Possibili</h2>
            <p style="color:#FF6B6B; margin-bottom: 15px;">⚠️ Il server potrebbe essere soggetto ai seguenti attacchi:</p>'''
        for i, attack in enumerate(attacks[:3], 1):
            html += f'''
            <div class="attack-card">
                <strong>#{i} {attack.get("name", "")}</strong> <span style="color:#FF8C00">[{attack.get("severity", "")}]</span>
                <p style="color:#60A5FA; margin: 5px 0;">Tipo: {attack.get("type", "")}</p>
                <p style="color:#888;">{attack.get("description", "")}</p>
                <p style="color:#FFB800;">🔧 Tools: {attack.get("tools", "")}</p>
                <p style="color:#FF6B6B;">💥 Impatto: {attack.get("impact", "")}</p>
            </div>'''
        html += '</div>'
    
    html += f'''
        <div class="footer">
            <p>🐧 Stealth Vulnerability Scanner v{Config.VERSION} | Red-Penguin</p>
        </div>
    </div>
</body>
</html>'''
    
    return html


def generate_txt_report(data: dict) -> str:
    """Genera un report TXT formattato"""
    lines = []
    lines.append("=" * 70)
    lines.append("           STEALTH VULNERABILITY SCANNER - REPORT")
    lines.append("                    Red-Penguin v" + Config.VERSION)
    lines.append("=" * 70)
    lines.append("")
    
    lines.append("-" * 70)
    lines.append("  INFORMAZIONI SCANSIONE")
    lines.append("-" * 70)
    lines.append(f"  Target: {data.get('target', 'N/A')}")
    lines.append(f"  IP: {data.get('ip', 'N/A')}")
    lines.append(f"  Data: {data.get('scan_date', 'N/A')}")
    
    # Geolocalizzazione
    geo = data.get("geolocation", {})
    if geo:
        lines.append("")
        lines.append("-" * 70)
        lines.append("  GEOLOCALIZZAZIONE")
        lines.append("-" * 70)
        lines.append(f"  Paese: {geo.get('country', 'N/A')} ({geo.get('country_code', '')})")
        lines.append(f"  Città: {geo.get('city', 'N/A')}")
        lines.append(f"  ISP: {data.get('network_info', {}).get('isp', 'N/A')}")
        lines.append(f"  È Hosting: {'Sì' if data.get('hosting', {}).get('is_hosting') else 'No'}")
        if data.get('hosting', {}).get('provider'):
            lines.append(f"  Provider: {data.get('hosting', {}).get('provider')}")
    
    # Porte
    ports = data.get("open_ports", [])
    if ports:
        lines.append("")
        lines.append("-" * 70)
        lines.append("  PORTE APERTE")
        lines.append("-" * 70)
        for port in ports:
            if isinstance(port, dict):
                lines.append(f"    [+] Porta {port.get('port', '')} - {port.get('service', '')}")
            else:
                lines.append(f"    [+] Porta {port}")
    
    # Vulnerabilità
    vulns = data.get("vulnerabilities", [])
    if vulns:
        lines.append("")
        lines.append("-" * 70)
        lines.append("  VULNERABILITÀ RILEVATE")
        lines.append("-" * 70)
        for vuln in vulns:
            lines.append(f"\n  [{vuln.get('severity', '')}] {vuln.get('title', '')}")
            lines.append(f"    {vuln.get('description', '')}")
            lines.append(f"    Rimedio: {vuln.get('remediation', '')}")
    
    # Attacchi
    attacks = data.get("possible_attacks", [])
    if attacks:
        lines.append("")
        lines.append("-" * 70)
        lines.append("  ATTACCHI POSSIBILI")
        lines.append("-" * 70)
        lines.append("")
        lines.append("  ⚠️ Il server potrebbe essere soggetto ai seguenti attacchi:")
        for i, attack in enumerate(attacks[:3], 1):
            lines.append(f"\n  [{attack.get('severity', '')}] ATTACCO #{i}: {attack.get('name', '')}")
            lines.append(f"    Tipo: {attack.get('type', '')}")
            lines.append(f"    {attack.get('description', '')}")
            lines.append(f"    Tools: {attack.get('tools', '')}")
            lines.append(f"    Impatto: {attack.get('impact', '')}")
    
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Report generato: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append("=" * 70)
    
    return '\n'.join(lines)


# ==================== MAIN ====================

def main():
    parser = argparse.ArgumentParser(
        description="Stealth Vulnerability Scanner v3.1 - Con AI, Geolocalizzazione e Analisi Attacchi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  %(prog)s example.com
  %(prog)s 192.168.1.1 --geo --attacks
  %(prog)s example.com --ai                   # Con analisi AI Gemini
  %(prog)s example.com -o report.json --html --txt
  %(prog)s example.com --all                  # Tutto + AI
  %(prog)s example.com --no-web --no-verify
  %(prog)s example.com --skip-network-check
        """
    )
    parser.add_argument("target", help="IP o dominio da analizzare")
    parser.add_argument("-o", "--output", help="Salva report JSON (o specifica nome base)")
    parser.add_argument("--html", action="store_true", help="Genera report HTML")
    parser.add_argument("--txt", action="store_true", help="Genera report TXT")
    parser.add_argument("--all", action="store_true", help="Genera tutti i formati + geo + attacchi + AI")
    parser.add_argument("--geo", action="store_true", help="Abilita geolocalizzazione")
    parser.add_argument("--attacks", action="store_true", help="Mostra attacchi possibili (distruttivi + probabili)")
    parser.add_argument("--ai", action="store_true", help="Esegui analisi AI con Gemini (richiede config.ini)")
    parser.add_argument("--no-web", action="store_true", help="Salta analisi web")
    parser.add_argument("--no-verify", action="store_true", help="Salta verifica vulnerabilità")
    parser.add_argument("--ports-only", action="store_true", help="Solo scansione porte")
    parser.add_argument("--skip-network-check", action="store_true", help="Salta verifica stato rete")
    
    args = parser.parse_args()
    
    # Pulisci target
    target = args.target.strip()
    if target.startswith(("http://", "https://")):
        target = urlparse(target).netloc
    
    # Inizializza output
    output = OutputManager()
    output.print_banner()
    
    # Verifica stato rete all'avvio
    if not args.skip_network_check:
        output.print_status("Verifica configurazione rete...", "info")
        network_checker = NetworkStatusChecker()
        network_checker.check_all()
        network_checker.display_status()
    
    output.print_status(f"Target: {target}", "info")
    output.print_status("Modalità: Stealth con Verifica Effettiva", "info")
    print()
    
    # Scanner principale
    scanner = StealthScanner(target, output)
    
    if not scanner.resolve_target():
        sys.exit(1)
    
    # Geolocalizzazione
    geo_info = None
    if args.geo or args.all:
        output.print_status("Recupero informazioni geolocalizzazione...", "info")
        geo_info = GeoHostingInfo.fetch(scanner.ip)
        display_geolocation(geo_info, output.console if HAS_RICH else None)
    
    # Scansione porte
    scanner.scan_ports()
    
    if not scanner.open_ports:
        output.print_status("Nessuna porta aperta trovata", "warning")
    else:
        if not args.ports_only and not args.no_verify:
            scanner.verify_vulnerabilities()
        
        # Analisi web
        if not args.no_web and HAS_REQUESTS:
            web_scanner = WebScanner(target, output)
            
            if 80 in scanner.open_ports or 8080 in scanner.open_ports:
                output.print_status("Analisi HTTP...", "info")
                port = 80 if 80 in scanner.open_ports else 8080
                web_scanner.check_http(port, https=False)
            
            if 443 in scanner.open_ports or 8443 in scanner.open_ports:
                output.print_status("Analisi HTTPS/SSL...", "info")
                port = 443 if 443 in scanner.open_ports else 8443
                web_scanner.check_http(port, https=True)
                web_scanner.check_ssl(port)
            
            output.print_status("Verifica file sensibili...", "info")
            web_scanner.check_sensitive_files()
    
    # Mostra risultati
    print()
    output.print_results(target)
    
    # Calcola attacchi possibili (ora ritorna un dict con destructive e probable)
    possible_attacks = {"destructive": [], "probable": []}
    if args.attacks or args.all:
        possible_attacks = get_possible_attacks(output.vulnerabilities)
        display_attacks(possible_attacks, output.console if HAS_RICH else None)
    
    # Analisi AI con Gemini
    ai_analysis = None
    if args.ai or args.all:
        output.print_status("🤖 Avvio analisi AI con Gemini...", "info")
        analyzer = GeminiAnalyzer()
        if analyzer.is_configured:
            # Prepara dati per AI
            ai_data = {
                "target": target,
                "ip": scanner.ip,
                "open_ports": [{"port": p, "service": scanner.services.get(p, "Unknown")} for p in scanner.open_ports],
                "vulnerabilities": output.vulnerabilities,
                "geolocation": geo_info.to_dict().get("geolocation", {}) if geo_info else {},
                "hosting": geo_info.to_dict().get("hosting", {}) if geo_info else {}
            }
            ai_analysis = analyzer.analyze(ai_data)
            display_ai_analysis(ai_analysis, output.console if HAS_RICH else None)
        else:
            output.print_status("⚠️ API key Gemini non configurata. Modifica config.ini", "warning")
    
    # Prepara dati report
    report = {
        "target": target,
        "ip": scanner.ip,
        "scan_timestamp": datetime.now().isoformat(),
        "scan_date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "scanner_version": Config.VERSION,
        "open_ports": [{"port": p, "service": scanner.services.get(p, "Unknown")} for p in scanner.open_ports],
        "vulnerabilities": output.vulnerabilities,
        "attacks": {
            "destructive": possible_attacks.get("destructive", []),
            "probable": possible_attacks.get("probable", [])
        },
        "possible_attacks": possible_attacks.get("destructive", []) + possible_attacks.get("probable", []),  # Retrocompatibilità
        "geolocation": geo_info.to_dict().get("geolocation", {}) if geo_info else {},
        "network_info": geo_info.to_dict().get("network", {}) if geo_info else {},
        "hosting": geo_info.to_dict().get("hosting", {}) if geo_info else {},
        "ai_analysis": ai_analysis,
        "info": output.info
    }
    
    # Cartella output
    script_dir = Path(__file__).parent.resolve()
    output_folder = script_dir / Config.OUTPUT_FOLDER
    output_folder.mkdir(parents=True, exist_ok=True)
    
    safe_target = re.sub(r'[^\w\-.]', '_', target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{safe_target}_{timestamp}"
    
    # Salva JSON
    if args.output or args.all:
        json_file = output_folder / f"{base_name}.json" if args.all else Path(args.output)
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        output.print_status(f"JSON salvato: {json_file}", "success")
    
    # Salva HTML
    if args.html or args.all:
        html_file = output_folder / f"{base_name}.html"
        html_content = generate_html_report(report)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        output.print_status(f"HTML salvato: {html_file}", "success")
    
    # Salva TXT
    if args.txt or args.all:
        txt_file = output_folder / f"{base_name}.txt"
        txt_content = generate_txt_report(report)
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(txt_content)
        output.print_status(f"TXT salvato: {txt_file}", "success")


if __name__ == "__main__":
    main()
