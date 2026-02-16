# 🐧 Stealth Vulnerability Scanner v3.2

Scanner di vulnerabilità stealth con GUI e CLI, integrazione AI Gemini, rilevamento hosting, geolocalizzazione e analisi attacchi.

![Version](https://img.shields.io/badge/version-3.2-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![AI](https://img.shields.io/badge/AI-Gemini-purple)

---

## ✨ Novità v3.2

- 🔧 **Fix Export TXT** - Corretto errore di esportazione report TXT
- 📊 **Report HTML Completo** - Ora mostra sia attacchi distruttivi che probabili separatamente
- 🛡️ **Gestione Errori AI Migliorata** - Messaggi di errore più chiari per problemi API
- ✅ **Verifica Moduli AI** - Disabilita automaticamente AI se moduli non disponibili
- 🔍 **Diagnosi Errori 403** - Messaggio specifico per API key non valide

---

## ✨ Novità v3.1

- 🤖 **Integrazione AI Gemini** - Analisi avanzata con Google Gemini AI
- 💀 **3 Attacchi Distruttivi** - RCE, Ransomware, compromissione totale
- 🎯 **5 Attacchi Probabili** - Backdoor, persistenza, credential harvesting
- 📁 **File config.ini** - Configurazione API key e modello Gemini
- ⏱️ **Tempo di exploit** - Stima del tempo necessario per ogni attacco

---

## 📋 Caratteristiche

### Scansione
- 🔍 **Port Scanning** - Scansione delle 21 porte più comuni
- 🛡️ **Vulnerability Detection** - Rilevamento automatico vulnerabilità con CVE/CWE
- ✅ **Verifica Effettiva** - Distingue tra "porta aperta" e "realmente compromettibile"
- 🌐 **Web Analysis** - Analisi header di sicurezza (HSTS, CSP, X-Frame-Options)
- 📂 **Sensitive Files** - Ricerca file sensibili esposti (.git, .env, backup, ecc.)
- 🔒 **SSL/TLS Analysis** - Verifica certificati e protocolli

### Analisi Attacchi
- 💀 **3 Attacchi Distruttivi** - EternalBlue, BlueKeep, Redis RCE, MongoDB Ransomware
- 🎯 **5 Attacchi Probabili** - SSH Key Injection, Webshell, Reverse Shell, Credential Harvesting
- ⏱️ **Tempo di Exploit** - Stima del tempo necessario per compromettere

### 🤖 Analisi AI Gemini
- 📊 **Risk Score** - Punteggio di rischio da 1 a 10
- ⛓️ **Attack Chain** - Sequenza di attacco più probabile
- ✅ **Priority Actions** - Azioni prioritarie di remediation

---

## 🔑 Configurazione AI (Gemini)

1. Ottieni una API key gratuita da https://aistudio.google.com/app/apikey
2. Modifica il file config.ini:

\`\`\`ini
[GEMINI]
api_key = LA_TUA_API_KEY_QUI
model = gemini-2.0-flash-exp
\`\`\`

### Risoluzione Problemi AI

**Errore 403 Forbidden**: L'API key non è valida o non è abilitata per Gemini API.
- Verifica di aver creato la key su https://aistudio.google.com/app/apikey
- Assicurati che la key sia abilitata per "Gemini API"

**Errore 429 Rate Limit**: Hai superato il limite di richieste. Attendi qualche minuto.

**AI Disabilitata**: Se vedi "🤖 AI (config.ini)" significa che la key non è configurata.

---

## 🚀 Installazione

\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 stealth_scanner_gui.py
\`\`\`

---

## 👨‍💻 Autore

**Red-Penguin**

## ⚠️ Disclaimer

Questo strumento è destinato esclusivamente a scopi educativi e di sicurezza autorizzata.
