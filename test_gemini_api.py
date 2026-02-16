#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEST DIAGNOSTICO API GEMINI
Esegui questo script per verificare la tua API key e i modelli disponibili.

Uso: python3 test_gemini_api.py
"""

import sys

try:
    import requests
except ImportError:
    print("❌ Modulo 'requests' non installato!")
    print("   Esegui: pip install requests")
    sys.exit(1)

import json
import configparser
from pathlib import Path

def load_api_key():
    """Carica API key da config.ini"""
    config_path = Path(__file__).parent / "config.ini"
    if not config_path.exists():
        return None, None
    
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')
    
    try:
        api_key = config.get("GEMINI", "api_key", fallback="")
        model = config.get("GEMINI", "model", fallback="gemini-1.5-flash")
        if api_key.startswith("YOUR_") or not api_key:
            return None, model
        return api_key, model
    except:
        return None, None

def test_list_models(api_key):
    """Elenca i modelli disponibili"""
    print("\n" + "=" * 60)
    print("TEST 1: Lista modelli disponibili")
    print("=" * 60)
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    
    try:
        resp = requests.get(url, timeout=15)
        print(f"Status HTTP: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("models", [])
            print(f"✅ {len(models)} modelli disponibili:\n")
            
            gemini_models = []
            for m in models:
                name = m.get("name", "").replace("models/", "")
                if "gemini" in name.lower():
                    gemini_models.append(name)
                    methods = m.get("supportedGenerationMethods", [])
                    print(f"   📦 {name}")
                    print(f"      Metodi: {', '.join(methods)}")
            
            return gemini_models
            
        elif resp.status_code == 400:
            print("❌ Errore 400: Richiesta malformata")
            print(f"   Dettagli: {resp.text[:200]}")
        elif resp.status_code == 403:
            print("❌ Errore 403: Accesso negato")
            try:
                err = resp.json()
                msg = err.get("error", {}).get("message", "")
                status = err.get("error", {}).get("status", "")
                print(f"   Status: {status}")
                print(f"   Messaggio: {msg}")
            except:
                print(f"   Risposta: {resp.text[:300]}")
            print("\n⚠️  POSSIBILI CAUSE:")
            print("   1. API key non valida o scaduta")
            print("   2. API key non abilitata per Gemini API")
            print("   3. Restrizioni geografiche (prova con VPN)")
            print("   4. Quota esaurita")
        elif resp.status_code == 429:
            print("❌ Errore 429: Rate limit superato")
            print("   Attendi qualche minuto e riprova")
        else:
            print(f"❌ Errore {resp.status_code}: {resp.text[:200]}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Errore di connessione: {e}")
        print("\n⚠️  Verifica la tua connessione internet")
    except requests.exceptions.Timeout:
        print("❌ Timeout: il server non risponde")
    except Exception as e:
        print(f"❌ Errore: {e}")
    
    return []

def test_generate(api_key, model):
    """Testa la generazione con un modello specifico"""
    print("\n" + "=" * 60)
    print(f"TEST 2: Generazione con modello '{model}'")
    print("=" * 60)
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": "Rispondi solo con la parola 'FUNZIONA' senza altro testo."}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 50
        }
    }
    
    try:
        print(f"Invio richiesta a: {model}...")
        resp = requests.post(url, json=payload, timeout=30)
        print(f"Status HTTP: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            
            # Verifica se ci sono candidati
            candidates = data.get("candidates", [])
            if candidates:
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                print(f"\n✅ RISPOSTA RICEVUTA:")
                print(f"   '{text.strip()}'")
                print(f"\n🎉 L'API GEMINI FUNZIONA CORRETTAMENTE!")
                return True
            else:
                # Potrebbe essere bloccato per safety
                block_reason = data.get("promptFeedback", {}).get("blockReason", "")
                if block_reason:
                    print(f"⚠️  Risposta bloccata: {block_reason}")
                else:
                    print(f"⚠️  Nessun candidato nella risposta: {json.dumps(data, indent=2)[:500]}")
                    
        elif resp.status_code == 404:
            print(f"❌ Modello '{model}' non trovato")
            print("   Prova con un altro modello come 'gemini-1.5-flash'")
        elif resp.status_code == 403:
            print("❌ Accesso negato al modello")
            try:
                err = resp.json()
                msg = err.get("error", {}).get("message", "")
                print(f"   Messaggio: {msg}")
            except:
                # Risposta HTML invece di JSON
                if "<!DOCTYPE" in resp.text or "<html" in resp.text.lower():
                    print("   ⚠️  Risposta HTML ricevuta invece di JSON")
                    print("   Questo indica un problema di rete/proxy/firewall")
                else:
                    print(f"   Risposta: {resp.text[:200]}")
        elif resp.status_code == 429:
            print("❌ Rate limit superato - attendi e riprova")
        elif resp.status_code == 500:
            print("❌ Errore interno del server Google - riprova più tardi")
        else:
            print(f"❌ Errore {resp.status_code}")
            print(f"   Risposta: {resp.text[:300]}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Errore di connessione: {e}")
    except requests.exceptions.Timeout:
        print("❌ Timeout nella richiesta")
    except Exception as e:
        print(f"❌ Errore: {e}")
    
    return False

def main():
    print("=" * 60)
    print("     🤖 TEST DIAGNOSTICO API GEMINI")
    print("=" * 60)
    
    # Carica API key
    api_key, model = load_api_key()
    
    if not api_key:
        print("\n❌ API key non trovata!")
        print("   Verifica che config.ini esista e contenga una chiave valida")
        print("\n   Oppure inserisci la chiave manualmente:")
        api_key = input("   API Key: ").strip()
        if not api_key:
            print("   Nessuna chiave inserita. Uscita.")
            return
        model = "gemini-1.5-flash"
    
    print(f"\n📋 Configurazione:")
    print(f"   API Key: {api_key[:10]}...{api_key[-4:]}")
    print(f"   Modello: {model}")
    
    # Test 1: Lista modelli
    available_models = test_list_models(api_key)
    
    # Test 2: Generazione
    if available_models:
        # Usa il modello configurato se disponibile, altrimenti il primo disponibile
        test_model = model if model in available_models else (available_models[0] if available_models else model)
        success = test_generate(api_key, test_model)
        
        if success:
            print("\n" + "=" * 60)
            print("✅ DIAGNOSI COMPLETATA: API FUNZIONANTE")
            print("=" * 60)
            print(f"\nModello consigliato per config.ini: {test_model}")
        else:
            print("\n" + "=" * 60)
            print("❌ DIAGNOSI COMPLETATA: PROBLEMI RILEVATI")
            print("=" * 60)
    else:
        # Prova comunque la generazione
        test_generate(api_key, model)
        print("\n" + "=" * 60)
        print("❌ DIAGNOSI COMPLETATA: PROBLEMI RILEVATI")
        print("=" * 60)
    
    print("\n📌 SUGGERIMENTI:")
    print("   1. Verifica la chiave su: https://aistudio.google.com/app/apikey")
    print("   2. Assicurati che 'Generative Language API' sia abilitata")
    print("   3. Controlla eventuali restrizioni IP sulla chiave")
    print("   4. Prova con una VPN se sei in una regione con restrizioni")
    print()

if __name__ == "__main__":
    main()
