import re
import socket
import hashlib
import os
import requests

def enrich_ip(ip_address: str) -> dict:
    """
    Enriches an IP address with Threat Intelligence data.
    If VT_API_KEY is present in .env, it uses the real VirusTotal v3 API.
    Otherwise, falls back to the heuristic mock engine.
    """
    
    # Baseline structure
    intel = {
        "ip_address": ip_address,
        "score": 0.0, # 0.0 (Safe) to 10.0 (Critical Threat)
        "malicious": False,
        "tags": [],
        "country": "Bilinmiyor"
    }
    
    # 1. Check for Private / Local Networking
    try:
        if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
            intel["tags"].append("Internal/LAN")
            intel["country"] = "Local Network"
            intel["score"] = 1.0
            return intel
        elif ip_address == "127.0.0.1":
            intel["tags"].append("Loopback")
            intel["country"] = "Localhost"
            return intel
    except Exception:
        pass

    # 2. VirusTotal Real API Integration
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": vt_key}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                
                malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total_scanners = sum(stats.values()) if sum(stats.values()) > 0 else 100
                
                # Calculate score 0-10
                intel["score"] = round((malicious_count / float(total_scanners)) * 100 / 10.0, 1)
                if malicious_count > 0:
                    intel["score"] = max(intel["score"], 3.0) # Boost score if at least 1 engine found it
                if malicious_count > 3:
                    intel["malicious"] = True
                    
                intel["country"] = data.get("country", "Bilinmiyor")
                
                # Gather tags from engines
                if malicious_count > 0:
                    intel["tags"].append("VT: Reported Suspicious/Malicious")
                    intel["tags"].append(f"Engines: {malicious_count}/{total_scanners}")
                else:
                    intel["tags"].append("VT: Clean")
                    
                return intel
            else:
                print(f"[TIP] VirusTotal API Error ({response.status_code}). Falling back to heuristics.")
        except Exception as e:
            print(f"[TIP] VirusTotal Request failed: {str(e)}. Falling back to heuristics.")


    # 3. Heuristic Intelligence Score Simulator (Fallback)
    ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest()[:4], 16)
    
    known_bad = ["185.220.101.44", "45.153.240.135", "103.111.53.11"]
    
    if ip_address in known_bad or ip_hash % 10 > 7:
        intel["score"] = 9.8 if ip_address in known_bad else float(ip_hash % 10 + (ip_hash % 100 / 100.0))
        intel["malicious"] = True
        intel["tags"].extend(["Malware C2", "Botnet", "Scanner"])
        intel["country"] = ["Rusya", "Kuzey Kore", "Çin", "Brezilya"][ip_hash % 4]
    elif ip_hash % 10 > 4:
        intel["score"] = float(ip_hash % 10 + (ip_hash % 100 / 100.0))
        intel["malicious"] = False
        intel["tags"].extend(["Spam IP", "Tor Exit Node", "Suspicious"])
        intel["country"] = ["Almanya", "Hollanda", "Romanya", "Bulgaristan"][ip_hash % 4]
    else:
        intel["score"] = float(ip_hash % 4 + (ip_hash % 100 / 100.0))
        intel["malicious"] = False
        intel["tags"].extend(["Temiz", "Kurumsal ASN", "Cloud Provider"])
        intel["country"] = ["Amerika Birleşik Devletleri", "İrlanda", "Türkiye", "İngiltere"][ip_hash % 4]

    return intel

