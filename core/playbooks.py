from typing import List, Dict, Any
from models.unified_alert import UnifiedAlert
from core.connector_base import BaseConnector

# Define the automated response scenarios (Playbooks)
# In production, this would be loaded from a YAML/JSON configuration file.
ACTIVE_PLAYBOOKS = [
    {
        "id": "PB_RANSOMWARE_01",
        "name": "Acil Ransomware İzolasyonu",
        "enabled": True,
        "conditions": {
            "severity_in": ["Critical"],
            "keyword_match": ["ransomware", "encrypt", "mimikatz", "log4shell", "log4j", "winrar"]
        },
        "action": "isolate_endpoint",
        "notify_message": "🚨 [SOAR ROBOTU] Kritik fidye yazılımı/istismar aktivitesi tespit edildi. Yayılmayı durdurmak için makine otomatik izolasyona alındı!"
    },
    {
        "id": "PB_BRUTEFORCE_01",
        "name": "Şüpheli Ağ Haraketi (Brute Force)",
        "enabled": False, # Just an example of a disabled playbook
        "conditions": {
            "severity_in": ["High", "Critical"],
            "keyword_match": ["brute force", "multiple failed logins"]
        },
        "action": "isolate_endpoint",
        "notify_message": "🚨 [SOAR ROBOTU] Ardışık hatalı giriş tespiti. Cihaz geçici izolasyona alındı."
    }
]

def evaluate_and_respond(alerts: List[UnifiedAlert], connector: BaseConnector, isolated_history: set) -> List[Dict[str, str]]:
    """
    Evaluates a list of unified alerts against active SOAR playbooks.
    If a playbook matches, it fires the automated action via the connector
    and returns a list of notification messages for the UI.
    """
    notifications = []
    
    for alert in alerts:
        # Skip if the agent is already in our history of automated isolations to prevent API spam
        if alert.agent_id in isolated_history:
            continue
            
        for playbook in ACTIVE_PLAYBOOKS:
            if not playbook["enabled"]:
                continue
                
            match_severity = alert.severity in playbook["conditions"].get("severity_in", [])
            
            match_keyword = False
            desc_lower = alert.description.lower()
            for kw in playbook["conditions"].get("keyword_match", []):
                if kw.lower() in desc_lower:
                    match_keyword = True
                    break
                    
            if match_severity and match_keyword:
                print(f"[SOAR] Playbook {playbook['id']} tetiklendi: {alert.agent_name} ({alert.description})")
                
                if playbook["action"] == "isolate_endpoint":
                    # Execute the Active Response via the Connector!
                    success = connector.isolate_endpoint(alert.agent_id)
                    if success:
                        isolated_history.add(alert.agent_id)
                        notifications.append({
                            "agent": alert.agent_name,
                            "playbook": playbook["name"],
                            "message": playbook["notify_message"]
                        })
                    break # Don't evaluate other playbooks for this alert if we just isolated it
                    
    return notifications
