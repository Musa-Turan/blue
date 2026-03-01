import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
import random
import uuid

from core.connector_base import BaseConnector
from models.unified_alert import UnifiedAlert

class DummyEDRConnector(BaseConnector):
    """
    A simulated EDR (e.g., CrowdStrike) to demonstrate multi-vendor and multi-tenant capabilities.
    Generates fake but realistic threat data.
    """
    
    def __init__(self, tenant_id: str, config: Dict[str, str]):
        super().__init__(tenant_id, config)
        self.vendor_name = "DummyStrike EDR"
        
    def authenticate(self) -> bool:
        # Simulate connection sequence using config
        api_key = self.config.get("API_KEY")
        return bool(api_key)

    def get_endpoints(self) -> List[Dict[str, Any]]:
        return [
            {"id": "ds-001", "name": "finance-svr", "ip": "10.0.5.10", "status": "active", "os": "Windows Server 2022"},
            {"id": "ds-002", "name": "ceo-laptop", "ip": "10.0.5.55", "status": "disconnected", "os": "macOS Sonoma"},
        ]

    def get_alerts(self, limit: int = 5) -> List[UnifiedAlert]:
        alerts = []
        incident_types = ["Ransomware Behavior Detected", "Suspicious PowerShell Execution", "Lateral Movement Try"]
        severities = ["High", "Critical"]
        
        for _ in range(limit):
            alerts.append(UnifiedAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.now() - timedelta(minutes=random.randint(1, 120)),
                severity=random.choice(severities),
                incident_type=random.choice(incident_types),
                agent_id="ds-001",
                agent_name="finance-svr",
                agent_ip="10.0.5.10",
                description=f"Dummy EDR blocked a malicious execution path involving {random.choice(['lsass.exe', 'cmd.exe', 'powershell.exe'])}",
                vendor_name=self.vendor_name,
                tenant_id=self.tenant_id,
                raw_log={"event": "simulated", "action": "blocked"}
            ))
        return alerts

    def get_raw_logs_for_ai(self, query: str) -> str:
        return f"DUMMY_LOG: Executed query [{query}] across {self.vendor_name} for tenant {self.tenant_id}."
