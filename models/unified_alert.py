from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any

class UnifiedAlert(BaseModel):
    """
    OCSF-inspired Vendor Agnostic Alert Model.
    Regardless of whether an alert comes from Wazuh, Splunk, or CrowdStrike,
    it must be transformed into this object before hitting the UI or AI.
    """
    alert_id: str
    timestamp: datetime
    severity: str = Field(description="Low, Medium, High, Critical")
    incident_type: str = Field(description="E.g., Malware, Privilege Escalation, Policy Violation")
    
    # Asset Information
    agent_id: str
    agent_name: str
    agent_ip: Optional[str] = None
    
    # Context
    description: str
    vendor_name: str = Field(description="Wazuh, CrowdStrike, SentinelOne, etc.")
    tenant_id: str = Field(description="Critical for Multi-Tenant Isolation")
    
    # Raw log preservation for AI analysis
    raw_log: Optional[Dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True
