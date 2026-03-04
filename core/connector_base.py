from abc import ABC, abstractmethod
from typing import List, Dict, Any
from models.unified_alert import UnifiedAlert

class BaseConnector(ABC):
    """
    Abstract Base Class for all EDR/SIEM Integrations.
    Forces all vendor APIs to comply with our global dashboard standard.
    """
    
    def __init__(self, tenant_id: str, config: Dict[str, str]):
        self.tenant_id = tenant_id
        self.config = config
        self.vendor_name = "Unknown"

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the vendor API."""
        pass

    @abstractmethod
    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Return a standardized list of all assets/endpoints."""
        pass

    @abstractmethod
    def get_alerts(self, limit: int = 50) -> List[UnifiedAlert]:
        """Fetch the latest alerts and transform them into UnifiedAlert objects."""
        pass

    @abstractmethod
    def get_raw_logs_for_ai(self, query: str) -> str:
        """Endpoint intended specifically for the MCP/AI Layer to run deep queries."""
        pass
        
    @abstractmethod
    def isolate_endpoint(self, agent_id: str) -> bool:
        """Trigger an Active Response script (e.g., firewall-drop) to isolate a compromised machine."""
        pass

    @abstractmethod
    def unisolate_endpoint(self, agent_id: str) -> bool:
        """Removes the Active Response network isolation firewall rule."""
        pass
        
    @abstractmethod
    def get_vulnerabilities(self, agent_id: str) -> List[Dict[str, Any]]:
        """Fetch all unpatched CVEs (Vulnerabilities) for a specific endpoint."""
        pass
