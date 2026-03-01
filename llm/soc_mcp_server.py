from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import os
import sys

# Add parent directory to path to allow importing the connectors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors.wazuh_connector import WazuhConnector
from connectors.dummy_edr_connector import DummyEDRConnector

# Setup Environment
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

# Initialize the Server
mcp = FastMCP("MSSP_SOC_Analyst")

def _get_connector(tenant_name: str):
    """Helper function to instantiate the correct EDR connector based on tenant."""
    if tenant_name.lower() == "musa_holding":
        config = {
            "WAZUH_MANAGER_IP": os.getenv("WAZUH_MANAGER_IP"),
            "WAZUH_API_PORT": os.getenv("WAZUH_API_PORT", "55000"),
            "WAZUH_API_USER": os.getenv("WAZUH_API_USER"),
            "WAZUH_API_PASSWORD": os.getenv("WAZUH_API_PASSWORD"),
            "OPENSEARCH_PORT": os.getenv("OPENSEARCH_PORT", "9200"),
            "OPENSEARCH_USER": os.getenv("OPENSEARCH_USER"),
            "OPENSEARCH_PASSWORD": os.getenv("OPENSEARCH_PASSWORD"),
        }
        return WazuhConnector("musa_holding", config)
    elif tenant_name.lower() == "ahmet_lojistik":
        config = {"API_KEY": os.getenv("DUMMY_EDR_API_KEY", "dummy_token")}
        return DummyEDRConnector("ahmet_lojistik", config)
    else:
        raise ValueError(f"Unknown tenant: {tenant_name}. Valid options: musa_holding, ahmet_lojistik")

@mcp.tool()
def get_active_tenants() -> str:
    """Returns a list of all active tenants (clients) managed by the MSSP."""
    return "Active Tenants:\n1) musa_holding (Wazuh XDR)\n2) ahmet_lojistik (DummyStrike EDR)"

@mcp.tool()
def get_tenant_alerts(tenant_name: str, limit: int = 5) -> str:
    """
    Fetches the most recent security alerts for a specific tenant.
    
    Args:
        tenant_name: The ID of the tenant (e.g., 'musa_holding' or 'ahmet_lojistik')
        limit: Number of alerts to retrieve (default 5)
    """
    try:
        connector = _get_connector(tenant_name)
        if not connector.authenticate():
            return f"Authentication failed for tenant {tenant_name}."
            
        alerts = connector.get_alerts(limit=limit)
        
        if not alerts:
            return f"No active alerts found for tenant {tenant_name}."
            
        result = f"--- LATEST {len(alerts)} ALERTS FOR {tenant_name.upper()} ---\n"
        for a in alerts:
            result += f"[{a.severity}] {a.incident_type} on {a.agent_name} ({a.agent_ip}) - {a.description}\n"
        return result
    except Exception as e:
        return f"Error fetching alerts: {str(e)}"

@mcp.tool()
def investigate_endpoint(tenant_name: str, agent_id: str) -> str:
    """
    Runs a deep investigation on a specific endpoint to gather raw EDR telemetry.
    
    Args:
        tenant_name: The client tenant (e.g., 'musa_holding')
        agent_id: The ID of the machine to investigate.
    """
    try:
        connector = _get_connector(tenant_name)
        if not connector.authenticate():
            return "Authentication failed."
        return connector.get_raw_logs_for_ai(f"Deep dive telemetry for agent {agent_id}")
    except Exception as e:
        return f"Investigation failed: {str(e)}"

if __name__ == "__main__":
    mcp.run()
