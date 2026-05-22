from streamlit_agraph import Node, Edge

def build_process_tree(alert_description):
    """
    Simulates a process tree based on the incident description.
    Returns: nodes, edges, node_metadata (dictionary of forensic artifacts per node)
    """
    nodes = []
    edges = []
    metadata = {}
    
    # 1. Root Node (The Server/Endpoint)
    nodes.append(
        Node(
            id="System",
            label="Endpoint",
            size=25,
            shape="circularImage",
            image="https://cdn-icons-png.flaticon.com/512/873/873117.png"
        )
    )
    metadata["System"] = {
        "Type": "Endpoint Server",
        "OS": "Windows Server 2022 / Linux",
        "IP Address": "Local Assigned",
        "Status": "Active Monitoring"
    }
    
    # Analyze description to generate a realistic looking tree
    desc_lower = alert_description.lower()
    
    if "powershell" in desc_lower or "base64" in desc_lower:
        nodes.append(Node(id="P1", label="explorer.exe", size=15, color="#117A65")) # Normal
        nodes.append(Node(id="P2", label="cmd.exe", size=20, color="#F4D03F"))     # Suspicious
        nodes.append(Node(id="P3", label="powershell.exe", size=25, color="#FF2B2B")) # Critical
        nodes.append(Node(id="Net1", label="185.x.x.x:443", size=15, color="#FF7A00")) # External IP
        
        edges.append(Edge(source="System", target="P1", label="boot"))
        edges.append(Edge(source="P1", target="P2", label="spawned"))
        edges.append(Edge(source="P2", target="P3", label="executed (-enc)"))
        edges.append(Edge(source="P3", target="Net1", label="network connection"))
        
        metadata["P1"] = {
            "Process": "explorer.exe",
            "Path": "C:\\Windows\\explorer.exe",
            "User": "Admin",
            "PID": "1024"
        }
        metadata["P2"] = {
            "Process": "cmd.exe",
            "Path": "C:\\Windows\\System32\\cmd.exe",
            "Command Line": "cmd.exe /c start powershell.exe -enc JABzAD...",
            "User": "Admin",
            "PID": "4096",
            "SHA256": "B4B3D44A89C199859A30E66C5EB636BDECC360A2D3C402AC6A2FBA1D84260D05"
        }
        metadata["P3"] = {
            "Process": "powershell.exe",
            "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Command Line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABzADQAZQBlA...==",
            "User": "NT AUTHORITY\\SYSTEM",
            "PID": "5112",
            "SHA256": "9F241088CEBB2541FCE2DAA514D162EDD87C9F92036DA7128549EF2E0BB28D48",
            "MITRE Tactics": "T1059.001 - PowerShell",
            "Note": "Suspicious base64 payload execution detected!"
        }
        metadata["Net1"] = {
            "Type": "Network Connection",
            "Destination IP": "185.10.10.15",
            "Destination Port": "443",
            "Protocol": "TCP",
            "Bytes Sent": "14500",
            "Status": "Established C2 Channel"
        }
        
    elif "login" in desc_lower or "authentication" in desc_lower:
        nodes.append(Node(id="P1", label="sshd", size=20, color="#117A65"))
        nodes.append(Node(id="Net1", label="Remote IP", size=25, color="#FF2B2B"))
        
        edges.append(Edge(source="System", target="P1", label="service running"))
        edges.append(Edge(source="Net1", target="P1", label="brute force attempt"))
        
        metadata["P1"] = {
            "Process": "sshd",
            "Path": "/usr/sbin/sshd",
            "Service": "OpenSSH Daemon",
            "PID": "854",
            "Config": "/etc/ssh/sshd_config"
        }
        metadata["Net1"] = {
            "Type": "Malicious Source IP",
            "Source IP": "194.26.29.11",
            "Source Port": "45211",
            "Target User": "root",
            "Attempts": "452",
            "Action": "Failed Logins (Brute Force)",
            "MITRE Tactics": "T1110 - Brute Force"
        }
        
    else:
        # Generic Tree
        nodes.append(Node(id="P1", label="services.exe", size=15, color="#117A65"))
        nodes.append(Node(id="P2", label="Unknown.exe", size=25, color="#FF7A00"))
        
        edges.append(Edge(source="System", target="P1", label="system"))
        edges.append(Edge(source="P1", target="P2", label="injected memory"))

        metadata["P1"] = {
            "Process": "services.exe",
            "Path": "C:\\Windows\\System32\\services.exe",
            "Service": "Service Control Manager (SCM)",
            "PID": "656"
        }
        metadata["P2"] = {
            "Process": "Unknown.exe",
            "Path": "C:\\Users\\Public\\Downloads\\Unknown.exe",
            "Command Line": "Unknown.exe --hidden --persist",
            "User": "Guest",
            "PID": "8888",
            "SHA256": "UNKNOWN_HASH_FILE_NOT_FOUND",
            "Warning": "Memory injection detected originating from services.exe"
        }

    return nodes, edges, metadata
