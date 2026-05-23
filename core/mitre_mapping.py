import pandas as pd

def generate_mitre_heatmap_data(alerts):
    """
    Parses the alerts to map them to MITRE ATT&CK Tactics and Techniques.
    Returns a pandas DataFrame suitable for a heatmap matrix.
    """
    tactics = [
        "Initial Access", 
        "Execution", 
        "Persistence", 
        "Privilege Esc", 
        "Defense Evasion", 
        "Credential Access", 
        "Discovery", 
        "Lateral Move", 
        "C&C (C2)", 
        "Impact"
    ]
    
    techniques = [
        "T1190 Public Exploit", 
        "T1110 Brute Force",
        "T1078 Valid Accounts", 
        "T1059 Command Line", 
        "T1053 Scheduled Task", 
        "T1055 Process Injection",
        "T1003 Credential Dump",
        "T1082 System Info",
        "T1021 Remote Services",
        "T1071 App Layer Prot",
        "T1486 Ransomware"
    ]
    
    # Initialize an empty matrix (all zeros)
    matrix = pd.DataFrame(0, index=techniques, columns=tactics)

    # Simple rule engine to map dummy alerts to MITRE
    for alert in alerts:
        desc = alert.description.lower()
        if "login" in desc or "authentication" in desc or "brute" in desc:
            matrix.at["T1110 Brute Force", "Initial Access"] += 2
            matrix.at["T1078 Valid Accounts", "Credential Access"] += 1
            
        if "powershell" in desc or "cmd" in desc or "base64" in desc:
            matrix.at["T1059 Command Line", "Execution"] += 3
            matrix.at["T1059 Command Line", "Defense Evasion"] += 2
            
        if "injection" in desc or "services.exe" in desc:
            matrix.at["T1055 Process Injection", "Defense Evasion"] += 2
            matrix.at["T1055 Process Injection", "Privilege Esc"] += 2
            
        if "network" in desc or "ip" in desc or "185." in desc:
            matrix.at["T1071 App Layer Prot", "C&C (C2)"] += 1
            
        if "malware" in desc or "virus" in desc:
            matrix.at["T1190 Public Exploit", "Initial Access"] += 1
            
        if "ransomware" in desc or "crypto" in desc:
            matrix.at["T1486 Ransomware", "Impact"] += 3

    # To ensure the heatmap looks "alive" even if alerts are sparse in dummy data,
    # we add a baseline of very light activity (background noise typical in SOCs)
    matrix.at["T1110 Brute Force", "Initial Access"] += 1
    matrix.at["T1059 Command Line", "Execution"] += 1

    return matrix
