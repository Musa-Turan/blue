import hashlib

# Hardcoded user database for demonstration purposes.
# In a real-world scenario, this should be in an SQL database or linked to Active Directory / AWS Cognito.

USERS_DB = {
    "admin": {
        "password_hash": hashlib.sha256("musa123".encode()).hexdigest(),
        "role": "L2_Analyst",
        "description": "MSSP SOC Admin Account (Full access to all clients)",
        "allowed_tenant": "ALL"
    },
    "ahmet_user": {
        "password_hash": hashlib.sha256("lojistik123".encode()).hexdigest(),
        "role": "Client_Admin",
        "description": "Ahmet Logistics IT Admin (Restricted to own tenant, read-only)",
        "allowed_tenant": "Ahmet Logistics (Dummy)"
    },
    "musa_user": {
        "password_hash": hashlib.sha256("hold123".encode()).hexdigest(),
        "role": "Client_Admin",
        "description": "Musa Holding IT Admin",
        "allowed_tenant": "Musa Holding (Wazuh)"
    }
}

def authenticate_user(username, password):
    """
    Checks if the provided username and password match the database.
    Returns the user profile dict if successful, None otherwise.
    """
    if username in USERS_DB:
        user = USERS_DB[username]
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] == pw_hash:
            # Mask the hash before returning the profile
            profile = user.copy()
            del profile["password_hash"]
            profile["username"] = username
            return profile
    return None
