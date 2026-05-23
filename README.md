# Blue SOC XDR Platform

**Status:** BETA / TEST PHASE (Geliştirme Aşamasında)

MSSP operasyonlarında kullanılabilecek, özellikle güvenlik uzmanları tarafında çoklu müşteri yönetimini tek ekrana indirip talep karşılama ve aradığınız şeye daha kısa zamanda ulaşmanızı sağlayacak, sekmeden sekmeye atlamanızı minimum seviyeye indirmek için tasarlanma aşamasında bir projedir.

Welcome to the **Blue SOC XDR Platform**! This project is currently in its active development and testing phase. It is an eXtended Detection and Response (XDR) interface that integrates with Wazuh and OpenSearch to provide real-time alerts, incident management, threat hunting, and AI-driven SOC Analyst capabilities.

## Features (In Testing)
- **Unified Dashboard:** Live overview of endpoints and active threats.
- **Incident Management:** View and isolate endpoints utilizing SOAR playbooks.
- **Process Tree & Forensics:** Graph-based analysis of suspicious processes.
- **AI SOC Analyst:** Gemini AI powered assistant to analyze raw logs and incidents.
- **Threat Intel (TIP):** Lookups for suspicious IPs using external intel (e.g., Shodan, VirusTotal).
- **Vulnerability Scanner:** Display active CVEs on endpoints.
- **MITRE ATT&CK Mapping:** Heatmap showing active tactics and techniques.

## Özellikler (Test Aşamasında)
- **Tekil Gösterge Paneli (Dashboard):** Uç noktaların (endpoint) ve aktif tehditlerin anlık canlı görünümü.
- **Vaka Yönetimi (Incident Management):** SOAR senaryoları kullanarak uç noktaları görüntüleme ve izole etme.
- **Süreç Ağacı ve Adli Bilişim (Forensics):** Şüpheli işlemlerin grafik tabanlı analizi.
- **Yapay Zeka SOC Analisti:** Ham logları ve vakaları analiz etmek için Gemini AI destekli yapay zeka asistanı.
- **Tehdit İstihbaratı (TIP):** Harici istihbarat servisleri (örn. Shodan, VirusTotal) kullanarak şüpheli IP adreslerinin sorgulanması.
- **Zafiyet Tarayıcı (Vulnerability Scanner):** Uç noktalardaki aktif CVE zafiyetlerinin listelenmesi.
- **MITRE ATT&CK Eşleştirmesi:** Aktif taktik ve teknikleri gösteren ısı haritası (Heatmap).

## Prerequisites
- Python 3.9+
- A running instance of **Wazuh Manager** (API enabled)
- A running instance of **OpenSearch**

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/blue.git
   cd blue
   ```

2. **Create a virtual environment & install dependencies:**
   *(Ensure you have a `requirements.txt` which will be added soon)*
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Environment Variables:**
   For security reasons, hardcoded credentials are not used. You must create an environment file.
   - Copy `.env.example` to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Open `.env` and fill in your local Wazuh, OpenSearch, and Gemini API keys.

4. **Run the Application:**
   ```bash
   streamlit run app.py
   ```

5. **Login to the Interface:**
   The application uses a hardcoded demonstration database for authentication (see `core/auth.py`). You can log in with the following default admin account:
   - **Username:** `admin`
   - **Password:** `admin`

## Disclaimer
This project is provided "as is" during its test phase. Please do not use it in a production environment without proper security reviews. If you find any issues, feel free to open an issue!
