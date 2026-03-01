import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from connectors.wazuh_connector import WazuhConnector
from connectors.dummy_edr_connector import DummyEDRConnector

# Load secrets from .env
load_dotenv()

st.set_page_config(page_title="SOC Platform v7.0", layout="wide", page_icon="🛡️")

st.title("🛡️ MSSP Yön. Güvenlik Operasyon Merkezi (XDR)")

# --- TENANT SELECTION ---
if "current_tenant" not in st.session_state:
    st.session_state.current_tenant = "Musa Holding (Wazuh)"

st.sidebar.header("🏢 MSSP Kontrol Paneli")
tenant_choice = st.sidebar.selectbox(
    "Müşteri (Tenant) Seçiniz:",
    ["Musa Holding (Wazuh)", "Ahmet Lojistik (Dummy EDR)"],
    index=0 if st.session_state.current_tenant == "Musa Holding (Wazuh)" else 1
)
st.session_state.current_tenant = tenant_choice

# Initialize Connector dynamically
@st.cache_resource(show_spinner=False)
def get_connector(tenant_name):
    if tenant_name == "Musa Holding (Wazuh)":
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
    else:
        config = {"API_KEY": os.getenv("DUMMY_EDR_API_KEY", "dummy_token")}
        return DummyEDRConnector("ahmet_lojistik", config)

connector = get_connector(st.session_state.current_tenant)
st.markdown(f"**Güncel Müşteri:** `{st.session_state.current_tenant}` | **Veri Kaynağı:** `{connector.vendor_name}`")

with st.spinner(f"🔑 {connector.vendor_name} API'sine bağlanılıyor..."):
    is_authenticated = connector.authenticate()

if not is_authenticated:
    st.sidebar.error("API Bağlantısı: REDDEDİLDİ 🔴")
    st.error(f"{connector.vendor_name} veri kaynağıyla bağlantı kurulamadı. Lütfen .env dosyasını kontrol edin.")
    st.stop()

st.sidebar.success(f"API Bağlantısı: AKTİF 🟢")

with st.spinner("Uç nokta verileri çekiliyor..."):
    endpoints = connector.get_endpoints()

active_endpoints = [e for e in endpoints if e.get("status") == "active"]
disconnected_endpoints = [e for e in endpoints if e.get("status") == "disconnected"]

st.sidebar.metric("Toplam Uç Nokta", len(endpoints))
st.sidebar.metric("Bağlı (Active)", len(active_endpoints), delta=len(active_endpoints), delta_color="normal")
st.sidebar.metric("Düşmüş (Disconnected)", len(disconnected_endpoints), delta=-len(disconnected_endpoints) if disconnected_endpoints else 0, delta_color="inverse")

st.sidebar.divider()
if st.sidebar.button("🔄 Verileri Yenile", use_container_width=True):
    # Clear the caching to force a hard refresh
    get_connector.clear()
    st.rerun()

# --- TABS ---
tab1, tab2, tab3 = st.tabs(["🚨 Olay Yönetimi (Incidents)", "💻 Uç Noktalar (Endpoints)", "🤖 AI Analist (MCP)"])

with tab1:
    st.subheader(f"🚨 {st.session_state.current_tenant} - Genel Olay Yöneticisi")
    
    with st.spinner("Güvenlik olayları (Logs/Alerts) derleniyor..."):
        alerts = connector.get_alerts(limit=50)
    
    if alerts:
        # Convert UnifiedAlert instances to dictionary format for DataFrame
        alert_dicts = []
        for a in alerts:
            alert_dicts.append({
                "Tarih/Zaman": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Önem": a.severity,
                "Olay Tipi": a.incident_type,
                "Ajan": f"{a.agent_name} ({a.agent_id})",
                "Açıklama": a.description,
            })
            
        df_events = pd.DataFrame(alert_dicts)
        
        c1, c2 = st.columns(2)
        selected_severity = c1.multiselect("Önem Derecesine Göre Filtrele", options=df_events['Önem'].unique(), default=list(df_events['Önem'].unique()))
        selected_type = c2.multiselect("Olay Tipine Göre Filtrele", options=df_events['Olay Tipi'].unique(), default=list(df_events['Olay Tipi'].unique()))
        
        filtered_df = df_events[(df_events['Önem'].isin(selected_severity)) & (df_events['Olay Tipi'].isin(selected_type))]
        
        def color_severity(val):
            color_map = {'Critical': 'darkred', 'High': 'red', 'Medium': 'orange', 'Low': 'darkkhaki', 'Info': 'blue'}
            color = color_map.get(val, '')
            return f'background-color: {color}; color: white' if val in ['Critical', 'High'] else f'background-color: {color}; color: black'

        # Streamlit 1.30+ uses map instead of applymap
        try:
            styled_df = filtered_df.style.map(color_severity, subset=['Önem'])
        except AttributeError:
            # Fallback for older pandas versions
            styled_df = filtered_df.style.applymap(color_severity, subset=['Önem'])

        st.dataframe(styled_df, use_container_width=True, height=500)
    else:
        st.success("Tebrikler! Aktif bir ihlal bulunamadı.")

with tab2:
    st.subheader("💻 Bağlı Olan Tüm Uç Noktalar")
    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        def highlight_status(val):
            if val == 'active': return 'color: green; font-weight: bold'
            elif val == 'disconnected': return 'color: red; font-weight: bold'
            return ''
            
        try:
            styled_endpoints = df_endpoints.style.map(highlight_status, subset=['status'])
        except AttributeError:
            styled_endpoints = df_endpoints.style.applymap(highlight_status, subset=['status'])
            
        st.dataframe(styled_endpoints, use_container_width=True)
    else:
        st.info("Kayıtlı uç nokta bulunamadı.")

with tab3:
    st.subheader("🤖 SOC Analisti (AI Chat)")
    st.markdown("XDR üzerinden tespit edilen olayları anında analiz etmek için MCP destekli yapay zeka ajanınıza sorular sorun.")
    
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": f"Merhaba! Ben {st.session_state.current_tenant} için atanmış sanal SOC Analistinizim. Size nasıl yardımcı olabilirim?"}
        ]

    # Display chat messages from history on app rerun
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input(f"{st.session_state.current_tenant} ortamında net user loglarını analiz et..."):
        # Display user message in chat message container
        st.chat_message("user").markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            st.markdown("⏳ SOC ortamına bağlanıldı. Loglar inceleniyor...")
            
            # Simulated Response showing the power of the tool WITHOUT needing an OpenAI API Key
            import time
            time.sleep(1) # Simulate thinking
            
            if "Ahmet" in st.session_state.current_tenant:
                response = f"**Analiz Raporu:** {st.session_state.current_tenant} ortamında `ds-001` isimli sunucuda şüpheli PowerShell yürütülmesi tespit ettim. Bu durum bir fidye yazılımı (Ransomware) faaliyetiyle eşleşiyor. İzole etmemi onaylıyor musunuz?"
            else:
                response = f"**Analiz Raporu:** {st.session_state.current_tenant} ortamında `anapc` makinesinde Peş peşe `net user` komutu çalıştırılmış. Kural 100011 ihlal edildi. Bu durum bir keşif (Discovery) girişimi olabilir. EDR üzerinden makinenin ağ erişimini keseyim mi?"
            
            st.markdown(response)
            
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})