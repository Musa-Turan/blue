import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import urllib3
from datetime import datetime

# Sertifika uyarısını gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- AYARLAR ---
WAZUH_IP = "192.168.1.43"  # Sabitlediğin IP
WAZUH_PORT = "55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = ".+jSKgf3IR3janqE2pWL+USnaQ6MeWxV"

# API URL
BASE_URL = f"https://{WAZUH_IP}:{WAZUH_PORT}"
AUTH_URL = f"{BASE_URL}/security/user/authenticate"

# --- FONKSIYONLAR ---
def get_token():
    try:
        response = requests.get(AUTH_URL, auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=5)
        if response.status_code == 200:
            return response.json()['data']['token']
        response = requests.post(AUTH_URL, auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=5)
        if response.status_code == 200:
            return response.json()['data']['token']
        return None
    except Exception as e:
        st.error(f"Bağlantı Hatası: {e}")
        return None

def get_agents(token):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(f"{BASE_URL}/agents?pretty=true", headers=headers, verify=False)
        if response.status_code == 200:
            return response.json().get('data', {}).get('affected_items', [])
        return []
    except:
        return []

def get_sca_scan(token, agent_id):
    headers = {'Authorization': f'Bearer {token}'}
    url = f"{BASE_URL}/sca/{agent_id}"
    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            return response.json().get('data', {}).get('affected_items', [])
        return []
    except:
        return []

# YENİ: Dosya Bütünlük (Syscheck/FIM) Verisini Çek
def get_fim_events(token, agent_id):
    headers = {'Authorization': f'Bearer {token}'}
    # Son dosya değişikliklerini getir
    url = f"{BASE_URL}/syscheck/{agent_id}/items?limit=20&sort=-mtime" 
    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            return response.json().get('data', {}).get('affected_items', [])
        return []
    except Exception as e:
        st.error(f"FIM Hatası: {e}")
        return []

# --- ARAYÜZ TASARIMI ---
st.set_page_config(page_title="Blue Team Asistanı", layout="wide", page_icon="🛡️")

st.title("🛡️ Blue Team Operasyon Merkezi v5.0")
st.markdown(f"**Sunucu:** `{WAZUH_IP}` | **Modül:** `Full Stack Monitoring`")

# Yan Menü
st.sidebar.header("Kontrol Paneli")
token = get_token()

if token:
    st.sidebar.success("API Bağlantısı: AKTİF 🟢")
    
    # Ajan Seçimi
    agents = get_agents(token)
    if agents:
        agent_options = {f"{a['id']} - {a['name']} ({a.get('ip', 'N/A')})": a['id'] for a in agents}
        selected_label = st.sidebar.selectbox("Hedef Ajan Seç:", list(agent_options.keys()))
        selected_agent_id = agent_options[selected_label]
        
        st.divider()

        # --- SEKMELER ---
        tab1, tab2, tab3 = st.tabs(["📊 Genel Durum", "🔒 Güvenlik (SCA)", "📁 Dosya İzleme (FIM)"])

        # TAB 1: GENEL DURUM
        with tab1:
            agent_info = next((item for item in agents if item["id"] == selected_agent_id), None)
            if agent_info:
                c1, c2, c3 = st.columns(3)
                c1.metric("Ajan Durumu", agent_info.get('status'))
                c2.metric("İşletim Sistemi", agent_info.get('os', {}).get('name', 'N/A'))
                c3.metric("IP Adresi", agent_info.get('ip', 'N/A'))
                
                # Basit bir saldırı simülasyon grafiği (Veri varsa)
                st.info("💡 İpucu: Dashboard'un hareketlenmesi için sisteme giriş yapmayı deneyebilir veya dosya oluşturabilirsiniz.")

        # TAB 2: SCA GÜVENLİK
        with tab2:
            sca_data = get_sca_scan(token, selected_agent_id)
            if sca_data:
                latest = sca_data[0]
                col_score, col_chart = st.columns([1, 2])
                col_score.metric("Güvenlik Puanı", f"{latest.get('score', 0)} / 100")
                
                df_chart = pd.DataFrame({'Durum': ['Geçilen', 'Başarısız'], 'Sayı': [latest.get('pass',0), latest.get('fail',0)]})
                fig = px.pie(df_chart, values='Sayı', names='Durum', hole=0.5, color='Durum', color_discrete_map={'Geçilen':'green', 'Başarısız':'red'})
                col_chart.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("Henüz güvenlik taraması tamamlanmadı.")

        # TAB 3: DOSYA İZLEME (YENİ)
        with tab3:
            st.subheader(f"🕵️ Dosya Bütünlük Kayıtları: {selected_label}")
            st.markdown("Sistemde değiştirilen, silinen veya eklenen kritik dosyalar burada görünür.")
            
            fim_data = get_fim_events(token, selected_agent_id)
            
            if fim_data:
                df_fim = pd.DataFrame(fim_data)
                # Tabloyu güzelleştir
                if 'file' in df_fim.columns:
                    # Hangi sütunları gösterelim?
                    cols = ['file', 'size', 'perm', 'uid', 'gid', 'mtime']
                    available_cols = [c for c in cols if c in df_fim.columns]
                    
                    st.dataframe(df_fim[available_cols], use_container_width=True)
                    
                    # Son değişiklik zamanı
                    last_change = df_fim['mtime'].max()
                    st.success(f"Son Dosya Aktivitesi: {last_change}")
                else:
                    st.dataframe(df_fim)
            else:
                st.info("Şu an için kaydedilmiş bir dosya değişikliği yok. (Syscheck taraması bekleniyor...)")
                
                # Test Butonu (Simülasyon için yönlendirme)
                with st.expander("🛠️ Bu Ekranı Nasıl Test Ederim?"):
                    st.write("""
                    1. Windows makinede **C:\\Program Files (x86)\\ossec-agent** klasörüne git.
                    2. Orada yeni bir metin belgesi oluştur (örn: `hacker.txt`).
                    3. Veya mevcut `ossec.conf` dosyasını açıp bir boşluk ekleyip kaydet.
                    4. Birkaç dakika sonra buraya yansıyacaktır.
                    """)

    else:
        st.warning("Aktif ajan bulunamadı.")
else:
    st.error("Sunucuya bağlanılamadı.")