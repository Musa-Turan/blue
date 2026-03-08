import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from connectors.wazuh_connector import WazuhConnector
from connectors.dummy_edr_connector import DummyEDRConnector

# Load secrets from .env
load_dotenv()

st.set_page_config(page_title="SOC Platform v7.0", layout="wide", page_icon="🛡️")

from core.auth import authenticate_user

# --- AUTHENTICATION ---
if "user_profile" not in st.session_state:
    st.session_state.user_profile = None

if st.session_state.user_profile is None:
    st.markdown("## 🔒 MSSP Müşteri Portalı Girişi")
    with st.form("login_form"):
        username = st.text_input("Kullanıcı Adı")
        password = st.text_input("Şifre", type="password")
        submitted = st.form_submit_button("Giriş Yap", type="primary")
        
        if submitted:
            user = authenticate_user(username, password)
            if user:
                st.session_state.user_profile = user
                
                # If they are a client, lock them to their tenant. If admin, default to Musa.
                if user["role"] == "Client_Admin":
                    st.session_state.current_tenant = user["allowed_tenant"]
                else:
                    st.session_state.current_tenant = "Musa Holding (Wazuh)"
                    
                st.rerun()
            else:
                st.error("Kullanıcı adı veya şifre hatalı!")
                
    st.stop() # Halt execution if not logged in

# --- APP EXECUTION (LOGGED IN) ---
user = st.session_state.user_profile

st.sidebar.header(f"🧑‍💻 Hoş Geldin, {user['username']}")
st.sidebar.write(f"*{user['description']}*")
if st.sidebar.button("🚪 Çıkış Yap"):
    st.session_state.user_profile = None
    st.rerun()

st.sidebar.divider()
st.sidebar.header("🏢 MSSP Kontrol Paneli")

# --- TENANT SELECTION (RBAC) ---
if user["role"] == "L2_Analyst":
    # Admin can choose the tenant
    tenant_choice = st.sidebar.selectbox(
        "Müşteri (Tenant) Seçiniz:",
        ["Musa Holding (Wazuh)", "Ahmet Lojistik (Dummy EDR)"],
        index=0 if st.session_state.current_tenant == "Musa Holding (Wazuh)" else 1
    )
    st.session_state.current_tenant = tenant_choice
else:
    # Client is locked to their allowed tenant
    st.sidebar.info(f"Geçerli Kurum: **{user['allowed_tenant']}**")
    st.session_state.current_tenant = user["allowed_tenant"]

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

# Define application tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "🚨 Olay Yönetimi (Incidents)", 
    "💻 Uç Noktalar (Endpoints)", 
    "🤖 AI Analist (MCP)",
    "🛡️ Zafiyet Yönetimi (Vulnerabilities)",
    "📊 Raporlama (SLA)",
    "🌐 Tehdit İstihbaratı (TIP)",
    "🌍 Dış Yüzey (ASM)",
    "🕵️ Tehdit Avı (Hunt)"
])

if "auto_isolated_agents" not in st.session_state:
    st.session_state.auto_isolated_agents = set()

with tab1:
    st.subheader(f"🚨 {st.session_state.current_tenant} - Genel Olay Yöneticisi")
    
    with st.spinner("Güvenlik olayları (Logs/Alerts) derleniyor..."):
        alerts = connector.get_alerts(limit=50)
        
        # --- TRUE SOAR AUTOMATION (PLAYBOOKS) ---
        from core.playbooks import evaluate_and_respond
        # We only run automation if we are looking at the Tenant's real connected data
        # Actually, the Playbook checks `connector`. DummyEDR will just "print" success.
        playbook_notifications = evaluate_and_respond(
            alerts=alerts,
            connector=connector,
            isolated_history=st.session_state.auto_isolated_agents
        )
        
        for notif in playbook_notifications:
            st.toast(f"🤖 **SOAR OTO-İzolasyon:** {notif['agent']}\n{notif['message']}", icon="🚨")
    
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

        st.dataframe(styled_df, use_container_width=True, height=400)
        
        # --- SOAR (Active Response) SECTION ---
        if user["role"] == "L2_Analyst":
            st.markdown("---")
            st.subheader("⚡ Aktif Müdahale (SOAR)")
            st.markdown("Tehdit algılanan makineyi anında ağdan izole ederek (Firewall Drop) saldırının yayılmasını önleyin.")
            
            # Sadece kritik alarm üreten makineleri listele
            threat_agents = df_events[df_events['Önem'].isin(['Critical', 'High'])]['Ajan'].unique()
            
            if len(threat_agents) > 0:
                c_action1, c_action2, c_action3 = st.columns([2, 1, 1])
                with c_action1:
                    target_agent = st.selectbox("İzole Edilecek / Açılacak Makineyi Seçin:", threat_agents)
                
                # Extract agent ID from "AgentName (ID)" format
                import re
                agent_id = None
                match = re.search(r'\((.*?)\)', target_agent)
                if match:
                    agent_id = match.group(1).strip()
                
                with c_action2:
                    st.write("") # Spacer
                    st.write("")
                    if st.button("🔴 Ağı Kes (İzole Et)", use_container_width=True, type="primary"):
                        if agent_id:
                            with st.spinner(f"{target_agent} acil durum izolasyonuna alınıyor..."):
                                success = connector.isolate_endpoint(agent_id=agent_id)
                                if success:
                                    st.success(f"BAŞARILI! {target_agent} makinesinin tüm ağ ve internet iletişimi EDR üzerinden kesildi.")
                                    st.balloons()
                                else:
                                    st.error("İzolasyon API çağrısı başarısız oldu. Logları kontrol edin.")
                
                with c_action3:
                    st.write("") # Spacer
                    st.write("")
                    if st.button("🟢 İzoleyi Kaldır (Ağı Aç)", use_container_width=True):
                        if agent_id:
                            with st.spinner(f"{target_agent} ağ erişimi geri yükleniyor..."):
                                success = connector.unisolate_endpoint(agent_id=agent_id)
                                if success:
                                    st.success(f"BAŞARILI! {target_agent} makinesinin ağ iletişimi tekrar sağlandı.")
                                else:
                                    st.error("İzolasyon kaldırma API çağrısı başarısız oldu.")
            else:
                st.info("Şu anda acil müdahale gerektiren kritik bir tehdit bulunmuyor.")
        else:
            st.markdown("---")
            st.info("🔒 Aktif Müdahale (SOAR) yetkiniz bulunmamaktadır. Lütfen MSSP SOC yöneticinizle görüşün.")

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
            with st.spinner("⏳ SOC ortamına bağlanıldı. Loglar inceleniyor ve AI analizine gönderiliyor..."):
                try:
                    from google import genai
                    
                    # 1. Fetch the latest alerts from the Connector for context
                    recent_alerts = connector.get_alerts(limit=25)
                    alert_context = "Veritabanında Kayıtlı Son Olaylar:\n"
                    for a in recent_alerts:
                        alert_context += f"- [{a.severity}] {a.incident_type} (Kural: {a.description}) Makine: {a.agent_name}\n"
                    
                    # 2. Build the exact prompt for Gemini
                    system_instructions = f"Sen kıdemli bir L2 SOC analistisin. Müşterinin (Tenant: {st.session_state.current_tenant}) güvenlik loglarını analiz ediyorsun. Sana verilen log verilerine göre kullanıcının '{prompt}' sorusunu yanıtla. Sadece önemli ihlallere odaklan ve izolasyon/tehdit avı tavsiyesi ver. Yanıtı markdown formatında ve profesyonel bir Türkçe Siber Güvenlik jargonuyla (örn. yanal hareket, yetki yükseltme) ver."
                    full_prompt = f"{system_instructions}\n\n{alert_context}"
                    
                    # 3. Call Gemini API
                    api_key = os.getenv("GEMINI_API_KEY")
                    if not api_key:
                        raise ValueError("GEMINI_API_KEY ortam değişkeni bulunamadı. Lütfen .env dosyanızı kontrol edin.")
                        
                    client = genai.Client(api_key=api_key)
                    gemini_response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=full_prompt,
                    )
                    response = gemini_response.text
                except Exception as e:
                    response = f"**🤖 AI Bağlantı Hatası:** Model ile iletişim kurulamadı. Hata detayı: `{str(e)}`"
                
            st.markdown(response)
            
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

with tab4:
    st.subheader("🛡️ Uç Nokta Zafiyet Yönetimi (Vulnerability Management)")
    st.markdown("Ağa bağlı makinelerdeki güncellenmemiş yazılımları ve kritik güvenlik açıklarını (CVE) tespit edin.")
    
    if endpoints:
        active_endpoints = [f"{e['name']} ({e['id']})" for e in endpoints if e['status'] == 'active']
        
        if active_endpoints:
            selected_agent_str = st.selectbox("Zafiyet Taraması Yapılacak Makineyi Seçin:", active_endpoints)
            
            import re
            match = re.search(r'\((.*?)\)', selected_agent_str)
            if match:
                selected_agent_id = match.group(1).strip()
                
                with st.spinner(f"{selected_agent_str} makinesi için zafiyet taraması başlatılıyor..."):
                    vulns = connector.get_vulnerabilities(agent_id=selected_agent_id)
                
                if vulns:
                    st.warning(f"⚠️ {selected_agent_str} üzerinde **{len(vulns)}** adet yama bekleyen zafiyet (CVE) bulundu!")
                    
                    df_vulns = pd.DataFrame(vulns)
                    
                    # Ensure columns are ordered and translated for the UI
                    df_vulns = df_vulns.rename(columns={
                        "cve": "CVE ID",
                        "severity": "Kritiklik",
                        "cvss_score": "CVSS Puanı",
                        "software": "Yazılım / Uygulama",
                        "version": "Sürüm",
                        "status": "Durum",
                        "published": "Yayınlanma Tarihi"
                    })
                    
                    def color_vuln_severity(val):
                        color_map = {'Critical': 'darkred', 'High': 'red', 'Medium': 'orange', 'Low': 'darkkhaki'}
                        color = color_map.get(val, '')
                        return f'background-color: {color}; color: white' if val in ['Critical', 'High'] else f'background-color: {color}; color: black'

                    try:
                        styled_vulns = df_vulns.style.map(color_vuln_severity, subset=['Kritiklik'])
                    except AttributeError:
                        styled_vulns = df_vulns.style.applymap(color_vuln_severity, subset=['Kritiklik'])

                    st.dataframe(styled_vulns, use_container_width=True, height=500)
                else:
                    st.success(f"✅ Harika! {selected_agent_str} makinesinde bilinen hiçbir zafiyet bulunamadı. Sistem güncel.")
        else:
            st.info("Zafiyet taraması yapılabilecek aktif (çevrimiçi) bir makine bulunamadı.")
    else:
        st.info("Sisteme kayıtlı hiçbir uç nokta bulunamadı.")

with tab5:
    st.subheader("📊 Otomatik SOC/SLA Raporu")
    st.markdown("Müşterinize (Tenant) sunmak üzere güncel güvenlik duruşunu özetleyen profesyonel bir rapor oluşturun.")
    
    c_rep1, c_rep2 = st.columns([2, 1])
    with c_rep1:
        report_period = st.selectbox("Rapor Dönemi:", ["Son 24 Saat", "Son 7 Gün", "Son 30 Gün"])
        report_author = st.text_input("Hazırlayan Analist:", value="Musa Holding L2 SOC Team")
    
    with c_rep2:
        st.write("")
        st.write("")
        generate_btn = st.button("📄 Raporu Sentezle", use_container_width=True, type="primary")

    if generate_btn:
        with st.spinner("SLA Raporu derleniyor..."):
            # Prepare data
            t_name = st.session_state.current_tenant
            date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
            
            # Fetch fresh alerts if not already in memory
            rep_alerts = connector.get_alerts(limit=100)
            crit_count = sum(1 for a in rep_alerts if a.severity == "Critical")
            high_count = sum(1 for a in rep_alerts if a.severity == "High")
            
            # Building the Markdown Report
            report_md = f"""# 🛡️ SİBER GÜVENLİK DURUM RAPORU (SLA)
**Müşteri (Kurum):** {t_name}
**Tarih:** {date_str}
**Hazırlayan:** {report_author}
**Dönem:** {report_period}

---

## 1. YÖNETİCİ ÖZETİ
Belirtilen dönem içerisinde **{t_name}** altyapısında bulunan **{len(endpoints)}** adet uç nokta (Endpoint) başarıyla izlenmiş ve {len(rep_alerts)} adet şüpheli güvenlik olayı analiz edilmiştir. SOC ekibi tarafından kritik alarmlara anında müdahale (Active Response) gerçekleştirilmiştir.

## 2. UÇ NOKTA DURUMU (EDR/XDR)
- **Kapsamdaki Toplam Cihaz:** {len(endpoints)}
- **Aktif (Sağlıklı) Cihazlar:** {len(active_endpoints)}
- **Çevrimdışı Cihazlar:** {len(disconnected_endpoints)}

## 3. TEHDİT VE İHLAL YÖNETİMİ
Tespit edilen en son {len(rep_alerts)} uyarının ciddiyet dağılımı:
- 🔴 **Kritik (Critical):** {crit_count} adet
- 🟠 **Yüksek (High):** {high_count} adet
- 🟡 **Orta/Düşük (Medium/Low):** {len(rep_alerts) - crit_count - high_count} adet

### Tespit Edilen Önemli Bulgular:
"""
            # Append top 5 critical/high alerts
            top_alerts = [a for a in rep_alerts if a.severity in ["Critical", "High"]][:5]
            if top_alerts:
                for idx, alert in enumerate(top_alerts, 1):
                    report_md += f"{idx}. **[{alert.severity}]** {alert.incident_type} - {alert.agent_name} makinesinde gerçekleşti.\n"
                    report_md += f"   *Açıklama:* {alert.description}\n"
            else:
                report_md += "> Bu dönem içerisinde kritik veya yüksek seviyeli bir ihlal saptanmamıştır.\n"
                
            report_md += "\n---\n*Bu rapor Musa Holding Merkezi XDR Platformu tarafından otomatik olarak oluşturulmuştur.*"
            
            st.success("Rapor başarıyla sentezlendi!")
            
            # Display preview
            with st.expander("Görsel Rapor Önizlemesi", expanded=True):
                st.markdown(report_md)
                
            # Download button
            st.download_button(
                label="📥 Raporu Markdown (.md) Olarak İndir",
                data=report_md,
                file_name=f"{t_name}_SOC_Raporu_{date_str[:10]}.md",
                mime="text/markdown",
                use_container_width=True
            )

with tab6:
    st.subheader("🌐 Dış Tehdit İstihbaratı (Threat Intelligence - TIP)")
    st.markdown("XDR Alarmları içerisinden otomatik çekilen IP adreslerinin küresel itibar (Reputation) ve Zafiyet taraması sonuçları.")

    with st.spinner("Loglardaki IP adresleri ayrıştırılıyor ve TIP Motoruna soruluyor..."):
        from core.threat_intel import enrich_ip
        import re
        
        # We need alerts to extract IPs
        alerts_for_tip = connector.get_alerts(limit=50)
        
        extracted_ips = set()
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for a in alerts_for_tip:
           found_ips = ip_pattern.findall(a.description)
           extracted_ips.update(found_ips)
           
        # Also let analyst manually check an IP
        manual_ip = st.text_input("🔍 Manuel IP Sorgula (Örn: 185.220.101.44):")
        if manual_ip:
            if ip_pattern.match(manual_ip):
                extracted_ips.add(manual_ip)
            else:
                st.warning("Geçersiz IPv4 Formatı")
        
        if extracted_ips:
            st.write(f"Sistemde saptanan **{len(extracted_ips)}** benzersiz IP adresi için istihbarat çekiliyor...")
            intel_data = []
            for ip in extracted_ips:
                res = enrich_ip(ip)
                intel_data.append({
                    "IP Adresi": res["ip_address"],
                    "Risk Skoru": res["score"],
                    "Zararlı mı?": "🔴 EVET" if res["malicious"] else "🟢 HAYIR",
                    "Lokasyon": res["country"],
                    "Etiketler": ", ".join(res["tags"])
                })
            
            df_intel = pd.DataFrame(intel_data)
            
            def color_risk_score(val):
                if val >= 8.0: return 'background-color: darkred; color: white'
                elif val >= 5.0: return 'background-color: orange; color: black'
                else: return 'background-color: green; color: white'

            try:
                styled_intel = df_intel.style.map(color_risk_score, subset=['Risk Skoru'])
            except AttributeError:
                styled_intel = df_intel.style.applymap(color_risk_score, subset=['Risk Skoru'])
                
            st.dataframe(styled_intel, use_container_width=True)
            
        else:
            st.info("Mevcut alarmların detayında herhangi bir dış IP adresine rastlanmadı.")

with tab7:
    st.subheader("🌍 Dış Saldırı Yüzeyi Yönetimi (External ASM)")
    st.markdown("Müşterinin internete açık varlıklarını (Açık Portlar, Zafiyetli Servisler) Hackerlardan önce proaktif olarak tespit edin.")
    
    # Try to guess a domain based on the tenant, or leave blank
    default_domain = ""
    if "Musa" in st.session_state.current_tenant:
        default_domain = "musaholding.com.tr"
    elif "Ahmet" in st.session_state.current_tenant:
        default_domain = "ahmetlojistik.com"
        
    target_input = st.text_input("Hedef Alan Adı veya Dış IP Adresi Girin:", value=default_domain)
    
    if st.button("🔍 Dış Yüzeyi Tara (Shodan/Nmap Simülasyonu)", type="primary"):
        if target_input:
            with st.spinner(f"{target_input} hedefine yönelik detaylı port ve servis zafiyet taraması gerçekleştiriliyor... (Ortalama 2s)"):
                from core.asm_scanner import analyze_attack_surface
                scan_results = analyze_attack_surface(target_input)
                
                if scan_results:
                    st.success(f"Tarama Tamamlandı! {target_input} üzerinde {len(scan_results)} adet internete açık servis bulundu.")
                    
                    df_asm = pd.DataFrame(scan_results)
                    
                    def color_asm_risk(val):
                        if val == 'Kritik': return 'background-color: darkred; color: white; font-weight: bold'
                        elif val == 'Yüksek': return 'background-color: red; color: white'
                        elif val == 'Orta': return 'background-color: orange; color: black'
                        else: return 'background-color: green; color: white'

                    try:
                        styled_asm = df_asm.style.map(color_asm_risk, subset=['Risk'])
                        # Optional: highlight CVE column if it's not 'Yok'
                        def highlight_cve(val):
                            return 'color: red; font-weight: bold' if val != 'Yok' else ''
                        styled_asm = styled_asm.map(highlight_cve, subset=['Zafiyet (CVE)'])
                    except AttributeError:
                        styled_asm = df_asm.style.applymap(color_asm_risk, subset=['Risk']).applymap(lambda v: 'color: red; font-weight: bold' if v != 'Yok' else '', subset=['Zafiyet (CVE)'])
                        
                    st.dataframe(styled_asm, use_container_width=True)
                    
                    # Add a warning if any critical/high
                    if any(r['Risk'] in ['Kritik', 'Yüksek'] for r in scan_results):
                        st.error("⚠️ **Kritik Dış Zafiyet Tespit Edildi!** Bu müşteri altyapısının derhal koruma altına alınması (Firewall kuralı yazılması veya VPN arkasına çekilmesi) gerekmektedir.")
                        
                else:
                    st.info(f"{target_input} üzerinde dış dünyaya açık hiçbir port tespit edilemedi. (Mükemmel)")
        else:
            st.warning("Lütfen taramak için bir IP veya Alan Adı girin.")

with tab8:
    st.subheader("🕵️ Tehdit Avı (Threat Hunting / Sigma Translator)")
    st.markdown("İnternette bulduğunuz genel **Sigma (YAML)** formatındaki tehdit avı kurallarını, tek tıkla kurumunuzun Wazuh / Elasticsearch arama motoruna (Lucene/KQL) çevirin.")
    
    default_sigma = '''title: Şüpheli PowerShell Encode Komutu
description: Base64 ile encode edilmiş şüpheli powershell komutlarını tespit eder.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ['-enc', '-EncodedCommand', 'Base64']
    condition: selection
'''
    sigma_input = st.text_area("Sigma Kuralını (YAML) Buraya Yapıştırın:", value=default_sigma, height=250)
    
    if st.button("⚡ Wazuh / Elastic Sorgusuna Çevir", type="primary"):
        if sigma_input.strip():
            from core.sigma_translator import translate_sigma_to_wazuh
            translation = translate_sigma_to_wazuh(sigma_input)
            
            if translation.get("error"):
                st.error(f"❌ Çeviri Hatası: {translation['error']}")
            else:
                st.success("✅ Kural Başarıyla Çevrildi!")
                st.markdown(f"**Kural Adı:** {translation['title']}")
                st.markdown(f"**Açıklama:** {translation['description']}")
                st.markdown(f"**Log Kaynağı:** `{translation['logsource']}`")
                
                st.markdown("### 🎯 Çalıştırılabilir Arama Sorgusu (Kibana / Wazuh)")
                st.code(translation["query"], language="bash")
                
                st.info("💡 Yukarıdaki sorguyu kopyalayıp Wazuh 'Discover' veya 'Threat Hunting' sekmesindeki arama çubuğuna yapıştırarak hemen avlanmaya başlayabilirsiniz.")
        else:
            st.warning("Lütfen çevrilecek bir kural girin.")