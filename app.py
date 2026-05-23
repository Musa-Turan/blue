import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv
import os
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from connectors.wazuh_connector import WazuhConnector
from connectors.dummy_edr_connector import DummyEDRConnector
from core.auth import authenticate_user
from core.process_tree import build_process_tree
from core.mitre_mapping import generate_mitre_heatmap_data
from streamlit_agraph import agraph, Config

# Load secrets
load_dotenv()

st.set_page_config(page_title="SOC XDR Platform", layout="wide", page_icon="🛡️")

# --- CUSTOM CSS (EDR/XDR Styling) ---
st.markdown("""
    <style>
    /* Hide Streamlit default header and footer */
    header {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Main background and padding */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Custom Card Style for KPIs and Data */
    div[data-testid="stMetricValue"] {
        font-size: 2.2rem;
        color: #00F0FF;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 1rem;
        color: #8B949E;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Make buttons look professional */
    .stButton>button {
        border-radius: 4px;
        font-weight: 600;
        border: 1px solid #30363D;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        border-color: #00F0FF;
        box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
    }
    
    /* Login Box Styling */
    .login-box {
        background-color: #161B22;
        padding: 2rem;
        border-radius: 8px;
        border: 1px solid #30363D;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    </style>
""", unsafe_allow_html=True)


# --- AUTHENTICATION ---
if "user_profile" not in st.session_state:
    st.session_state.user_profile = None

if st.session_state.user_profile is None:
    st.markdown("<br><br>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 1.5, 1])
    with c2:
        st.markdown("<h2 style='text-align: center; color: #00F0FF;'>🛡️ SOC XDR Platform</h2>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #8B949E;'>Central Security Operations Login</p>", unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login to System", use_container_width=True)
            
            if submitted:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.user_profile = user
                    if user["role"] == "Client_Admin":
                        st.session_state.current_tenant = user["allowed_tenant"]
                    else:
                        st.session_state.current_tenant = "Wazuh"
                    st.rerun()
                else:
                    st.error("Invalid username or password!")
    st.stop()


# --- APP EXECUTION (LOGGED IN) ---
user = st.session_state.user_profile

# SIDEBAR CONFIGURATION
with st.sidebar:
    st.markdown("<h3 style='color: #00F0FF; text-align: center;'>🛡️ SOC XDR</h3>", unsafe_allow_html=True)
    st.markdown(f"<p style='text-align: center; font-size: 0.8rem; color: #8B949E;'>Analyst: {user['username']}</p>", unsafe_allow_html=True)
    st.divider()
    
    if user["role"] == "L2_Analyst":
        tenant_choice = st.selectbox(
            "🏢 Integration / Source:",
            ["Wazuh", "Dummy EDR"],
            index=0 if "Wazuh" in st.session_state.current_tenant else 1
        )
        st.session_state.current_tenant = tenant_choice
    else:
        st.info(f"Active Tenant: **{user['allowed_tenant']}**")
        st.session_state.current_tenant = user["allowed_tenant"]

    st.divider()
    
    # NAVIGATION MENU
    menu_selection = st.radio(
        "Navigation Menu",
        [
            "📊 Overview (Dashboard)", 
            "🚨 Incident Management", 
            "💻 Endpoints", 
            "🤖 SOC Analyst (AI)",
            "🛡️ Vulnerabilities (Vulns)",
            "🌐 Threat Intel (TIP)",
            "🌍 Attack Surface (ASM)",
            "🔥 MITRE ATT&CK Heatmap",
            "🕵️ Threat Hunting",
            "📋 SLA Reporting"
        ]
    )
    
    st.divider()
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.user_profile = None
        st.rerun()


# Initialize Connector
@st.cache_resource(show_spinner=False)
def get_connector(tenant_name):
    if "Wazuh" in tenant_name:
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
        return DummyEDRConnector("ahmet_logistics", config)

connector = get_connector(st.session_state.current_tenant)
is_authenticated = connector.authenticate()

if not is_authenticated:
    st.error(f"🔴 API Connection Failed: {connector.vendor_name}. Please check VPN and IP settings.")
    st.stop()

endpoints = connector.get_endpoints()
active_endpoints = [e for e in endpoints if e.get("status") == "active"]
disconnected_endpoints = [e for e in endpoints if e.get("status") == "disconnected"]
alerts = connector.get_alerts(limit=100)

if "auto_isolated_agents" not in st.session_state:
    st.session_state.auto_isolated_agents = set()


# ==========================================
# PAGE ROUTING
# ==========================================

st.markdown(f"<div style='display:flex; justify-content:space-between; align-items:center;'><h3>{menu_selection.split('(')[0].strip()}</h3><span style='color:#00F0FF;'>{st.session_state.current_tenant}</span></div>", unsafe_allow_html=True)
st.divider()

if menu_selection == "📊 Overview (Dashboard)":
    # 1. KPI Row
    k1, k2, k3, k4 = st.columns(4)
    crit_count = sum(1 for a in alerts if a.severity == "Critical")
    high_count = sum(1 for a in alerts if a.severity == "High")
    
    k1.metric("Critical Incidents", crit_count, delta="Urgent Response" if crit_count>0 else None, delta_color="inverse")
    k2.metric("High Risk Incidents", high_count)
    k3.metric("Active Endpoints", len(active_endpoints), delta=f"{len(endpoints)} Total")
    k4.metric("Offline (Disconnected)", len(disconnected_endpoints), delta="Investigate" if disconnected_endpoints else "All Good", delta_color="inverse")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # 2. Charts Row
    c1, c2 = st.columns(2)
    if alerts:
        # Prepare data for charts
        df_alerts = pd.DataFrame([{
            "Time": a.timestamp,
            "Severity": a.severity,
            "Type": a.incident_type,
            "Machine": a.agent_name
        } for a in alerts])
        
        with c1:
            st.markdown("##### 📈 Incident Distribution (Severity)")
            fig_pie = px.pie(df_alerts, names='Severity', hole=0.5, color='Severity', 
                             color_discrete_map={'Critical':'#FF0000', 'High':'#FF7A00', 'Medium':'#FFD700', 'Low':'#000080'})
            fig_pie.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with c2:
            st.markdown("##### 🖥️ Top Targeted Machines")
            fig_bar = px.histogram(df_alerts, x='Machine', color='Severity', barmode='stack', 
                                   color_discrete_map={'Critical':'#FF0000', 'High':'#FF7A00', 'Medium':'#FFD700', 'Low':'#000080'})
            fig_bar.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No active incident data to report in the system.")


elif menu_selection == "🚨 Incident Management":
    # Run Playbooks
    from core.playbooks import evaluate_and_respond
    playbook_notifications = evaluate_and_respond(alerts=alerts, connector=connector, isolated_history=st.session_state.auto_isolated_agents)
    for notif in playbook_notifications:
        st.toast(f"🤖 **SOAR AUTO-Isolation:** {notif['agent']}\n{notif['message']}", icon="🚨")
        
    if alerts:
        alert_dicts = [{"Date/Time": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "Severity": a.severity, "Event Type": a.incident_type, "Agent": f"{a.agent_name} ({a.agent_id})", "Description": a.description} for a in alerts]
        df_events = pd.DataFrame(alert_dicts)
        
        c1, c2 = st.columns(2)
        selected_severity = c1.multiselect("Filter by Severity", options=df_events['Severity'].unique(), default=list(df_events['Severity'].unique()))
        selected_type = c2.multiselect("Filter by Event Type", options=df_events['Event Type'].unique(), default=list(df_events['Event Type'].unique()))
        
        filtered_df = df_events[(df_events['Severity'].isin(selected_severity)) & (df_events['Event Type'].isin(selected_type))]
        
        def color_severity(val):
            color_map = {'Critical': 'darkred', 'High': 'red', 'Medium': 'orange', 'Low': 'darkkhaki', 'Info': 'blue'}
            color = color_map.get(val, '')
            return f'background-color: {color}; color: white' if val in ['Critical', 'High'] else f'background-color: {color}; color: black'

        try:
            styled_df = filtered_df.style.map(color_severity, subset=['Severity'])
        except AttributeError:
            styled_df = filtered_df.style.applymap(color_severity, subset=['Severity'])

        st.dataframe(styled_df, use_container_width=True, height=400)
        
        # Process Tree Section
        st.markdown("---")
        st.markdown("#### 🕸️ Process Tree (Execution Graph)")
        selected_alert_desc = st.selectbox("Select an incident to view its process tree:", [a.description for a in alerts])
        if selected_alert_desc:
            nodes, edges, metadata = build_process_tree(selected_alert_desc)
            config = Config(width="100%", height=400, directed=True, physics=True, hierarchical=True)
            
            tree_col, detail_col = st.columns([2, 1])
            with tree_col:
                clicked_node = agraph(nodes=nodes, edges=edges, config=config)
            with detail_col:
                st.markdown("##### 🔍 Forensic Artifacts")
                if clicked_node and clicked_node in metadata:
                    st.markdown(f"<div style='background-color:#161B22; padding:15px; border-radius:8px; border: 1px solid #30363D;'>", unsafe_allow_html=True)
                    for key, val in metadata[clicked_node].items():
                        st.markdown(f"<span style='color:#8B949E; font-size:0.9rem; font-weight:bold;'>{key}:</span><br><code style='color:#00F0FF; font-size:0.85rem; word-break: break-all; background-color: transparent;'>{val}</code>", unsafe_allow_html=True)
                        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                else:
                    st.info("Click on a node in the graph (left) to view its forensic details, command lines, and hashes.")
        
        # SOAR Section
        if user["role"] == "L2_Analyst":
            st.markdown("---")
            st.markdown("#### ⚡ Active Response (SOAR - Network Isolation)")
            
            threat_agents = df_events[df_events['Severity'].isin(['Critical', 'High'])]['Agent'].unique()
            if len(threat_agents) > 0:
                ac1, ac2, ac3 = st.columns([2, 1, 1])
                with ac1:
                    target_agent = st.selectbox("Machine to Isolate:", threat_agents)
                    match = re.search(r'\((.*?)\)', target_agent)
                    agent_id = match.group(1).strip() if match else None
                with ac2:
                    st.write("")
                    st.write("")
                    if st.button("🔴 Isolate Network", use_container_width=True, type="primary"):
                        if agent_id and connector.isolate_endpoint(agent_id=agent_id):
                            st.success(f"{target_agent} isolated successfully.")
                            st.balloons()
                        else:
                            st.error("API call failed.")
                with ac3:
                    st.write("")
                    st.write("")
                    if st.button("🟢 Remove Isolation", use_container_width=True):
                        if agent_id and connector.unisolate_endpoint(agent_id=agent_id):
                            st.success(f"{target_agent} reconnected to network.")
            else:
                st.info("No devices require critical intervention.")
    else:
        st.success("No active incidents found.")


elif menu_selection == "💻 Endpoints":
    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        def highlight_status(val):
            return 'color: #00FF00; font-weight: bold' if val == 'active' else 'color: #FF0000; font-weight: bold'
        try:
            st.dataframe(df_endpoints.style.map(highlight_status, subset=['status']), use_container_width=True)
        except AttributeError:
            st.dataframe(df_endpoints.style.applymap(highlight_status, subset=['status']), use_container_width=True)
    else:
        st.info("No endpoints found in the system.")


elif menu_selection == "🤖 SOC Analyst (AI)":
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "assistant", "content": f"Hello! I am the AI-powered security assistant for the XDR Platform. I'm here for log analysis, incident clarification, and SOAR commands."}]

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Analyze logs, list suspicious activities..."):
        st.chat_message("user").markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("assistant"):
            with st.spinner("⏳ Synchronizing with XDR database and running Gemini model..."):
                try:
                    from google import genai
                    alert_context = "Recent Incidents:\n" + "\n".join([f"- [{a.severity}] {a.incident_type} - Machine: {a.agent_name}" for a in alerts[:25]])
                    system_instructions = "You are a senior SOC analyst. Answer the user's question using professional cybersecurity terminology based on the provided log data."
                    
                    api_key = os.getenv("GEMINI_API_KEY")
                    if not api_key: raise ValueError("GEMINI_API_KEY not found.")
                        
                    client = genai.Client(api_key=api_key)
                    gemini_response = client.models.generate_content(model='gemini-2.5-flash', contents=f"{system_instructions}\n\n{alert_context}\n\nQuestion: {prompt}")
                    response = gemini_response.text
                except Exception as e:
                    response = f"**Error:** `{str(e)}`"
            st.markdown(response)
        st.session_state.messages.append({"role": "assistant", "content": response})


elif menu_selection == "🛡️ Vulnerabilities (Vulns)":
    if active_endpoints:
        agent_names = [f"{e['name']} ({e['id']})" for e in active_endpoints]
        target = st.selectbox("Select Machine to Scan:", agent_names)
        match = re.search(r'\((.*?)\)', target)
        if match:
            with st.spinner(f"Scanning CVE database for {target}..."):
                vulns = connector.get_vulnerabilities(agent_id=match.group(1).strip())
                if vulns:
                    st.warning(f"⚠️ {len(vulns)} vulnerabilities found!")
                    df_vulns = pd.DataFrame(vulns).rename(columns={"cve": "CVE ID", "severity": "Severity", "cvss_score": "CVSS", "software": "Software"})
                    def color_vuln(val):
                        return 'background-color: darkred; color: white' if val in ['Critical', 'High'] else ''
                    try:
                        st.dataframe(df_vulns.style.map(color_vuln, subset=['Severity']), use_container_width=True, height=500)
                    except:
                        st.dataframe(df_vulns.style.applymap(color_vuln, subset=['Severity']), use_container_width=True, height=500)
                else:
                    st.success("System is up to date. No vulnerabilities found.")


elif menu_selection == "🌐 Threat Intel (TIP)":
    with st.spinner("Analyzing IPs with VirusTotal and other intel engines..."):
        from core.threat_intel import enrich_ip
        extracted_ips = set(re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b').findall(" ".join([a.description for a in alerts])))
        
        m_ip = st.text_input("🔍 Query IP Manually:")
        if m_ip: extracted_ips.add(m_ip)
        
        if extracted_ips:
            data = [enrich_ip(ip) for ip in extracted_ips]
            df_intel = pd.DataFrame([{"IP": r["ip_address"], "Risk": r["score"], "Malicious": "🔴 YES" if r["malicious"] else "🟢 NO", "Country": r["country"]} for r in data])
            try:
                st.dataframe(df_intel.style.map(lambda v: 'background-color: darkred; color: white' if v>=8 else '', subset=['Risk']), use_container_width=True)
            except:
                st.dataframe(df_intel.style.applymap(lambda v: 'background-color: darkred; color: white' if v>=8 else '', subset=['Risk']), use_container_width=True)
        else:
            st.info("No suspicious external IPs found in alert details.")


elif menu_selection == "🌍 Attack Surface (ASM)":
    target_input = st.text_input("Target Domain / IP:", value="example-corp.com" if "Wazuh" in st.session_state.current_tenant else "test-domain.local")
    if st.button("🔍 Scan Attack Surface", type="primary"):
        with st.spinner("Running Nmap and Shodan simulation..."):
            from core.asm_scanner import analyze_attack_surface
            results = analyze_attack_surface(target_input)
            if results:
                df_asm = pd.DataFrame(results).rename(columns={"Port": "Port", "Servis": "Service", "Durum": "Status", "Risk": "Risk", "Zafiyet (CVE)": "Vulnerability (CVE)"})
                try:
                    st.dataframe(df_asm.style.map(lambda v: 'background-color: darkred; color: white' if v=='Kritik' else '', subset=['Risk']), use_container_width=True)
                except:
                    st.dataframe(df_asm.style.applymap(lambda v: 'background-color: darkred; color: white' if v=='Kritik' else '', subset=['Risk']), use_container_width=True)
            else:
                st.success("No vulnerable exposed services detected.")


elif menu_selection == "🕵️ Threat Hunting":
    sigma_input = st.text_area("Sigma Rule (YAML):", value="title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: ['-enc', 'Base64']\n  condition: selection", height=200)
    if st.button("⚡ Translate to Wazuh / Elastic Query", type="primary"):
        from core.sigma_translator import translate_sigma_to_wazuh
        res = translate_sigma_to_wazuh(sigma_input)
        if res.get("error"): st.error(res["error"])
        else:
            st.success("Success!")
            st.code(res["query"], language="bash")


elif menu_selection == "🔥 MITRE ATT&CK Heatmap":
    st.markdown("#### 🗺️ MITRE ATT&CK Coverage")
    st.markdown("<p style='color:#8B949E; font-size:0.95rem;'>This heatmap highlights the intensity of active threats mapped against the MITRE framework.</p>", unsafe_allow_html=True)
    
    matrix_df = generate_mitre_heatmap_data(alerts)
    
    fig = px.imshow(
        matrix_df, 
        text_auto=True, 
        aspect="auto",
        color_continuous_scale="Reds",
        labels=dict(x="Tactics", y="Techniques", color="Alert Count")
    )
    
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", 
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis_title="",
        yaxis_title="",
        font=dict(color="#8B949E"),
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)


elif menu_selection == "📋 SLA Reporting":
    c_rep1, c_rep2 = st.columns([2, 1])
    with c_rep1:
        report_period = st.selectbox("Period:", ["Last 24 Hours", "Last 7 Days"])
        report_author = st.text_input("Analyst:", value="L2 SOC Team")
    with c_rep2:
        st.write(""); st.write("")
        if st.button("📄 Synthesize Report", use_container_width=True, type="primary"):
            st.session_state.report_ready = True
            
    if st.session_state.get("report_ready"):
        st.success("Report generated. Please review the 'Visual Preview' below.")
        md = f"# SOC SLA Report - {st.session_state.current_tenant}\n\n**Period:** {report_period} | **Prepared By:** {report_author}\n\n- Active Devices: {len(active_endpoints)}\n- Total Incidents: {len(alerts)}\n"
        st.markdown(md)
        st.download_button("Download (.md)", data=md, file_name="report.md", mime="text/markdown")
