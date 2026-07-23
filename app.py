import os
import re
import json
import streamlit as st
import pandas as pd
from pyvis.network import Network
import streamlit.components.v1 as components
from neo4j import GraphDatabase
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()


def get_secret(key, default=""):
    """本機開發讀 .env，部署到 Streamlit Community Cloud 時改讀後台設定的 Secrets。"""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.environ.get(key, default)


GOOGLE_API_KEY = get_secret("GOOGLE_API_KEY")

RISK_COLORS = {
    "Critical": "#FF4B4B",
    "High": "#FFA500",
    "Medium": "#FFD84D",
    "Low": "#4B9CD3",
}

AI_SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "what": {"type": "string"},
        "harm": {"type": "string"},
        "action": {"type": "string"},
    },
    "required": ["what", "harm", "action"],
}


def generate_ai_summary(cve, cve_info, endpoints_text):
    """回傳固定結構 {what, harm, action}，畫面排版由 App 自己控制，
    不依賴模型每次輸出的文字格式，避免每次呼叫排版不一致。"""
    client = genai.Client(api_key=GOOGLE_API_KEY)
    prompt = f"""你是資安分析師，請針對以下弱點掃描結果，寫給非技術主管看的說明。
不要只是把漏洞描述翻譯成中文，而是要用你自己的理解重新解釋。請填寫三個欄位：

- what：用非技術人員能懂的比喻或白話，解釋這個弱點的成因（例如是什麼設定錯誤、過時軟體、還是驗證漏洞）。1-2 句話。
- harm：如果被入侵者利用，實際上可能發生什麼後果（例如：資料外洩、被植入勒索軟體、被當跳板攻擊其他系統、服務中斷等），
  要具體到這個弱點的攻擊情境，不要講空泛的「資安風險」。1-2 句話。
- action：根據風險等級與修補方案，給出優先順序建議。1 句話。

CVE: {cve}
名稱: {cve_info['Name']}
風險等級: {cve_info['Risk']}
CWE: {cve_info['CWE_Parsed']}
漏洞描述: {cve_info['Description']}
官方修補方案: {cve_info['Solution'] if pd.notna(cve_info['Solution']) else '無'}
受影響主機/Port:
{endpoints_text}
"""
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=AI_SUMMARY_SCHEMA,
    )
    last_error = None
    for model in ["gemini-flash-lite-latest", "gemma-4-26b-a4b-it"]:
        try:
            response = client.models.generate_content(model=model, contents=prompt, config=config)
            return json.loads(response.text)
        except Exception as e:
            last_error = e
            continue
    raise RuntimeError(f"所有候選模型皆呼叫失敗（可能額度用盡）：{last_error}")


def build_risk_graph(risk_group_df, risk):
    """針對單一風險等級畫一張 1-Depth 圖：CVE 連到 CWE 與所有受影響 Host。"""
    color = RISK_COLORS.get(risk, "#FF4B4B")
    net = Network(height="480px", width="100%", bgcolor="#222222", font_color="white")

    for cve, group in risk_group_df.groupby("CVE"):
        cve_info = group.iloc[0]
        net.add_node(cve, label=cve, color=color, size=30, title=f"{risk} 風險")

        if cve_info["CWE_Parsed"] != "N/A":
            net.add_node(cve_info["CWE_Parsed"], label=cve_info["CWE_Parsed"], color="#4B9CD3", size=20)
            net.add_edge(cve, cve_info["CWE_Parsed"], label="Problem_Type")

        for host in group["Host"].dropna().unique():
            host_label = f"Host: {host}"
            net.add_node(host_label, label=host_label, color="#50C878", size=20)
            net.add_edge(cve, host_label, label="AFFECTS")

    # 加大節點間距與邊標籤外框，避免圖太擠、文字疊在一起看不清楚
    net.set_options("""
    {
      "nodes": { "font": { "size": 16, "color": "#ffffff" } },
      "edges": {
        "font": {
          "size": 12,
          "color": "#ffffff",
          "align": "top",
          "strokeWidth": 4,
          "strokeColor": "#222222"
        },
        "smooth": { "type": "continuous" }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -12000,
          "centralGravity": 0.15,
          "springLength": 220,
          "springConstant": 0.03,
          "damping": 0.15
        },
        "stabilization": { "iterations": 200 }
      }
    }
    """)
    return net

# --- 頁面標題與佈局配置 ---
st.set_page_config(page_title="資安漏洞互動式圖譜系統", layout="wide")
st.title("🛡️ 弱點掃描 (Nessus) 互動分析與修補指引系統")

# --- 側邊欄：檔案上傳與 Neo4j 連線設定 ---
with st.sidebar:
    st.header("1. 資料來源")
    uploaded_file = st.file_uploader("上傳 Nessus CSV 檔案", type=["csv"])

    st.header("2. Neo4j 資料庫連線")
    neo4j_url = get_secret("NEO4J_URI")
    neo4j_user = get_secret("NEO4J_USER", "neo4j")
    neo4j_pwd = get_secret("NEO4J_PASSWORD")
    if neo4j_url and neo4j_pwd:
        st.success("已自動套用固定連線設定")
    else:
        st.warning("未偵測到連線設定（.env 或 Secrets）")

if uploaded_file is not None:
    # 讀取 CSV
    df = pd.read_csv(uploaded_file)

    # 解析 CWE 資訊 (從 XREF 提取)
    def extract_cwe(xref):
        if pd.isna(xref): return "N/A"
        cwes = [item.strip() for item in str(xref).split(',') if 'CWE' in item]
        return cwes[0] if cwes else "N/A"

    df['CWE_Parsed'] = df['XREF'].apply(extract_cwe)

    # 從 Nessus 的「OS Identification」插件輸出解析實際 OS 名稱，
    # 支援「Remote operating system : XXX」與「cpe:/o:vendor:product:version」兩種常見格式
    def parse_os_from_plugin_output(output):
        text = str(output)

        m = re.search(r'(?:Remote operating system|Operating System)\s*:\s*(.+)', text, re.IGNORECASE)
        if m and m.group(1).strip():
            return m.group(1).strip()

        m = re.search(r'cpe:/o:([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?', text)
        if m:
            vendor, product, version = m.group(1), m.group(2), m.group(3)
            parts = [vendor.replace('_', ' ').title(), product.replace('_', ' ').title()]
            if version:
                parts.append(version)
            return ' '.join(parts)

        for line in text.strip().splitlines():
            line = line.strip()
            if line and not line.endswith(':'):
                return line

        return "Unknown"

    # 嘗試取得每台主機的作業系統資訊：優先讀取現成欄位，
    # 否則從 Nessus 的「OS Identification」類插件輸出解析
    def build_os_lookup(full_df):
        for col in ["OS", "Operating System", "operating_system", "os"]:
            if col in full_df.columns:
                return full_df.dropna(subset=[col]).groupby("Host")[col].first().to_dict()

        if "Plugin Output" in full_df.columns and "Name" in full_df.columns:
            os_rows = full_df[full_df["Name"].astype(str).str.contains(
                "OS Identification|Common Platform Enumeration", case=False, na=False)]
            lookup = {}
            for _, row in os_rows.iterrows():
                output = row.get("Plugin Output")
                if pd.notna(output):
                    lookup[row["Host"]] = parse_os_from_plugin_output(output)
            return lookup

        return {}

    os_lookup = build_os_lookup(df)

    # 只取出包含 CVE 的有效漏洞資料
    cve_df = df[df['CVE'].notna()].copy()

    # --- 篩選控制區 ---
    st.subheader("🔍 漏洞條件篩選")

    # 風險等級複選：符合選取風險等級的 CVE 全部納入分析，不再限制單一目標
    risk_options = ['Critical', 'High', 'Medium', 'Low']
    selected_risks = st.multiselect("選擇風險等級 (Severity)：", risk_options, default=['Critical', 'High'])

    # 根據風險條件過濾
    filtered_df = cve_df[cve_df['Risk'].isin(selected_risks)]
    matched_cves = filtered_df['CVE'].unique().tolist()
    st.caption(f"符合條件的 CVE 共 {len(matched_cves)} 個，將全數納入圖譜與修補指引。")

    # --- 執行/搜尋按鈕 ---
    # 用 session_state 記住「已產生」狀態，避免點擊下方 AI 按鈕造成整頁重跑時，
    # 因為 st.button 不會持續回傳 True 而讓這個區塊整個消失
    if st.button("🚀 生成單層拓撲圖與修補指引", type="primary"):
        st.session_state["analysis_triggered"] = True
        st.session_state["analysis_risks"] = selected_risks

    if st.session_state.get("analysis_triggered") and st.session_state.get("analysis_risks") == selected_risks:
        st.divider()

        if filtered_df.empty:
            st.warning("目前選取的風險等級沒有符合的 CVE，請調整篩選條件。")
        else:
            # --- 依風險等級切成區塊：每個區塊各自一張圖 + 一區文字說明 ---
            for risk in risk_options:
                risk_group_df = filtered_df[filtered_df['Risk'] == risk]
                if risk_group_df.empty:
                    continue

                risk_cve_count = risk_group_df['CVE'].nunique()
                st.subheader(f"🔺 風險等級：{risk}（共 {risk_cve_count} 個 CVE）")

                net = build_risk_graph(risk_group_df, risk)
                net.save_graph("temp_graph.html")
                with open("temp_graph.html", 'r', encoding='utf-8') as f:
                    html_content = f.read()
                components.html(html_content, height=500)

                for cve, group in risk_group_df.groupby('CVE'):
                    cve_info = group.iloc[0]
                    with st.expander(f"{cve} — {cve_info['Name']}"):
                        t1, t2, t3 = st.tabs(["📌 問題概述", "🛠️ 官方修補方案 (Solution)", "🔗 關聯 CWE/CVE 與參考來源"])

                        with t1:
                            st.markdown(f"**漏洞名稱**：{cve_info['Name']}")
                            st.markdown(f"**風險等級**：`{cve_info['Risk']}`")
                            st.info(cve_info['Description'])

                            st.divider()
                            summary_key = f"ai_summary_{cve}"
                            if st.button("🤖 產生 AI 白話摘要", key=f"ai_btn_{cve}"):
                                if not GOOGLE_API_KEY:
                                    st.error("尚未設定 GOOGLE_API_KEY，請至 .env 補上金鑰後重新啟動 App。")
                                else:
                                    with st.spinner("AI 分析中..."):
                                        try:
                                            endpoints = group[['Host', 'Port', 'Protocol']].drop_duplicates()
                                            endpoints_text = "\n".join(
                                                f"- {r.Host}:{r.Port} ({r.Protocol})" for r in endpoints.itertuples()
                                            )
                                            st.session_state[summary_key] = generate_ai_summary(cve, cve_info, endpoints_text)
                                        except Exception as e:
                                            st.error(f"AI 摘要產生失敗：{e}")

                            if summary_key in st.session_state:
                                summary = st.session_state[summary_key]
                                st.markdown("**🤖 AI 白話摘要**")
                                st.markdown(f"**這是什麼？**\n\n{summary['what']}")
                                st.markdown(f"**可能造成的危害**\n\n{summary['harm']}")
                                st.markdown(f"**建議處理方式**\n\n{summary['action']}")

                        with t2:
                            st.success(cve_info['Solution'] if pd.notna(cve_info['Solution']) else "無明確修補方案，請參考官方規範。")

                        with t3:
                            st.markdown(f"* **對應 CWE 分類**：`{cve_info['CWE_Parsed']}`")
                            endpoints = group[['Host', 'Port', 'Protocol']].drop_duplicates()
                            endpoint_lines = "\n".join(
                                f"  * `{r.Host}:{r.Port}` ({r.Protocol})" for r in endpoints.itertuples()
                            )
                            st.markdown(f"* **受影響主機 IP / Port**（共 {len(endpoints)} 筆）：\n{endpoint_lines}")
                            if pd.notna(cve_info['See Also']):
                                st.markdown(f"* **官方參考通報**：\n{cve_info['See Also']}")

                st.divider()

            # --- 觸發統計區塊：IP / Port / OS（整份篩選結果只出現一次）---
            st.subheader("📈 本次觸發統計")

            s1, s2, s3 = st.columns(3)

            with s1:
                st.markdown("**觸發的來源 IP (Host)**")
                ip_counts = filtered_df['Host'].value_counts().rename_axis('Host').reset_index(name='觸發次數')
                st.dataframe(ip_counts, hide_index=True, use_container_width=True)

            with s2:
                st.markdown("**觸發的 Port（含觸發的風險等級）**")
                port_counts = filtered_df['Port'].value_counts().rename_axis('Port').reset_index(name='觸發次數')
                port_risk = (
                    filtered_df.groupby('Port')['Risk']
                    .apply(lambda s: ', '.join(sorted(set(s), key=lambda r: risk_options.index(r))))
                    .reset_index(name='觸發的風險等級')
                )
                port_summary = port_counts.merge(port_risk, on='Port')
                st.dataframe(port_summary, hide_index=True, use_container_width=True)

            with s3:
                st.markdown("**受影響主機作業系統 (OS)**")
                affected_hosts = filtered_df['Host'].dropna().unique().tolist()
                if os_lookup:
                    os_rows = [{"Host": h, "OS": os_lookup.get(h, "未知")} for h in affected_hosts]
                    os_df = pd.DataFrame(os_rows)
                    os_summary = os_df['OS'].value_counts().rename_axis('OS').reset_index(name='主機數')
                    st.dataframe(os_summary, hide_index=True, use_container_width=True)
                else:
                    st.caption("此 Nessus CSV 未包含 OS 欄位，也找不到 OS Identification 插件輸出，無法統計作業系統。")

else:
    st.info("👈 請先於左側邊欄上傳您的 Nessus CSV 檔案以開始分析。")
