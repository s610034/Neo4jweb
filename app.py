import os
import re
import json
import time
import html
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import streamlit as st
import pandas as pd
from pyvis.network import Network
import streamlit.components.v1 as components
from neo4j import GraphDatabase
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()


def cwe_url(cwe_id):
    m = re.search(r"\d+", cwe_id or "")
    return f"https://cwe.mitre.org/data/definitions/{m.group()}.html" if m else None


def capec_url(capec_id):
    m = re.search(r"\d+", capec_id or "")
    return f"https://capec.mitre.org/data/definitions/{m.group()}.html" if m else None


def attack_technique_id(technique):
    """ATT&CK 技術 ID 在本機資料跟 Neo4j 查回來的格式不一致（有沒有帶 'T' 開頭、
    有沒有獨立欄位），統一從 id 或 name 裡解析出標準格式，解析不出來就回傳 None。"""
    raw_id = technique.get("id")
    if raw_id:
        return raw_id if str(raw_id).upper().startswith("T") else f"T{raw_id}"
    m = re.match(r"(T\d+(?:\.\d+)?)", technique.get("name") or "")
    return m.group(1) if m else None


def attack_url(technique_id):
    if not technique_id:
        return None
    parts = technique_id.split(".")
    base = parts[0]
    return f"https://attack.mitre.org/techniques/{base}/{parts[1]}/" if len(parts) > 1 else f"https://attack.mitre.org/techniques/{base}/"


def get_secret(key, default=""):
    """本機開發讀 .env，部署到 Streamlit Community Cloud 時改讀後台設定的 Secrets。"""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.environ.get(key, default)


GOOGLE_API_KEY = get_secret("GOOGLE_API_KEY")
OPENCVE_TOKEN = get_secret("OPENCVE_TOKEN")
GROQ_API_KEY = get_secret("GROQ_API_KEY")

KG_PATH = os.path.join(os.path.dirname(__file__), "data", "cwe_knowledge_graph.json")


@st.cache_data(show_spinner=False)
def load_cwe_knowledge_graph():
    """CWE/CAPEC/ATT&CK 知識圖譜，離線從 MITRE 官方資料建置、隨程式碼一起部署，
    不依賴任何即時資料庫連線（本機、Streamlit Cloud 都能直接讀）。"""
    try:
        with open(KG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"cwe": {}, "capec": {}}


def get_exploit_frameworks(cve_info):
    """Nessus 原始掃描結果會標記這個漏洞在 Metasploit / Core Impact / CANVAS
    這幾套滲透測試框架裡有沒有現成的攻擊模組，值是字串 'true'。
    這是比 EPSS/KEV 更直接的「能不能被輕易攻擊」訊號，且不需要額外查詢外部 API。"""
    frameworks = []
    for column in ["Metasploit", "Core Impact", "CANVAS"]:
        value = cve_info.get(column)
        if pd.notna(value) and str(value).strip().lower() == "true":
            frameworks.append(column)
    return frameworks


def normalize_cwe_id(raw_cwe):
    """Nessus CSV 的 XREF 常寫成 'CWE:79'，NVD/知識圖譜統一用 'CWE-79'，這裡做格式對齊。"""
    if not raw_cwe or raw_cwe == "N/A":
        return None
    m = re.search(r"\d+", raw_cwe)
    return f"CWE-{m.group()}" if m else None


def get_related_weakness_context_offline(cwe_id):
    """依 CWE 編號從本機知識圖譜找出：CWE 說明、相關弱點（父子/同儕分類）、
    對應的 CAPEC 攻擊手法與 ATT&CK 技術。找不到就回傳 None。"""
    kg = load_cwe_knowledge_graph()
    cwe_entry = kg["cwe"].get(cwe_id)
    if not cwe_entry:
        return None

    related_weaknesses = [
        {
            "cwe_id": rw["cwe_id"],
            "nature": rw["nature"],
            "name": kg["cwe"].get(rw["cwe_id"], {}).get("name", ""),
        }
        for rw in cwe_entry["related_weaknesses"]
    ]

    attack_patterns = []
    all_techniques = {}
    for capec_id in cwe_entry["related_capec"]:
        capec_entry = kg["capec"].get(capec_id)
        if capec_entry:
            attack_patterns.append({
                "capec_id": capec_id,
                "name": capec_entry["name"],
                "severity": capec_entry["severity"],
                "attack_techniques": capec_entry["attack_techniques"],
            })
            for t in capec_entry["attack_techniques"]:
                if t.get("id"):
                    all_techniques[t["id"]] = t["name"]

    return {
        "source": "本機 MITRE 知識圖譜",
        "cwe_id": cwe_id,
        "name": cwe_entry["name"],
        "description": cwe_entry["description"],
        "related_weaknesses": related_weaknesses,
        "attack_patterns": attack_patterns,
        "attack_techniques": [{"id": k, "name": v} for k, v in all_techniques.items()],
    }


TUNNEL_LOCAL_PORT = 17687


def get_cloudflared_binary():
    """找到可用的 cloudflared 執行檔：本機開發環境通常已透過 brew 裝好、在 PATH 裡；
    Streamlit Community Cloud 這種雲端容器沒有，改成第一次啟動時下載官方單一執行檔，
    存到暫存目錄重複使用，不需要 apt/套件管理員權限。"""
    import shutil

    which_path = shutil.which("cloudflared")
    if which_path:
        return which_path

    bin_dir = "/tmp/cloudflared_bin"
    bin_path = os.path.join(bin_dir, "cloudflared")
    if os.path.exists(bin_path):
        return bin_path

    os.makedirs(bin_dir, exist_ok=True)
    url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    with open(bin_path, "wb") as f:
        f.write(resp.content)
    os.chmod(bin_path, 0o755)
    return bin_path


@st.cache_resource(show_spinner=False)
def ensure_cloudflare_tunnel():
    """在背景啟動 cloudflared access tcp，把共用 Neo4j 的 Bolt 協定用 WebSocket 包裝
    後轉發到本機 port，藉此繞過 Cloudflare 代理對原生 Bolt 協定的封鎖。
    用 cache_resource 讓這個 subprocess 整個 App 生命週期只啟動一次。
    成功回傳本機轉發後的 bolt URI；任何一步失敗都回傳 None，由呼叫端 fallback。"""
    import subprocess
    import socket
    import time

    uri = get_secret("NEO4J_URI")
    if not uri:
        return None

    hostname = re.sub(r"^[a-z+]+://", "", uri).split(":")[0].split("/")[0]
    if not hostname:
        return None

    try:
        binary = get_cloudflared_binary()
    except Exception:
        return None

    try:
        subprocess.Popen(
            [binary, "access", "tcp",
             "--hostname", hostname,
             "--url", f"127.0.0.1:{TUNNEL_LOCAL_PORT}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None

    # 等通道建立起來，最多等 10 秒；一旦本機 port 開始接受連線就視為就緒
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", TUNNEL_LOCAL_PORT), timeout=0.5):
                return f"bolt://127.0.0.1:{TUNNEL_LOCAL_PORT}"
        except OSError:
            time.sleep(0.5)

    return None


@st.cache_resource(show_spinner=False)
def get_neo4j_driver():
    """建立共用 Neo4j 的連線（團隊協作維護的資料庫）。連不上就回傳 None，
    讓呼叫端自動退回本機知識圖譜，不會讓整個 App 卡住或報錯。
    用 cache_resource 讓整個 session 只嘗試連線一次，避免每張卡片都重新等逾時。
    優先透過 cloudflared 通道連線（繞過協定封鎖），通道建立失敗才退而求其次
    直接嘗試原始 URI（已知在多數環境會被 Cloudflare 擋下，留著只是保底）。"""
    user = get_secret("NEO4J_USER", "neo4j")
    pwd = get_secret("NEO4J_PASSWORD")
    if not pwd:
        return None

    tunnel_uri = ensure_cloudflare_tunnel()
    candidate_uris = [tunnel_uri] if tunnel_uri else []
    candidate_uris.append(get_secret("NEO4J_URI"))

    for uri in candidate_uris:
        if not uri:
            continue
        try:
            driver = GraphDatabase.driver(uri, auth=(user, pwd), connection_timeout=5)
            driver.verify_connectivity()
            return driver
        except Exception:
            continue

    return None


def get_related_weakness_context_online(cwe_id):
    """查詢團隊共用的 Neo4j，取得跟本機知識圖譜相同結構的資料。
    Neo4j 連不上、查無資料、或查詢過程出錯，都回傳 None（由呼叫端 fallback）。"""
    driver = get_neo4j_driver()
    if driver is None:
        return None

    query = """
    MATCH (c:CWE {Name: $cwe_id})
    OPTIONAL MATCH (c)-[rel:Related_Weakness]-(rw:CWE)
    OPTIONAL MATCH (c)-[:RelatedAttackPattern]->(cap:CAPEC)
    OPTIONAL MATCH (cap)-[:Mapped_Attack]->(atk:ATTACK)
    RETURN c.Description AS description,
           c.Extended_Name AS cwe_name,
           collect(DISTINCT {cwe_id: rw.Name, name: rw.Extended_Name, nature: rel.Nature}) AS related_weaknesses,
           collect(DISTINCT {capec_id: cap.Name, name: cap.ExtendedName, severity: cap.Typical_Severity}) AS attack_patterns,
           collect(DISTINCT atk.Name) AS attack_techniques
    LIMIT 1
    """
    try:
        with driver.session() as session:
            result = session.run(query, cwe_id=cwe_id)
            record = result.single()
            if record is None or record["description"] is None:
                return None

            related_weaknesses = [
                rw for rw in record["related_weaknesses"] if rw.get("cwe_id")
            ]
            attack_patterns = [
                {**ap, "attack_techniques": []}
                for ap in record["attack_patterns"] if ap.get("capec_id")
            ]
            # Neo4j 查詢沒辦法細分「哪個 CAPEC 對應哪個 ATT&CK 技術」，
            # 只能拿到整個 CWE 底下的技術總表，所以另外放在 attack_techniques 彙總欄位
            attack_techniques = [
                {"id": None, "name": name} for name in record["attack_techniques"] if name
            ]

            return {
                "source": "Neo4j（團隊共用協作資料庫）",
                "cwe_id": cwe_id,
                "name": record["cwe_name"] or cwe_id,
                "description": record["description"] or "",
                "related_weaknesses": related_weaknesses,
                "attack_patterns": attack_patterns,
                "attack_techniques": attack_techniques,
            }
    except Exception:
        return None


def get_related_weakness_context(cwe_id):
    """優先查詢共用 Neo4j（跟同事協作用的最新資料），查不到才退回本機的 MITRE 靜態知識圖譜。"""
    return get_related_weakness_context_online(cwe_id) or get_related_weakness_context_offline(cwe_id)


def fetch_cve_from_nvd(cve_id):
    """查詢 NVD 官方 CVE 資料庫，取得比 Nessus CSV 更完整的描述、CVSS 向量、CWE 與參考連結。"""
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        timeout=8,
    )
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    description = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")

    cvss_vector, cvss_score, cvss_severity = "", None, ""
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric = cve.get("metrics", {}).get(key)
        if metric:
            m = metric[0]
            cvss_vector = m["cvssData"].get("vectorString", "")
            cvss_score = m["cvssData"].get("baseScore")
            cvss_severity = m.get("baseSeverity", m["cvssData"].get("baseSeverity", ""))
            break

    # NVD 對沒有分類資訊的漏洞會回傳 NVD-CWE-noinfo / NVD-CWE-Other 這種內部佔位標籤，
    # 不是真正的 CWE 編號，過濾掉避免顯示無意義的原始標籤或產生壞掉的連結
    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("lang") == "en" and re.match(r"^CWE-\d+$", d["value"])
    })
    references = [r["url"] for r in cve.get("references", [])][:5]

    return {
        "source": "NVD",
        "description": description,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwes": cwes,
        "references": references,
    }


def fetch_cve_from_opencve(cve_id):
    """OpenCVE 備用來源，需要 Organization API Token（OPENCVE_TOKEN）才會啟用。"""
    if not OPENCVE_TOKEN:
        return None

    resp = requests.get(
        f"https://app.opencve.io/api/v2/cves/{cve_id}",
        headers={"Authorization": f"Bearer {OPENCVE_TOKEN}"},
        timeout=8,
    )
    resp.raise_for_status()
    data = resp.json()
    cvss = data.get("cvss") if isinstance(data.get("cvss"), dict) else {}
    return {
        "source": "OpenCVE",
        "description": data.get("description", ""),
        "cvss_vector": cvss.get("vector", ""),
        "cvss_score": cvss.get("score"),
        "cvss_severity": "",
        "cwes": data.get("cwes", []),
        "references": [r.get("url", r) if isinstance(r, dict) else r for r in data.get("references", [])][:5],
    }


def fetch_epss(cve_id):
    """FIRST.org EPSS：這個 CVE 未來 30 天內被實際攻擊利用的機率，免驗證。"""
    resp = requests.get(
        "https://api.first.org/data/v1/epss",
        params={"cve": cve_id},
        timeout=8,
    )
    resp.raise_for_status()
    rows = resp.json().get("data", [])
    if not rows:
        return None
    row = rows[0]
    return {
        "score": float(row["epss"]),
        "percentile": float(row["percentile"]),
    }


@st.cache_data(ttl=86400, show_spinner=False)
def fetch_cisa_kev_catalog():
    """CISA 已知遭利用漏洞目錄，全量下載，一天快取一次，避免每次點擊都抓 1.5MB。"""
    resp = requests.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=15,
    )
    resp.raise_for_status()
    entries = resp.json().get("vulnerabilities", [])
    return {e["cveID"]: e for e in entries}


def fetch_kev_status(cve_id):
    try:
        catalog = fetch_cisa_kev_catalog()
    except Exception:
        return None
    entry = catalog.get(cve_id)
    if not entry:
        return {"listed": False}
    return {
        "listed": True,
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
        "required_action": entry.get("requiredAction", ""),
    }


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_cve_enrichment(cve_id):
    """依序嘗試 NVD、OpenCVE 取得基本資料，並疊加 EPSS 機率分數與 CISA KEV 是否已遭利用。
    NVD/OpenCVE、EPSS、KEV 三個查詢彼此不互相依賴，平行呼叫以縮短總等待時間
    （雲端環境每個外部 API 延遲都比本機高，序列呼叫的等待時間會直接疊加）。"""
    with ThreadPoolExecutor(max_workers=3) as executor:
        base_future = executor.submit(_fetch_cve_base, cve_id)
        epss_future = executor.submit(fetch_epss, cve_id)
        kev_future = executor.submit(fetch_kev_status, cve_id)

        enrichment = base_future.result()
        if enrichment is None:
            return None

        try:
            enrichment["epss"] = epss_future.result()
        except Exception:
            enrichment["epss"] = None

        try:
            enrichment["kev"] = kev_future.result()
        except Exception:
            enrichment["kev"] = None

    return enrichment


def _fetch_cve_base(cve_id):
    for fetcher in (fetch_cve_from_nvd, fetch_cve_from_opencve):
        try:
            result = fetcher(cve_id)
            if result:
                return result
        except Exception:
            continue
    return None

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
        "reference": {"type": "string"},
        "related": {"type": "string"},
        "description_zh": {"type": "string"},
        "solution_zh": {"type": "string"},
    },
    "required": ["what", "harm", "action", "reference", "related", "description_zh", "solution_zh"],
}

AI_SUMMARY_KEYS = ("what", "harm", "action", "reference", "related", "description_zh", "solution_zh")


def _validate_summary_dict(data):
    """Groq 的 json_object 模式只保證語法合法的 JSON，不保證欄位符合我們要的結構，
    這裡補一層檢查，缺欄位就當作這次呼叫失敗，讓賽跑機制换下一個候選。"""
    if not isinstance(data, dict) or any(k not in data for k in AI_SUMMARY_KEYS):
        raise ValueError(f"Groq 回傳的 JSON 缺少必要欄位：{data}")
    return data


def call_groq_model(prompt, model="llama-3.3-70b-versatile"):
    """Groq 是跟 Google 完全獨立的公司/基礎設施，用免費、速度很快的 Llama 模型
    當第三個賽跑候選，避免 Gemini/Gemma 同時壅塞時完全沒有備援可用。"""
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
        json={
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "你只回傳一個合法的 JSON 物件，且必須包含 what、harm、action、reference、related、"
                        "description_zh、solution_zh 七個字串欄位，不要有其他文字、不要用 markdown 程式碼區塊包起來。"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        },
        timeout=25,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return json.loads(content)


def generate_ai_summary(cve, cve_info, endpoints_text, enrichment=None, weakness_context=None, related_cves=None):
    """回傳固定結構 {what, harm, action, reference, related}，畫面排版由 App 自己控制，
    不依賴模型每次輸出的文字格式，避免每次呼叫排版不一致。
    enrichment 是從 NVD/OpenCVE 查到的官方資料；weakness_context 是 CWE/CAPEC/ATT&CK 知識圖譜資料；
    related_cves 是這次掃描裡其他共用同一個 CWE 的漏洞，三者都能補足 Nessus CSV 描述過於精簡的問題。"""
    client = genai.Client(api_key=GOOGLE_API_KEY)

    enrichment_text = "（未取得官方 CVE 資料庫額外資訊，僅根據 Nessus 掃描結果分析）"
    if enrichment:
        epss = enrichment.get("epss")
        epss_text = (
            f"{epss['score']*100:.1f}%（贏過 {epss['percentile']*100:.0f}% 的 CVE，代表未來 30 天內被實際攻擊利用的機率）"
            if epss else "無資料"
        )
        kev = enrichment.get("kev")
        if kev and kev.get("listed"):
            kev_text = (
                f"是！已列入 CISA 已知遭利用漏洞目錄（加入日期 {kev.get('date_added', '無')}，"
                f"要求修補期限 {kev.get('due_date', '無')}，勒索軟體使用情況：{kev.get('ransomware_use', '無')}）"
            )
        elif kev is not None:
            kev_text = "否，目前不在 CISA 已知遭利用漏洞目錄中"
        else:
            kev_text = "無資料"

        enrichment_text = f"""資料來源：{enrichment['source']}
官方完整描述：{enrichment['description'] or '無'}
CVSS 向量：{enrichment['cvss_vector'] or '無'}（分數：{enrichment['cvss_score']}，等級：{enrichment['cvss_severity'] or '無'}）
關聯 CWE：{', '.join(enrichment['cwes']) if enrichment['cwes'] else '無'}
EPSS 被實際利用機率：{epss_text}
CISA KEV 是否已知遭利用：{kev_text}
參考連結：{', '.join(enrichment['references']) if enrichment['references'] else '無'}"""

    weakness_text = "（未取得 CWE 知識圖譜資料）"
    if weakness_context:
        rw_text = "、".join(
            f"{rw['name']}（{rw['cwe_id']}，關係：{rw['nature']}）" for rw in weakness_context["related_weaknesses"]
        ) or "無"
        capec_lines = []
        for ap in weakness_context["attack_patterns"]:
            techniques = "、".join(f"{t['name']}（{t['id']}）" for t in ap["attack_techniques"]) or "無對應 ATT&CK 技術"
            capec_lines.append(f"{ap['name']}（{ap['capec_id']}，嚴重程度：{ap['severity'] or '未評級'}）→ {techniques}")
        overall_techniques = "、".join(
            t["name"] for t in weakness_context.get("attack_techniques", [])
        ) or "無"
        weakness_text = f"""CWE 分類：{weakness_context['cwe_id']} {weakness_context['name']}
CWE 官方說明：{weakness_context['description'][:300]}
相關/父子弱點分類：{rw_text}
對應的 CAPEC 攻擊手法與 ATT&CK 技術：
{chr(10).join(capec_lines) if capec_lines else '無'}
彙總 ATT&CK 技術：{overall_techniques}"""

    related_text = "（這次掃描中沒有其他漏洞共用同一個 CWE 分類）"
    if related_cves:
        related_text = "、".join(related_cves)

    prompt = f"""你是資安分析師，請針對以下弱點掃描結果，寫給非技術主管看的說明，並額外提供官方原文的中文翻譯。
請填寫七個欄位，分成兩組，兩組的寫法要求完全不同：

【第一組：what/harm/action/reference/related，這五個欄位要用你自己的理解重新解釋，不是翻譯】
必須實際引用下方「官方 CVE 資料庫補充資訊」的具體數據（例如 CVSS 分數、EPSS 機率、是否列入 CISA KEV），
不能只是背景參考卻完全不提到。

- what：用非技術人員能懂的比喻或白話，解釋這個弱點的成因（例如是什麼設定錯誤、過時軟體、還是驗證漏洞）。1-2 句話。
- harm：如果被入侵者利用，實際上可能發生什麼後果（例如：資料外洩、被植入勒索軟體、被當跳板攻擊其他系統、服務中斷等），
  要具體到這個弱點的攻擊情境，不要講空泛的「資安風險」。1-2 句話。
- action：根據風險等級、CVSS 分數、EPSS 機率、是否已被 CISA 列為已知遭利用、是否有現成攻擊模組，給出優先順序建議
  （如果已列入 CISA KEV 或有現成攻擊模組如 Metasploit，要明確指出這代表攻擊門檻很低、隨時可能被利用，應優先於其他同等級但沒有這些條件的漏洞）。1 句話。
- reference：明確引用官方 CVE 資料庫的具體數據來佐證，例如「根據 NVD，此漏洞 CVSS 分數為 9.1（Critical），EPSS 機率 99.9%，
  且已列入 CISA KEV」。如果下方沒有取得官方資料（顯示「未取得官方 CVE 資料庫額外資訊」），就直接寫
  「本次分析僅根據 Nessus 掃描結果，未查得官方 CVE 資料庫資訊」。1 句話。
- related：說明這個弱點分類常見的攻擊手法（引用下方 CAPEC/ATT&CK 資料），以及如果這次掃描裡還有其他漏洞屬於同一個
  CWE 分類，要指出這代表環境中存在系統性、重複出現的弱點模式，不是單一個案，修補時應該一併檢討根本原因
  （例如是不是共用同一套過時框架、同一種開發習慣）。如果都沒有相關資料，就寫「未查得相關攻擊手法或同類漏洞資料」。1-2 句話。
【第二組：description_zh/solution_zh，這兩個欄位「只能」是逐字直譯，禁止用你自己的理解改寫、禁止摘要、
禁止省略，輸出**必須全部是繁體中文**（專有名詞如協定名稱、產品名稱、CVE/CWE 編號可保留英文原文，
其餘一個英文單字都不能留），這兩個欄位絕對不能直接複製貼上英文原文】

- description_zh：把下方「Nessus 漏洞描述」翻譯成繁體中文，一字不漏地逐句直譯，不是摘要也不是重新詮釋。
- solution_zh：把下方「官方修補方案」翻譯成繁體中文，一字不漏地逐句直譯。如果官方修補方案是「無」，這裡也填「無」。

CVE: {cve}
名稱: {cve_info['Name']}
風險等級: {cve_info['Risk']}
CWE: {cve_info['CWE_Parsed']}
Nessus 漏洞描述: {cve_info['Description']}
官方修補方案: {cve_info['Solution'] if pd.notna(cve_info['Solution']) else '無'}
Nessus 標記的現成攻擊模組: {', '.join(get_exploit_frameworks(cve_info)) or '無'}
受影響主機/Port:
{endpoints_text}

官方 CVE 資料庫補充資訊：
{enrichment_text}

CWE/CAPEC/ATT&CK 知識圖譜補充資訊：
{weakness_text}

這次掃描中同樣屬於 {cve_info['CWE_Parsed']} 分類的其他漏洞：
{related_text}
"""
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=AI_SUMMARY_SCHEMA,
        http_options=types.HttpOptions(timeout=30000),
    )

    # 多個候選模型同時發送請求、誰先成功回應就用誰，而不是「A 失敗才試 B」的序列方式。
    # 特意混用不同公司的服務（Google 的 Gemini/Gemma + Groq 的 Llama）而不是同一家的兩個模型，
    # 這樣單一供應商整體壅塞時，還有另一家完全獨立的基礎設施可以頂上。
    executor = ThreadPoolExecutor(max_workers=3)
    unwrap_by_future = {}

    for model in ["gemini-flash-lite-latest", "gemma-4-26b-a4b-it"]:
        future = executor.submit(client.models.generate_content, model=model, contents=prompt, config=config)
        unwrap_by_future[future] = lambda f: json.loads(f.result().text)

    if GROQ_API_KEY:
        groq_future = executor.submit(call_groq_model, prompt)
        unwrap_by_future[groq_future] = lambda f: _validate_summary_dict(f.result())

    last_error = None
    try:
        for future in as_completed(unwrap_by_future):
            try:
                return unwrap_by_future[future](future)
            except Exception as e:
                last_error = e
                continue
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

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


def build_cve_relation_graph(cve, enrichment, weakness_context):
    """針對單一 CVE，畫出「CVE → CWE → 相關弱點/CAPEC 攻擊手法 → ATT&CK 技術」的拓樸圖，
    資料完全來自官方來源（NVD 的 enrichment ＋ CWE/CAPEC/ATT&CK 知識圖譜），
    不是隨機示意，是這筆 CVE 實際查到的官方關聯。"""
    net = Network(height="420px", width="100%", bgcolor="#222222", font_color="white")
    net.add_node(cve, label=cve, color="#FF4B4B", size=30, title="核心 CVE")

    cwe_ids = list(enrichment.get("cwes") or [])
    if weakness_context and weakness_context["cwe_id"] not in cwe_ids:
        cwe_ids.append(weakness_context["cwe_id"])

    for cwe_id in cwe_ids:
        cwe_label = weakness_context["name"] if (weakness_context and weakness_context["cwe_id"] == cwe_id) else cwe_id
        net.add_node(cwe_id, label=cwe_id, title=cwe_label, color="#4B9CD3", size=22)
        net.add_edge(cve, cwe_id, label="Problem_Type")

    if weakness_context:
        primary_cwe = weakness_context["cwe_id"]

        for rw in weakness_context["related_weaknesses"][:6]:
            net.add_node(rw["cwe_id"], label=rw["cwe_id"], title=rw["name"], color="#7FB3E8", size=16)
            net.add_edge(primary_cwe, rw["cwe_id"], label=rw["nature"])

        for ap in weakness_context["attack_patterns"][:6]:
            net.add_node(ap["capec_id"], label=ap["capec_id"], title=ap["name"], color="#FFA500", size=18)
            net.add_edge(primary_cwe, ap["capec_id"], label="RelatedAttackPattern")
            for t in ap["attack_techniques"][:3]:
                net.add_node(t["id"] or t["name"], label=t["id"] or t["name"], title=t["name"], color="#B266FF", size=14)
                net.add_edge(ap["capec_id"], t["id"] or t["name"], label="Mapped_Attack")

        # 線上查詢查不到「哪個 CAPEC 對應哪個 ATT&CK」，只有彙總技術清單時，
        # 直接掛在主要 CWE 底下，至少讓攻擊手法的脈絡看得到
        if weakness_context.get("attack_techniques") and not any(
            ap["attack_techniques"] for ap in weakness_context["attack_patterns"]
        ):
            for t in weakness_context["attack_techniques"][:6]:
                node_id = t["id"] or t["name"]
                net.add_node(node_id, label=node_id, title=t["name"], color="#B266FF", size=14)
                net.add_edge(primary_cwe, node_id, label="Mapped_Attack")

    net.set_options("""
    {
      "nodes": { "font": { "size": 14, "color": "#ffffff" } },
      "edges": {
        "font": {
          "size": 11,
          "color": "#ffffff",
          "align": "top",
          "strokeWidth": 4,
          "strokeColor": "#222222"
        },
        "smooth": { "type": "continuous" }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -10000,
          "centralGravity": 0.2,
          "springLength": 180,
          "springConstant": 0.03,
          "damping": 0.15
        },
        "stabilization": { "iterations": 200 }
      }
    }
    """)
    return net


RISK_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
# 固定的狀態色盤（critical/serious/warning/good），跟一般分類色刻意做區隔、
# 已通過色盲安全驗證，不隨主題改變。文字顏色依每個底色分別挑白字或深字以確保可讀。
RISK_TREEMAP_COLORS = {
    "Critical": ("#C1121F", "#ffd6d9"),
    "High": ("#E69F00", "#402c00"),
    "Medium": ("#0072B2", "#cfe8fb"),
    "Low": ("#56B4E9", "#052033"),
}


def render_host_treemap(filtered_df):
    """主機風險總覽：方塊大小依漏洞數量縮放，顏色依該主機最高風險等級，
    放在畫面最上方讓使用者一眼看出「哪台主機問題最大」，不用先看完整份圖譜跟清單。"""
    host_stats = (
        filtered_df.groupby("Host")
        .agg(count=("CVE", "count"), max_risk=("Risk", lambda s: max(s, key=lambda r: RISK_RANK.get(r, 0))))
        .reset_index()
        .sort_values("count", ascending=False)
    )

    if host_stats.empty:
        return ""

    max_count = host_stats["count"].max()

    def span_for(count):
        ratio = count / max_count
        if ratio > 0.7: return 5
        if ratio > 0.45: return 4
        if ratio > 0.25: return 3
        if ratio > 0.1: return 2
        return 1

    boxes = []
    for _, row in host_stats.iterrows():
        span = span_for(row["count"])
        bg, fg = RISK_TREEMAP_COLORS.get(row["max_risk"], RISK_TREEMAP_COLORS["Low"])
        font_size = 12 + span
        # Host 是 CSV 使用者上傳的內容，不是我們自己產生的資料，組進 HTML 前一定要 escape，
        # 不然惡意構造的 CSV（例如 Host 欄位塞 <img onerror=...>）會在 components.html 的 iframe 裡被當成標籤執行
        safe_host = html.escape(str(row["Host"]))
        boxes.append(f"""
        <div style="grid-column: span {span}; grid-row: span {span}; background: {bg};
                    border-radius: 6px; padding: 10px; display: flex; flex-direction: column;
                    justify-content: space-between; min-height: 32px;">
          <span style="color: {fg}; font-size: 12px; font-weight: 500;">{safe_host}</span>
          <div><span style="color: {fg}; font-size: {font_size}px; font-weight: 500;">{row['count']}</span>
          <span style="color: {fg}; font-size: 11px;"> 筆漏洞</span></div>
        </div>""")

    legend = "".join(
        f'<span style="margin-right:16px;"><span style="display:inline-block;width:10px;height:10px;'
        f'border-radius:2px;background:{bg};margin-right:4px;"></span>{risk}</span>'
        for risk, (bg, fg) in RISK_TREEMAP_COLORS.items()
    )

    return f"""
    <div style="background: #0e1117; border-radius: 8px; padding: 1.25rem; font-family: sans-serif;">
      <p style="color: #e6e6e6; font-size: 14px; font-weight: 500; margin: 0 0 12px;">
        📊 主機風險總覽（方塊大小＝漏洞數量，顏色＝最高風險等級）</p>
      <div style="display: grid; grid-template-columns: repeat(12, 1fr); grid-auto-rows: 30px; gap: 4px;">
        {''.join(boxes)}
      </div>
      <div style="margin-top: 14px; font-size: 11px; color: #9a9ba0;">{legend}</div>
    </div>
    """

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

    if st.button("🔄 重新測試 Neo4j 連線", key="retry_neo4j"):
        get_neo4j_driver.clear()

    driver_status = get_neo4j_driver()
    if driver_status is not None:
        st.success("✅ 共用 Neo4j 連線正常，相關漏洞會優先用這份協作資料")
    else:
        st.caption("⚠️ 共用 Neo4j 連不上，相關漏洞功能會自動退回本機 MITRE 知識圖譜")

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
    # 支援「Remote operating system : XXX」與「cpe:/o:vendor:product:version」兩種常見格式。
    # 抓不到就回傳 None，不要亂猜第一行文字（Nessus 猜不出 OS 時的除錯輸出常常是一堆
    # SinFP 指紋十六進位或「請協助回報特徵碼」的說明文字，硬當成 OS 名稱只會誤導）。
    def parse_os_from_plugin_output(output):
        text = str(output)

        m = re.search(r'Remote operating system\s*:\s*(.+)', text, re.IGNORECASE)
        if m and m.group(1).strip():
            # SinFP 信心不足時會列出好幾個候選 OS（一行一個），只取最有可能的第一個
            return m.group(1).strip().splitlines()[0].strip()

        m = re.search(r'cpe:/o:([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?', text)
        if m:
            vendor, product, version = m.group(1), m.group(2), m.group(3)
            parts = [vendor.replace('_', ' ').title(), product.replace('_', ' ').title()]
            if version:
                parts.append(version)
            return ' '.join(parts)

        return None

    # 嘗試取得每台主機的作業系統資訊：優先讀取現成欄位，否則從 Nessus 插件輸出解析。
    # 同一台主機常常同時有「OS Identification」跟「Common Platform Enumeration (CPE)」兩筆結果，
    # 用精確比對插件名稱（不是模糊比對）＋固定優先序，避免：
    # (1) 誤把「OS Identification Failed」這種除錯用插件的內容當成有效 OS 資料；
    # (2) CPE 那筆有時只列出應用程式層級的 cpe:/a:（例如 nginx、openssh）、沒有作業系統層級的
    #     cpe:/o:，若剛好排在 OS Identification 後面覆蓋掉，會把應用程式名稱誤植為 OS。
    def build_os_lookup(full_df):
        for col in ["OS", "Operating System", "operating_system", "os"]:
            if col in full_df.columns:
                return full_df.dropna(subset=[col]).groupby("Host")[col].first().to_dict()

        if "Plugin Output" not in full_df.columns or "Name" not in full_df.columns:
            return {}

        lookup = {}
        for plugin_name in ["OS Identification", "Common Platform Enumeration (CPE)"]:
            for _, row in full_df[full_df["Name"] == plugin_name].iterrows():
                host = row["Host"]
                if host in lookup:
                    continue
                output = row.get("Plugin Output")
                if pd.notna(output):
                    parsed = parse_os_from_plugin_output(output)
                    if parsed:
                        lookup[host] = parsed
        return lookup

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
            # --- 總覽區塊：放在畫面最上方，讓使用者先看到「哪台主機問題最大」---
            components.html(render_host_treemap(filtered_df), height=260)

            # --- 批次產生全部 CVE 的 AI 摘要並匯出報告 ---
            with st.expander("📥 批次產生 AI 摘要並匯出報告"):
                st.caption(
                    f"會依序對這 {len(matched_cves)} 個 CVE 呼叫 AI 分析（已經產生過的會跳過），"
                    "每筆之間會稍微間隔，避免免費額度的速率限制。CVE 數量多的話會需要一點時間。"
                )
                if st.button("開始批次產生", key="batch_ai_btn"):
                    progress = st.progress(0, text="準備中...")
                    total = len(matched_cves)
                    for i, cve in enumerate(matched_cves):
                        summary_key = f"ai_summary_{cve}"
                        if summary_key not in st.session_state:
                            group = filtered_df[filtered_df['CVE'] == cve]
                            cve_info = group.iloc[0]
                            try:
                                enrichment = fetch_cve_enrichment(cve)
                                st.session_state[f"cve_enrichment_{cve}"] = enrichment
                                normalized = normalize_cwe_id(cve_info['CWE_Parsed'])
                                wctx = get_related_weakness_context(normalized) if normalized else None
                                if not wctx and enrichment and enrichment.get('cwes'):
                                    for c in enrichment['cwes']:
                                        n = normalize_cwe_id(c)
                                        if n:
                                            wctx = get_related_weakness_context(n)
                                            if wctx:
                                                break
                                st.session_state[f"cve_weakness_{cve}"] = wctx
                                related = sorted(
                                    set(cve_df[cve_df['CWE_Parsed'] == cve_info['CWE_Parsed']]['CVE']) - {cve}
                                ) if cve_info['CWE_Parsed'] != "N/A" else []
                                endpoints = group[['Host', 'Port', 'Protocol']].drop_duplicates()
                                endpoints_text = "\n".join(
                                    f"- {r.Host}:{r.Port} ({r.Protocol})" for r in endpoints.itertuples()
                                )
                                st.session_state[summary_key] = generate_ai_summary(
                                    cve, cve_info, endpoints_text, enrichment, wctx, related
                                )
                            except Exception:
                                # 這個結果會被寫進客戶看的匯出報告，不放原始例外文字，避免洩漏內部細節
                                st.session_state[summary_key] = {
                                    "what": "（本筆暫時無法產生 AI 摘要，請稍後重試或改用個別按鈕重新產生）",
                                    "harm": "", "action": "", "reference": "", "related": "",
                                    "description_zh": "", "solution_zh": "",
                                }
                            time.sleep(1)
                        progress.progress((i + 1) / total, text=f"{i+1}/{total}：{cve}")
                    progress.empty()
                    st.success("批次產生完成，可以展開下方各個 CVE 卡片查看，或匯出報告。")

                report_lines = []
                for cve in matched_cves:
                    summary_key = f"ai_summary_{cve}"
                    if summary_key in st.session_state:
                        s = st.session_state[summary_key]
                        cve_info = cve_df[cve_df['CVE'] == cve].iloc[0]
                        report_lines.append(
                            f"## {cve} — {cve_info['Name']}（{cve_info['Risk']}）\n\n"
                            f"**這是什麼？**\n{s['what']}\n\n"
                            f"**可能造成的危害**\n{s['harm']}\n\n"
                            f"**建議處理方式**\n{s['action']}\n\n"
                            f"**官方資料佐證**\n{s['reference']}\n\n"
                            f"**相關弱點與攻擊手法**\n{s['related']}\n"
                        )
                if report_lines:
                    report_text = f"# 弱點分析報告\n\n共 {len(report_lines)} 個 CVE 已產生摘要\n\n" + "\n---\n\n".join(report_lines)
                    st.download_button(
                        "⬇️ 下載報告（Markdown）",
                        data=report_text,
                        file_name="vulnerability_report.md",
                        mime="text/markdown",
                    )
                else:
                    st.caption("目前還沒有任何 CVE 產生過 AI 摘要，批次產生或到下面各別點擊後才能匯出。")

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
                    normalized_cwe = normalize_cwe_id(cve_info['CWE_Parsed'])
                    weakness_context = get_related_weakness_context(normalized_cwe) if normalized_cwe else None
                    related_cves = sorted(
                        set(cve_df[cve_df['CWE_Parsed'] == cve_info['CWE_Parsed']]['CVE']) - {cve}
                    ) if cve_info['CWE_Parsed'] != "N/A" else []

                    with st.expander(f"{cve} — {cve_info['Name']}"):
                        t1, t2, t3 = st.tabs(["📌 問題概述", "🛠️ 官方修補方案 (Solution)", "🔗 關聯 CWE/CVE 與參考來源"])

                        with t1:
                            st.markdown(f"**漏洞名稱**：{cve_info['Name']}")
                            st.markdown(f"**風險等級**：`{cve_info['Risk']}`")

                            exploit_frameworks = get_exploit_frameworks(cve_info)
                            if exploit_frameworks:
                                st.error(f"💣 已有現成攻擊模組可直接利用：{', '.join(exploit_frameworks)}")

                            existing_summary = st.session_state.get(f"ai_summary_{cve}")
                            description_block = cve_info['Description']
                            if existing_summary and existing_summary.get('description_zh'):
                                description_block += f"\n\n🌐 **繁體中文翻譯**\n\n{existing_summary['description_zh']}"
                            st.info(description_block)
                            if not existing_summary:
                                st.caption("🌐 點下方「AI 摘要與官方資源」可同時取得繁體中文翻譯")

                            with st.container(border=True):
                                st.markdown("🔗 **這次掃描中的相關漏洞**")
                                if related_cves:
                                    st.markdown(
                                        f"還有 **{len(related_cves)}** 個漏洞跟這個同屬 "
                                        f"`{cve_info['CWE_Parsed']}` 分類：{', '.join(related_cves)}"
                                    )
                                else:
                                    st.caption("這次掃描中沒有其他漏洞屬於同一個 CWE 分類。")
                                st.caption("完整的弱點分類、攻擊手法說明請看「🔗 關聯 CWE/CVE 與參考來源」分頁。")

                            st.divider()
                            summary_key = f"ai_summary_{cve}"
                            enrichment_key = f"cve_enrichment_{cve}"
                            weakness_key = f"cve_weakness_{cve}"
                            if st.button("🤖 AI 摘要與官方資源", key=f"ai_btn_{cve}"):
                                if not GOOGLE_API_KEY:
                                    st.error("尚未設定 GOOGLE_API_KEY，請至 .env 補上金鑰後重新啟動 App。")
                                else:
                                    with st.spinner("查詢官方 CVE 資料庫並產生 AI 分析..."):
                                        try:
                                            enrichment = fetch_cve_enrichment(cve)
                                            st.session_state[enrichment_key] = enrichment

                                            # CSV 裡的 CWE 欄位有時是空的或跟 NVD 不同步；
                                            # 如果 CSV 查不到弱點關聯、但 NVD 有給出 CWE，改用 NVD 的 CWE 重新查一次，
                                            # 確保 AI 摘要跟下面「官方 CVE 資料來源」顯示的 CWE 是同一份。
                                            effective_weakness_context = weakness_context
                                            if not effective_weakness_context and enrichment and enrichment.get('cwes'):
                                                for cwe_candidate in enrichment['cwes']:
                                                    norm = normalize_cwe_id(cwe_candidate)
                                                    if norm:
                                                        effective_weakness_context = get_related_weakness_context(norm)
                                                        if effective_weakness_context:
                                                            break
                                            st.session_state[weakness_key] = effective_weakness_context

                                            endpoints = group[['Host', 'Port', 'Protocol']].drop_duplicates()
                                            endpoints_text = "\n".join(
                                                f"- {r.Host}:{r.Port} ({r.Protocol})" for r in endpoints.itertuples()
                                            )
                                            st.session_state[summary_key] = generate_ai_summary(
                                                cve, cve_info, endpoints_text, enrichment,
                                                effective_weakness_context, related_cves
                                            )
                                        except Exception as e:
                                            st.error(f"AI 摘要產生失敗：{e}")

                            # AI 分析可能用 NVD 的 CWE 重新查過一次更完整的資料，
                            # 之後 t3、拓樸圖都改用這份「有 AI 分析過就用它，沒有就退回 CSV 版本」的結果，避免兩邊不一致
                            display_weakness_context = st.session_state.get(weakness_key, weakness_context)

                            if summary_key in st.session_state:
                                summary = st.session_state[summary_key]
                                st.markdown("#### 🤖 AI 白話摘要")

                                with st.container(border=True):
                                    st.markdown("🔍 **這是什麼？**")
                                    st.write(summary['what'])

                                st.warning(f"⚠️ **可能造成的危害**\n\n{summary['harm']}")
                                st.success(f"✅ **建議處理方式**\n\n{summary['action']}")

                                with st.container(border=True):
                                    st.markdown("📎 **官方資料佐證**")
                                    st.caption(summary['reference'])

                                with st.container(border=True):
                                    st.markdown("🔗 **相關弱點與攻擊手法**")
                                    st.caption(summary['related'])

                                enrichment = st.session_state.get(enrichment_key)
                                if enrichment:
                                    with st.expander(f"🌐 官方 CVE 資料來源（{enrichment['source']}）"):
                                        st.markdown(f"**官方描述**：{enrichment['description'] or '無'}")
                                        st.markdown(
                                            f"**CVSS**：`{enrichment['cvss_vector'] or '無'}`"
                                            f"（分數 {enrichment['cvss_score']}，{enrichment['cvss_severity'] or '無'}）"
                                        )
                                        if enrichment['cwes']:
                                            cwe_refs = ", ".join(
                                                f"[{c}]({cwe_url(c)})" if cwe_url(c) else c for c in enrichment['cwes']
                                            )
                                            st.markdown(f"**關聯 CWE**：{cwe_refs}")

                                        epss = enrichment.get('epss')
                                        if epss:
                                            st.markdown(
                                                f"**EPSS 被利用機率**：{epss['score']*100:.1f}%"
                                                f"（贏過 {epss['percentile']*100:.0f}% 的 CVE）"
                                            )

                                        kev = enrichment.get('kev')
                                        if kev and kev.get('listed'):
                                            st.error(
                                                f"⚠️ 已列入 CISA 已知遭利用漏洞目錄（KEV）\n\n"
                                                f"加入日期：{kev.get('date_added', '無')}　"
                                                f"要求修補期限：{kev.get('due_date', '無')}　"
                                                f"勒索軟體使用情況：{kev.get('ransomware_use', '無')}"
                                            )
                                        elif kev is not None:
                                            st.caption("目前不在 CISA KEV（已知遭利用漏洞）目錄中")

                                        for ref in enrichment['references']:
                                            st.markdown(f"- {ref}")

                                        if enrichment.get('cwes') or display_weakness_context:
                                            st.markdown("**🕸️ 官方關聯拓樸圖**（CVE → CWE → 相關弱點／攻擊手法）")
                                            relation_net = build_cve_relation_graph(cve, enrichment, display_weakness_context)
                                            relation_file = f"temp_graph_cve_{re.sub(r'[^A-Za-z0-9]', '_', cve)}.html"
                                            relation_net.save_graph(relation_file)
                                            with open(relation_file, 'r', encoding='utf-8') as f:
                                                components.html(f.read(), height=440)
                                else:
                                    st.caption("⚠️ 未取得官方 CVE 資料庫資訊，以上摘要僅根據 Nessus 掃描結果分析。")

                        with t2:
                            existing_summary_t2 = st.session_state.get(f"ai_summary_{cve}")
                            solution_block = cve_info['Solution'] if pd.notna(cve_info['Solution']) else "無明確修補方案，請參考官方規範。"
                            if existing_summary_t2 and existing_summary_t2.get('solution_zh'):
                                solution_block += f"\n\n🌐 **繁體中文翻譯**\n\n{existing_summary_t2['solution_zh']}"
                            st.success(solution_block)
                            if not existing_summary_t2:
                                st.caption("🌐 點「📌 問題概述」分頁的「AI 摘要與官方資源」可同時取得繁體中文翻譯")

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
                            st.markdown("**🕸️ CWE 弱點分類與攻擊手法關聯**")
                            if display_weakness_context:
                                cwe_link = cwe_url(display_weakness_context['cwe_id'])
                                cwe_title = f"{display_weakness_context['cwe_id']} — {display_weakness_context['name']}"
                                st.markdown(f"[{cwe_title}]({cwe_link})" if cwe_link else cwe_title)
                                st.caption(display_weakness_context['description'][:400])

                                if display_weakness_context['related_weaknesses']:
                                    st.markdown("相關／父子弱點分類：")
                                    for rw in display_weakness_context['related_weaknesses']:
                                        rw_link = cwe_url(rw['cwe_id'])
                                        rw_ref = f"[`{rw['cwe_id']}`]({rw_link})" if rw_link else f"`{rw['cwe_id']}`"
                                        st.markdown(f"  - {rw['name']}（{rw_ref}，{rw['nature']}）")

                                if display_weakness_context['attack_patterns']:
                                    st.markdown("對應的 CAPEC 攻擊手法：")
                                    for ap in display_weakness_context['attack_patterns']:
                                        technique_links = []
                                        for t in ap['attack_techniques']:
                                            tid = attack_technique_id(t)
                                            turl = attack_url(tid)
                                            technique_links.append(f"[{t['name']}]({turl})" if turl else t['name'])
                                        techniques = ", ".join(technique_links)

                                        cap_link = capec_url(ap['capec_id'])
                                        cap_ref = f"[`{ap['capec_id']}`]({cap_link})" if cap_link else f"`{ap['capec_id']}`"
                                        st.markdown(
                                            f"  - ⚔️ {ap['name']}（{cap_ref}，嚴重程度 {ap['severity'] or '未評級'}）"
                                            + (f" → ATT&CK：{techniques}" if techniques else "")
                                        )

                                if display_weakness_context.get('attack_techniques'):
                                    overall_links = []
                                    for t in display_weakness_context['attack_techniques']:
                                        tid = attack_technique_id(t)
                                        turl = attack_url(tid)
                                        overall_links.append(f"[{t['name']}]({turl})" if turl else t['name'])
                                    st.markdown(f"對應 ATT&CK 技術（彙總）：{', '.join(overall_links)}")
                            elif weakness_context is None and st.session_state.get(enrichment_key) is None:
                                st.caption("目前查無此弱點分類的延伸資訊；點擊「🤖 AI 摘要與官方資源」可額外查詢 NVD 的 CWE 對應。")
                            else:
                                st.caption("目前查無此弱點分類的延伸資訊。")

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

            st.markdown("**觸發明細：哪個 IP 觸發了哪個 CVE、在哪些 Port**")

            def _port_sort_key(port_proto):
                port = port_proto.split('/')[0]
                return int(port) if port.isdigit() else 0

            # 同一個 IP 對同一個 CVE 常常在好幾個 Port 上都被觸發（例如同一個 SSL 弱點在
            # 443/3389/636 都成立），原本一個 Port 一列會把同一筆漏洞拆得很散，
            # 改成用 Host+CVE+Risk 分組，把 Port/協定合併成一格逗號分隔、按 Port 號排序
            detail_table = (
                filtered_df
                .assign(PortProto=lambda d: d['Port'].astype(str) + '/' + d['Protocol'].astype(str))
                .groupby(['Host', 'CVE', 'Risk'], as_index=False)
                .agg(Port=('PortProto', lambda s: ', '.join(sorted(set(s), key=_port_sort_key))))
                .sort_values(['Host', 'Risk'], key=lambda col: col.map(RISK_RANK) if col.name == 'Risk' else col,
                             ascending=[True, False])
                .rename(columns={'Host': 'IP', 'Risk': '風險等級', 'Port': '觸發的 Port（Port/協定）'})
            )
            st.dataframe(detail_table, hide_index=True, use_container_width=True)

else:
    st.info("👈 請先於左側邊欄上傳您的 Nessus CSV 檔案以開始分析。")
