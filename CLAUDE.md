# 專案：弱點掃描 (Nessus) 互動分析與修補指引系統

Streamlit 單檔 App（`app.py`），讓使用者上傳 Nessus CSV 掃描結果，依風險等級篩選、畫出
1-Depth 拓樸圖，並用 AI（Gemini/Groq）產生白話風險摘要，同時串接 NVD／EPSS／CISA KEV／
CWE-CAPEC-ATT&CK 知識圖譜，補足 Nessus CSV 本身描述過於精簡的問題。

- 本機：`http://localhost:8501`
- 雲端：https://neo4j-vuln-report.streamlit.app （Streamlit Community Cloud，跟隨 GitHub `main` branch 自動部署）
- GitHub：https://github.com/s610034/Neo4jweb

## 執行環境（重要，不要用錯 Python）

這台機器同時有 Homebrew Python 3.13 和系統內建的 Python 3.9，兩者的 pip 套件是分開的。
所有專案依賴（streamlit/pandas/neo4j/google-genai 等）是裝在 **系統 Python 3.9**，
不是 `python3`／Homebrew 那個（那個是空的，`pip install` 還會因為 externally-managed 被拒絕）。

啟動本機開發伺服器一律用這個路徑：

```bash
/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3 -m streamlit run app.py
```

## 兩套獨立的密鑰管理，不會互相同步

- **本機**：`.env`（`python-dotenv` 讀取，已加進 `.gitignore`，不會進版控）
- **雲端**：Streamlit Community Cloud 的 App Settings → Secrets（純網頁後台設定，跟 GitHub repo 完全無關）
- 改本機 `.env` 不會自動同步到雲端的 Secrets，兩邊要各自手動維護一份，鍵名要一致。

當前用到的鍵：`NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD`、`GOOGLE_API_KEY`、`GROQ_API_KEY`、
`OPENCVE_TOKEN`（選用，OpenCVE 備援來源，目前沒申請、留空即可）。

`app.py` 裡的 `get_secret()` 會優先讀 `st.secrets`（雲端），讀不到才 fallback 到 `os.environ`（本機 `.env`）。

## Neo4j 連線：Cloudflare 擋原生 Bolt 協定，用 cloudflared 通道繞過

共用的 Neo4j（`graphker.lab.114514.my.id`，由團隊成員維護，資料庫本身應該是用開源工具
[GraphKer](https://github.com/amberzovitis/GraphKer) 建的，schema 完全對得上：`CVE
-[:Problem_Type]-> CWE -[:Related_Weakness]-> CWE`、`CWE -[:RelatedAttackPattern]-> CAPEC
-[:Mapped_Attack]-> ATTACK`）被 Cloudflare 代理擋住了：

- 這個網域是 Cloudflare Proxied（橘雲），Cloudflare 的邊緣節點只認得 HTTP(S)，原生 Bolt 協定
  （`bolt+s://...:443`）會被判定成格式錯誤的 HTTP 請求直接拒絕（`neo4j` 官方 driver 因此固定
  丟出 `Cannot to connect to Bolt service...(looks like HTTP)`）。這是 Cloudflare 官方文件證實
  的行為，換 `neo4j` 套件版本、換本機/雲端都一樣會擋。
- **解法**：`cloudflared access tcp --hostname <host> --url 127.0.0.1:<port>` 會用 WebSocket
  包裝 Bolt 流量，Cloudflare 能正常轉發（WebSocket 是合法的 HTTP Upgrade），實測完全不需要
  Cloudflare Access 的登入驗證就能連上（代表這個服務目前沒有身份驗證把關，安全性存疑，但不是
  我們這邊能改的）。
- `app.py` 裡的 `ensure_cloudflare_tunnel()`（`st.cache_resource`，整個 App 生命週期只跑一次）
  會自動處理這件事：本機找 PATH 裡的 `cloudflared`（`brew install cloudflared`），雲端環境沒有
  就自動下載 Linux 版執行檔到 `/tmp/cloudflared_bin/`，兩邊都會在背景 spawn 一個 subprocess
  把 Bolt 轉發到本機的 `127.0.0.1:17687`，`get_neo4j_driver()` 才透過這個本機 port 連線。
- 連不上（通道建立失敗、或 Neo4j 本身掛了）會自動 fallback 到 `data/cwe_knowledge_graph.json`
  （本機離線 CWE/CAPEC/ATT&CK 知識圖譜，從 MITRE 官方 XML 資料一次性建置，不含 CVE 節點）。
  兩邊回傳格式統一，UI 跟 AI prompt 不用管資料是哪裡來的。
- 側邊欄有「🔄 重新測試 Neo4j 連線」按鈕（清 `get_neo4j_driver` 的 cache），連線狀態改變後
  不用重啟 App 就能重新嘗試。

## AI 摘要：多供應商平行賽跑，不要走回序列 fallback

`generate_ai_summary()` 同時對 `gemini-flash-lite-latest`、`gemma-4-26b-a4b-it`（Google）、
`llama-3.3-70b-versatile`（Groq，`call_groq_model()`）發送請求，**誰先成功回應就用誰**
（`ThreadPoolExecutor` + `as_completed`）。

這是刻意的架構決定，不要改回「A 失敗才試 B」的序列寫法：實測過 Google 的兩個模型會**同時**
壅塞（`gemini-flash-lite-latest` 直接 503，`gemma` 撐到 30 秒逾時），只有混用完全獨立公司的
服務（Groq）才能保證單一供應商掛掉時還有其他候選頂上。Gemini 用 `response_schema` 強制結構化
輸出；Groq 只有 `response_format: json_object`（保證合法 JSON，不保證欄位），所以 Groq 的結果
會額外過 `_validate_summary_dict()` 檢查五個必要欄位都在，不過就當這次候選失敗、換下一個。

`AI_SUMMARY_SCHEMA` 的五個欄位（`what`/`harm`/`action`/`reference`/`related`）畫面排版完全由
App 自己控制（各自獨立的色塊：資訊框/警示框/成功框），不依賴模型輸出的文字格式。

## CWE/CAPEC/ATT&CK 知識圖譜資料的來源

`data/cwe_knowledge_graph.json`（約 0.67MB，已進版控）是从 MITRE 官方 XML 一次性抓取＋濃縮出來
的靜態資料（CWE 969 筆、CAPEC 615 筆，CAPEC 內建的 `Taxonomy_Mappings` 直接給 ATT&CK 對應，
不需要另外處理 47MB 的 ATT&CK STIX JSON）。重新產生的腳本沒有留在 repo 裡（一次性用完即丟），
來源網址：
- CWE: `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- CAPEC: `https://capec.mitre.org/data/xml/capec_latest.xml`

線上 Neo4j 的節點屬性名稱跟這份本機資料不完全一樣（例如 CWE 的人類可讀名稱，Neo4j 裡是
`Extended_Name`，CAPEC 是 `ExtendedName`，本機 JSON 統一用 `name`），`get_related_weakness_context_online()`
/ `_offline()` 兩邊各自轉換成同一份格式再回傳，呼叫端（`get_related_weakness_context()`）完全
不用管來源。

## CWE 格式對齊

Nessus CSV 的 `XREF` 欄位常寫成 `CWE:79`（冒號），NVD API 回傳的是 `CWE-79`（連字號），本機/
線上知識圖譜也是連字號格式。`normalize_cwe_id()` 統一轉換，不要在別的地方重複寫格式轉換邏輯。

NVD 對沒有分類資訊的漏洞會回傳 `NVD-CWE-noinfo` / `NVD-CWE-Other` 這種內部佔位標籤（不是真正
的 CWE 編號），`fetch_cve_from_nvd()` 已經用正則 `^CWE-\d+$` 過濾掉，不要讓這種標籤流到 UI 或
AI prompt 裡。

## 客戶報告不能暴露內部架構

畫面上顯示給客戶看的卡片文字，不能出現「Neo4j」「本機知識圖譜」這類內部代號/架構細節，也不能
出現任何內部人員的稱呼或代號（之前修過這個問題）。真的要顯示資料來源／連線狀態，只能放在側邊欄的
管理者專用區塊。

## 已知的其他坑

- **NVD/EPSS/CISA KEV 查詢彼此獨立**，`fetch_cve_enrichment()` 用 `ThreadPoolExecutor` 平行
  呼叫，不要改回序列（雲端環境的網路延遲比本機高，序列呼叫的等待時間會直接疊加）。
- **CISA KEV 目錄是全量下載**（約 1.5MB JSON，`fetch_cisa_kev_catalog()`），用 `st.cache_data(ttl=86400)`
  快取一天，不要拿掉快取或改成每次都下載。
- Nessus CSV 的 `Metasploit`/`Core Impact`/`CANVAS` 欄位值是字串 `'true'`（不是布林），
  `get_exploit_frameworks()` 已經處理，這三個欄位本來就在 CSV 裡，不需要額外查詢。
- `Plugin Output` 裡的 OS 資訊有兩種常見格式（`Remote operating system : XXX` 純文字，或
  `cpe:/o:vendor:product:version` CPE 格式），`parse_os_from_plugin_output()` 兩種都有處理。

## 改動程式碼前的 Open Code Review 審查流程

commit 前（尤其 `app.py`），先跑一次 delegation mode 審查，而不是直接憑印象改完就 commit：

```bash
ocr delegate preview                              # 看這次 diff 涵蓋哪些檔案
ocr delegate rule app.py                          # 取出對應的自訂規則（.opencodereview/rule.json）
```

規則檔在 `.opencodereview/rule.json`，內容對應本文件「已知的其他坑」跟上面各段落列出的架構決定
（AI 平行賽跑不能改序列、CISA KEV 快取不能拿掉、客戶畫面不能露內部代號、CWE 格式要走
`normalize_cwe_id()`、Neo4j 連線要走 cloudflared 通道）。取出規則後由 Claude Code 實際讀 diff+
規則做判斷、回報結果，使用者確認沒問題才 commit——目前不自動擋 commit，也還沒接 CI，是輔助複核
的角色，不是自動化關卡。內建規則（NPE/XSS/SQL injection 這類）對這個 Python/Streamlit 專案命中
率低，主要價值來自這份客製規則，之後踩到新坑要記得補進 `rule.json`，不然規則庫不會自動變聰明。

## 待辦（使用者提過但還沒做的功能）

- **批次匯出報告**：一鍵產生全部 CVE 的 AI 摘要並匯出 PDF/Word，目前每個 CVE 要各自點按鈕。
  使用者關心批次會不會暴增 Gemini/Groq 用量／撞到免費層級速率限制，設計時要考慮節流或讓使用者
  勾選要跑哪幾筆，不要無腦全部一次送出。
- **Treemap 主機風險總覽圖**：依 CVSS／漏洞數量縮放方塊大小、顏色代表最高風險等級，用意是讓
  使用者一眼看出「哪台主機問題最大」。**使用者明確要求要放在畫面上半部**（生成拓樸圖／統計表
  之前），不是放在最下面。目前只有一張用假資料做的預覽圖，還沒接真實統計數字。
