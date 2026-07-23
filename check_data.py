import os
import pandas as pd
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

# 1. 測試讀取 Nessus CSV
print("--- [1/2] 檢查 Nessus CSV ---")
try:
    csv_file = "MSSP scan_gx1b3b.csv"
    df = pd.read_csv(csv_file)
    cve_df = df[df['CVE'].notna()]
    unique_cves = cve_df['CVE'].unique().tolist()

    print(f"✅ CSV 讀取成功！")
    print(f"   - 總筆數: {len(df)} 筆")
    print(f"   - 包含 CVE 的漏洞筆數: {len(cve_df)} 筆")
    print(f"   - 獨立 CVE 數量: {len(unique_cves)} 個")
    print(f"   - 前 3 個 CVE 範例: {unique_cves[:3]}")
except Exception as e:
    print(f"❌ CSV 讀取失敗: {e}")

print("\n" + "="*40 + "\n")

# 2. 測試 Neo4j 資料庫遠端連線
print("--- [2/2] 檢查 Neo4j 1-Depth 連線 ---")
NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

try:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        # 測試連線並拿第一個 CVE (例如 CVE-1999-0524) 去查 1-Depth 節點
        test_cve = unique_cves[0] if 'unique_cves' in locals() and unique_cves else 'CVE-1999-0524'
        print(f"🔍 正在向 Neo4j 查詢 {test_cve} 的 1-Depth 拓撲資料...")

        query = """
        MATCH (c:CVE {Name: $cve})-[r]-(connected)
        RETURN labels(connected) AS node_type, connected.Name AS name, type(r) AS rel_type
        LIMIT 5
        """
        records = session.run(query, cve=test_cve)

        print(f"   找到與 {test_cve} 相連的 1-Depth 節點：")
        found = False
        for rec in records:
            found = True
            print(f"   - [{rec['node_type'][0]}] {rec['name']} (關係: {rec['rel_type']})")

        if not found:
            print("   ⚠️ 查詢成功，但該 CVE 在 Neo4j 中沒有找到直接相連的節點。")

    driver.close()
    print("\n✅ Neo4j 連線與測試完成！")
except Exception as e:
    print(f"❌ Neo4j 連線失敗: {e}")
