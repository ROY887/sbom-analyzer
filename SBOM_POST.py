import os
import subprocess
import json
import requests
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
import datetime

# === API設定 ===
url = "http://127.0.0.1:8000/api/sbom"
api_key = "secret123"  
# === ユーザー入力 ===
target = input("SBOMを解析する対象を入力してください: ")


# === 入力の種類を判定 ===
def detect_input_type(target):
    if target.startswith("docker://") or (":" in target and not target.endswith(".git")):
        return "image"
    elif target.endswith(".git"):
        return "git"
    elif os.path.isfile(target):
        return "binary"
    elif os.path.isdir(target):
        return "git"
    return "unknown"


# === 各SBOMツール実行関数 ===

def run_trivy(target):
    try:
        subprocess.run([
            "trivy", "image", target,
            "-f", "cyclonedx",
            "--output", "trivy_sbom.json"
        ], check=True)
        return "trivy_sbom.json", "trivy"
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Trivy実行エラー: {e}")
        return None, None


def run_ORT(target):
    try:
        subprocess.run([
            "ort", "analyze", "-i", target, "-o", "ort_sbom.json"
        ], check=True)
        subprocess.run([
            "ort", "report", "-i", "ort_sbom.json", "-f", "cyclonedx", "-o", "ort_report.json"
        ], check=True)
        return "ort_sbom.json", "ort"
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] ORT実行エラー: {e}")
        return None, None


def run_surfactant(target):
    try:
        subprocess.run([
            "surfactant", "generate", target, "surfactant_sbom.json",
            "--output-format", "cyclonedx"
        ], check=True)
        return "surfactant_sbom.json", "surfactant"
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Surfactant実行エラー: {e}")
        return None, None


# === APIへPOSTする関数 ===
def sbom_post(json_path, tool_name):
    if not json_path or not tool_name:
        print("[ERROR] 無効なJSONパスまたはツール名です。POSTをスキップします。")
        return

    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] JSONファイルの読み込みエラー: {e}")
        return

    sbom_data = {
        "tool": tool_name,
        "sbom": data
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        response = requests.post(url, json=sbom_data, headers=headers)
        if response.status_code == 200:
            print(f"[OK] {tool_name} のSBOMをAPIに送信しました。")
        else:
            print(f"[ERROR] APIエラー: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"[ERROR] API通信エラー: {e}")


#sbomデータをgetする関数
def get_sbom_data():
    headers ={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            sboms= response.json() 
            print("[OK] SBOMデータを取得しました。")
            for sbom in sboms["sboms"]:
                print(f"tool: {sbom['tool']}")
                print(f"sbom: {sbom['sbom']}")
        else:
            print(f"[ERROR] APIエラー: {response.status_code} - {response.text}")
       
    except requests.RequestException as e:
        print(f"[ERROR] API通信エラー: {e}")
        return None

# === OSV APIを使用して脆弱性情報を取得 ===
def osv_reference(package_name, version ,ecosystem="PyPI"):
    osv_url = "https://api.osv.dev/v1/query"
    query = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem  # 例としてPythonのパッケージを指定
        },
        "version": version, 
    }
    
    
    response=requests.post(osv_url,json=query)
    if response.status_code ==200:
        vulunerabilities = response.json().get("vulunerabilities", [])
        if vulunerabilities:
            print(f"[OK] {package_name} の脆弱性情報を取得しました。")
            for vuln in vulunerabilities:
                print(f"Vulnerability ID: {vuln['id']}")
                print(f"Summary: {vuln.get('summary', 'No summary available')}")
                print(f"Published Date: {vuln.get('published', 'No date available')}")
        else:
            print(f"[INFO] {package_name} の脆弱性情報は見つかりませんでした。")
    else:
        print(f"[ERROR] OSV APIエラー: {response.status_code} - {response.text}")
        


def generate_sbom_report(sbom_data, tool_name, output_path="sbom_report.pdf"):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"SBOM レポート - ツール: {tool_name}", styles['Title']))
    elements.append(Paragraph(f"生成日: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    components = sbom_data.get("components", [])
    data = [["Name", "Version", "Type", "PURL", "Hash"]]
    for comp in components:
        data.append([
            comp.get("name", "N/A"),
            comp.get("version", "N/A"),
            comp.get("type", "N/A"),
            comp.get("purl", "N/A"),
            comp.get("hashes", [{}])[0].get("content", "N/A") if comp.get("hashes") else "N/A"
        ])

    t = Table(data)
    elements.append(t)
    doc.build(elements)
    print(f"[OK] レポートが作成されました: {output_path}")
    
            


# === メイン処理 ===
def main():
    input_type = detect_input_type(target)

    tools = {
        "image": run_trivy,
        "git": run_ORT,
        "binary": run_surfactant
    }

    if input_type in tools:
        print(f"{input_type} を解析しています...")
        json_path, tool_name = tools[input_type](target)
        sbom_post(json_path, tool_name)
    else:
        print("[ERROR] 入力タイプが不明です。対応形式: dockerイメージ、gitリポジトリ、バイナリファイル")




    if json_path:
        with open(json_path) as f:
            sbom_data = json.load(f)
        generate_sbom_report(sbom_data, tool_name)
# === 実行 ===
if __name__ == "__main__":
    main()



#choice=input("SBOMデータを取得しますか？(y/n): ")
#if choice.lower() == 'y':
    #get_sbom_data()
#else:
    #print("SBOMデータの取得をスキップします。")


#with open("trivy_sbom.json") as f:
    #sbom = json.load(f)

#components = sbom.get("components", [])
#for comp in components:
    #if comp.get("type") == "library":
        #name = comp.get("name")
        #version = comp.get("version")
        #osv_reference(name, version)
