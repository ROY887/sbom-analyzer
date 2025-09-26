import os
import subprocess
import json
import requests
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
import datetime
from dotenv import load_dotenv
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import TableStyle, Paragraph
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import LongTable
import shutil
import glob


load_dotenv()  
pdfmetrics.registerFont(UnicodeCIDFont('HeiseiKakuGo-W5'))
rules_file = "rules.kts"#ortのevaluateを使うためのもの

api_key = os.getenv("API_KEY")
url=os.getenv("API_URL")

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
        subprocess.run([
            "trivy", "image", target,
            "-f", "json",
            "--output", "trivy_vuln.json"
        ], check=True)
        
        return {
            "sbom_file": "trivy_sbom.json",
            "vuln_file": "trivy_vuln.json",
            "tool": "trivy"   
        }
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Trivy実行エラー: {e}")
        return None, None


def run_ORT(target):
    output_dir="ort_output"
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    

    

    # Analyzer 
    subprocess.run([
        "ort", "analyze",
        "-i", target,
        "-o", output_dir,
        "--output-formats", "Json"
    ], check=False)

    #  Reporter 
    analyzer_files = glob.glob(os.path.join(output_dir, "analyzer-result.json"))
    if not analyzer_files:
        print("[ERROR] analyzer-result ファイルが見つかりません")
        return None
    analyzer_file = analyzer_files[0]
    
    reporter_output = os.path.join(output_dir, "reporter-output")
    os.makedirs(reporter_output, exist_ok=True)
    
    
    
    # evaluator_result_json = os.path.join(output_dir, "evaluator-result.json")
    # subprocess.run([
    #     "ort", "evaluate", 
    #     "-i", analyzer_file, 
    #     "-o", evaluator_result_json, 
    #     "--output-formats", "Json",
    #     "--rules-resource", rules_file
    # ], check=True)
    
   

    subprocess.run([
            "ort", "report", 
            "-i", analyzer_file, 
            "-f","CycloneDX",
            "-o", reporter_output
        ], check=False)
        
    sbom_files = glob.glob(os.path.join(reporter_output, "*.json"))
    if not sbom_files:
            print("[ERROR] SBOM JSON が見つかりません")
            return None
    sbom_json = sbom_files[0]
        
       
    return {"sbom_file": sbom_json ,
                "vuln_file":None,
                "tool":"ORT"}
    


def run_surfactant(target):
    try:
        subprocess.run([
            "surfactant", "generate", target, "surfactant_sbom.json",
            "--output_format", "cyclonedx"
        ], check=False)
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

# # === OSV APIを使用して脆弱性情報を取得 ===
# def osv_reference(package_name, version ,ecosystem="PyPI"):
#     osv_url = "https://api.osv.dev/v1/query"
#     query = {
#         "package": {
#             "name": package_name,
#             "ecosystem": ecosystem  # 例としてPythonのパッケージを指定
#         },
#         "version": version, 
#     }
    
    
#     response=requests.post(osv_url,json=query)
#     if response.status_code ==200:
#         vulunerabilities = response.json().get("vulunerabilities", [])
#         if vulunerabilities:
#             print(f"[OK] {package_name} の脆弱性情報を取得しました。")
#             for vuln in vulunerabilities:
#                 print(f"Vulnerability ID: {vuln['id']}")
#                 print(f"Summary: {vuln.get('summary', 'No summary available')}")
#                 print(f"Published Date: {vuln.get('published', 'No date available')}")
#         else:
#             print(f"[INFO] {package_name} の脆弱性情報は見つかりませんでした。")
#     else:
#         print(f"[ERROR] OSV APIエラー: {response.status_code} - {response.text}")
        

#解析した情報のレポート
def generate_sbom_report(sbom_data, tool_name, output_path="sbom_report.pdf"):
 
    base_dir =  os.path.abspath(os.getcwd())#abspathサーバー上のルートディレクトリへの絶対パスを表す
    base, ext = os.path.splitext(output_path)#拡張子とファイル名を分けて保存する
    base = os.path.join(base_dir,os.path.basename(base))#
    
    counter = 0
    #sbom_reportの重複を防ぐための処理
    while True:
        if counter == 0 :
            new_output_path = f"{base}{ext}"
        else:
            new_output_path = f"{base}_{counter}{ext}"
            
        if not os.path.exists(new_output_path):
            break
        counter += 1
            
    
    
    try:
        doc = SimpleDocTemplate(new_output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        
        
        styles.add(ParagraphStyle(
        name='JapaneseTitle',
        fontName='HeiseiKakuGo-W5',
        fontSize=16,
        leading=20
        ))

        elements.append(Paragraph(f"SBOM レポート - ツール: {tool_name}", styles['JapaneseTitle']))
        elements.append(Paragraph(f" {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        styleN = styles["Normal"]
        style_wrap = ParagraphStyle(
        'wrap',
        parent=styleN,
        fontSize=8,
        leading=10,
        wordWrap='CJK',  # 長文でも折り返し
        )

        components = sbom_data.get("components", [])
        data = [["Name", "Version", "Type", "PURL", "Hash"]]
        for comp in components:
            data.append([
                Paragraph(comp.get("name", "N/A"),style_wrap),
                Paragraph(comp.get("version", "N/A"),style_wrap),
                Paragraph(comp.get("type", "N/A"),style_wrap),
                Paragraph(comp.get("purl", "N/A"),style_wrap),
                Paragraph(comp.get("hashes", [{}])[0].get("content", "N/A") if comp.get("hashes") else "N/A",style_wrap)
            ])
            
        col_widths = [25*mm, 20*mm, 20*mm, 47*mm, 47*mm]
        t = LongTable(data, colWidths=col_widths,repeatRows=1)

        t.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,0), 'HeiseiKakuGo-W5'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
            

        elements.append(t)
        doc.build(elements)
        print(f"[OK] レポートが作成されました: {new_output_path}")
    except Exception as e:
        print(f"[ERROR] レポート作成に失敗しました: {e}")
#脆弱性に関するレポートの作成
def generate_vuln_report(vuln_file, tool_name, output_pdf="vuln_report.pdf"):
    base_dir = os.path.abspath(os.getcwd())
    base, ext = os.path.splitext(output_pdf)
    base = os.path.join(base_dir, os.path.basename(base))
    counter = 0
    while True:
        new_output_path = f"{base}{'' if counter==0 else f'_{counter}'}{ext}"
        if not os.path.exists(new_output_path):
            break
        counter += 1
        
    
    try:

    
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(new_output_path, pagesize=A4)
        story = []
        
        title_style = ParagraphStyle(
            'title',
            parent=styles['Title'],
            fontName='HeiseiKakuGo-W5',
            fontSize=16,
            leading=20
        )

        story.append(Paragraph(f"脆弱性レポート - ツール: {tool_name}", title_style))
        story.append(Paragraph(f" {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 12))

        with open(vuln_file, "r", encoding="utf-8") as f:
            vuln_data = json.load(f)

        results = vuln_data.get("Results", [])
        wrap_style = ParagraphStyle(
            'wrap',
            fontName='HeiseiKakuGo-W5',  
            fontSize=8,
            leading=10,
            wordWrap='CJK'
        )
        
        for result in results:
            target = result.get("Target", "不明なターゲット")
            story.append(Paragraph(f"<b>対象:</b> {target}", wrap_style))
            story.append(Spacer(1, 4))

            vulns = result.get("Vulnerabilities", [])
            if not vulns:
                story.append(Paragraph("脆弱性は検出されませんでした。", wrap_style))
            else:
                data = [["ID", "PkgName", "InstalledVersion", "Severity", "Title"]]
                for v in vulns:
                    data.append([
                    
                        Paragraph(v.get("VulnerabilityID", ""), wrap_style),
                        Paragraph(v.get("PkgName", ""), wrap_style),
                        Paragraph(v.get("InstalledVersion", ""), wrap_style),
                        Paragraph(v.get("Severity", ""), wrap_style),
                        Paragraph(v.get("Title", ""), wrap_style),
                    ])

                # 列幅合計をA4横幅内に収める
                col_widths = [30*mm, 30*mm, 30*mm, 25*mm, 45*mm]
                t = Table(data, colWidths=col_widths, repeatRows=1)
                t.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), 'HeiseiKakuGo-W5'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BOX', (0,0), (-1,-1), 0.5, colors.black),
                    ('INNERGRID',(0,0),(-1,-1),0.5, colors.black),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ALIGN', (0,0), (-1,0), 'CENTER')
                ]))
                story.append(t)
            story.append(Spacer(1, 12))

        doc.build(story)
        print(f"[OK] 脆弱性レポート作成: {new_output_path}")

    except Exception as e:
        print(f"[ERROR] 脆弱性レポート作成に失敗: {e}")
    
            


# === メイン処理 ===
def main():
    input_type = detect_input_type(target)

    tools = {
        "image": run_trivy,      # SBOM + 脆弱性
        "git": run_ORT,          # SBOMのみ
        "binary": run_surfactant # SBOMのみ
    }

    if input_type not in tools:
        print("[ERROR] 入力タイプが不明です。対応形式: dockerイメージ、gitリポジトリ、バイナリファイル")
        return

    print(f"{input_type} を解析しています...")

    # TrivyはSBOMと脆弱性を返す、それ以外は従来どおり
    result = tools[input_type](target)

    if not result:
        print("[ERROR] ツールの実行に失敗しました。")
        return

    # Trivyの場合
    if input_type == "image":
        sbom_file = result.get("sbom_file")
        vuln_file = result.get("vuln_file")
        tool_name = result.get("tool")
    #ORTの場合
    elif input_type == "git":
        
        sbom_file = result.get("sbom_file")
        vuln_file = result.get("vuln_file")
        tool_name = result.get("tool")
    else:
        # ORT, Surfactant は (json_path, tool_name) を返す想定
        sbom_file, tool_name = result
        vuln_file = None

    # SBOMのPOST処理
    if sbom_file:
        sbom_post(sbom_file, tool_name)

    # SBOMレポート
    if sbom_file:
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        generate_sbom_report(sbom_data, tool_name, "sbom_report.pdf")

    # 脆弱性レポート
    if vuln_file:
        generate_vuln_report(vuln_file, tool_name, "vuln_report.pdf")


        
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

