from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import mysql.connector
import json

# DB接続関数
def DB_connect():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="testuser",
        password="testpass",
        database="sbomdb"
    )

# PDFレポート出力関数
def generate_pdf_report(output_path="sbom_report.pdf"):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("📄 SBOM Report", styles['Title']))
    elements.append(Spacer(1, 12))

    try:
        conn = DB_connect()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM component")
        components = cursor.fetchall()

        if not components:
            elements.append(Paragraph("No SBOM components found.", styles["Normal"]))
        else:
            for comp in components:
                elements.append(Paragraph(f"🔧 Component: {comp['component_name']} ({comp['version']})", styles["Heading2"]))
                elements.append(Paragraph(f"Tool: {comp['tool']}", styles["Normal"]))
                elements.append(Paragraph(f"PURL: {comp['purl']}", styles["Normal"]))
                elements.append(Paragraph(f"SHA256: {comp['hash_sha256']}", styles["Normal"]))
                elements.append(Spacer(1, 6))

                # 脆弱性の取得
                cursor.execute("SELECT * FROM vulnerabilities WHERE component_id = %s", (comp["id"],))
                vulns = cursor.fetchall()
                if vulns:
                    data = [["CVE ID", "Severity", "Description"]]
                    for vuln in vulns:
                        data.append([
                            vuln["cve_id"],
                            vuln["severity"],
                            vuln["description"][:80] + "..." if len(vuln["description"]) > 80 else vuln["description"]
                        ])
                    table = Table(data, colWidths=[100, 100, 300])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
                    ]))
                    elements.append(table)
                else:
                    elements.append(Paragraph("✅ No vulnerabilities found.", styles["Normal"]))

                elements.append(Spacer(1, 12))

        cursor.close()
        conn.close()

    except Exception as e:
        elements.append(Paragraph(f"[ERROR] {str(e)}", styles["Normal"]))

    doc.build(elements)
    print(f"[OK] PDFレポートを生成しました: {output_path}")

# 実行
if __name__ == "__main__":
    generate_pdf_report()
