from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
import mysql.connector
import json
import os
import subprocess
import requests
import csv
from dotenv import load_dotenv

load_dotenv()

app= FastAPI()
api_key=os.getenv("API_KEY")  # APIキーを設定

# SBOMの情報をMySQLに格納するプログラム
class SBOMrequests(BaseModel):
    
     #バリーデーション
    tool: str   
    sbom: dict

#DBに接続ための情報
def DB_connect():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="testuser",
        password="testpass",
        database="sbomdb"
    )

# SBOMをMySQLに挿入するエンドポイント
@app.post("/api/sbom")
async def SBOM_insert(sbom_data: SBOMrequests, authorization: str=Header(None)):
    if authorization != f"Bearer {api_key}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        conn=DB_connect()
        cursor= conn.cursor()
        cursor.execute(
            "insert into scan (timestamp) values (now())"
        )
        scan_id = cursor.lastrowid  # 最後に挿入したIDを取得
        
        cursor.execute(
            "INSERT INTO raw_sbom (scan_id, tool, json_data) VALUES (%s, %s, %s)",
            (scan_id, sbom_data.tool, json.dumps(sbom_data.sbom))
        )

        
        
        sbom=sbom_data.sbom
        components = sbom.get("components", [])
        dependencies = sbom.get("dependencies", [])
        purl_to_id= {}
        
        for comp in components:
            if comp.get("type") in {"library","application", "container"}:
                tool= sbom_data.tool
                component_name=comp.get("name")
                version=comp.get("version")
                purl=comp.get("purl","")
                hash_sha256=""
            
                for hash in comp.get("hashes", []):
                    if hash.get("alg")=="SHA-256":
                        hash_sha256=hash.get("content")
                    break
                #componentテーブルに挿入
                cursor.execute(
                "insert into component (tool, component_name, version,purl,hash_sha256) values (%s, %s, %s, %s, %s)",
                (tool, component_name, version, purl, hash_sha256)
                ) 
            
                component_id = cursor.lastrowid  # 最後に挿入したIDを取得
                purl_to_id[purl] = component_id
                
                for lic in comp.get("licenses", []):
                    license_info = lic.get("license", {})
                    
                    license_id = license_info.get("id") or license_info.get("name")
                    if license_id:
                        cursor.execute(
                            "INSERT INTO license (component_id, license_id) VALUES (%s, %s)", 
                            (component_id, license_id)
                        )
        
        dep_key="dependsOn"
        for dep in dependencies:
            parent_purl = dep.get("ref")
            parent_id = purl_to_id.get(parent_purl)
            print(f"dep parent: {parent_purl} => id: {parent_id}")
            
            
            for child_purl in dep.get(dep_key, []):
                child_id = purl_to_id.get(child_purl)
                print(f"dep child: {child_purl} => id: {child_id}")
                
                if parent_id and child_id:
                    cursor.execute("""
                        INSERT INTO dependencies (parent_id, child_id)
                        VALUES (%s, %s)
                    """, (parent_id, child_id))
    
        cursor.close()
        conn.commit()
        conn.close()
        return {"message": "SBOM data inserted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

#SBOMデータを取得するエンドポイント
@app.get("/api/sbom")
async def get_sbom_data(authorization: str= Header(None)):
    if authorization != f"Bearer {api_key}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        conn=DB_connect()
        cursor=conn.cursor()
        cursor.execute("select tool, json_data from raw_sbom")
        result=cursor.fetchall()
        cursor.close()
        conn.close()
    
        sboms=[]
        for tool, json_data in result:
            sboms.append({
                "tool":  tool,
                "sbom": json.loads(json_data)   
                
            })
        return {"sboms": sboms}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    


if __name__=="__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload =  True)
    

    
        
    
    
    

























    