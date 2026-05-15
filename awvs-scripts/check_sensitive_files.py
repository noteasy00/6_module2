import os
import json

def check_sensitive_files(web_root="/var/www/html"):
    result = {
        "module": "A05-05",
        "ref": "SRV-046",
        "category": "웹",
        "title": "민감 파일 노출 점검",
        "target": web_root,
        "status": "",
        "evidence": "",
        "reason": "",
        "recommendation": "",
        "ai_analysis": {
            "risk_detail": "",
            "attack_scenario": "",
            "countermeasure": ""
        }
    }

    if not os.path.exists(web_root):
        result["status"] = "N/A"
        result["evidence"] = f"{web_root} 디렉토리가 존재하지 않음"
        result["reason"] = "웹 서버가 운영되지 않는 환경으로 점검 대상 아님"
        return result

    # 민감 파일 패턴
    sensitive_patterns = [
        ".env",
        ".git",
        ".gitignore",
        ".htpasswd",
        ".htaccess",
        "config.bak",
        "config.old",
        "config.php.bak",
        "database.yml",
        "db.conf",
        "wp-config.php.bak",
        "backup.sql",
        "dump.sql",
        ".sql",
        "id_rsa",
        "id_dsa",
        "server.key",
        "private.pem",
        "credentials.json",
        "secrets.json",
    ]

    found = []

    for root, dirs, files in os.walk(web_root):
        # .git 디렉토리 자체 탐지
        if ".git" in dirs:
            git_path = os.path.join(root, ".git")
            found.append({
                "file": git_path,
                "type": "Git 저장소 노출"
            })

        for fname in files:
            fname_lower = fname.lower()
            for pattern in sensitive_patterns:
                if fname_lower == pattern or fname_lower.endswith(pattern):
                    fpath = os.path.join(root, fname)
                    # 파일 크기 확인
                    try:
                        size = os.path.getsize(fpath)
                    except:
                        size = 0
                    found.append({
                        "file": fpath,
                        "type": f"민감 파일 ({pattern})",
                        "size": size
                    })
                    break

    if found:
        result["status"] = "취약"
        evidence_lines = []
        for f in found[:5]:
            size_str = f" ({f.get('size', 0)} bytes)" if 'size' in f else ""
            evidence_lines.append(f"{f['file']}{size_str}: {f['type']}")
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = f"웹 디렉토리에서 외부 접근 가능한 민감 파일 {len(found)}건 탐지됨"
        result["recommendation"] = "민감 파일을 웹 루트 외부로 이동하거나 삭제. .htaccess 또는 웹 서버 설정으로 접근 차단. .git 디렉토리는 즉시 삭제"
    else:
        result["status"] = "양호"
        result["evidence"] = f"{web_root} 하위 민감 파일 점검 완료, 노출 파일 미탐지"
        result["reason"] = "웹 디렉토리 내 민감 파일이 외부에 노출되지 않음"
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    result = check_sensitive_files()
    print(json.dumps(result, ensure_ascii=False, indent=2))
