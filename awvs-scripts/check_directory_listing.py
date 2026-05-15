import os
import json
import subprocess

def check_directory_listing(web_root="/var/www/html"):
    result = {
        "module": "A05-04",
        "ref": "SRV-045",
        "category": "웹",
        "title": "디렉토리 리스팅 점검",
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

    vulnerable = []

    # === 1. Apache 설정 점검 ===
    apache_configs = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/apache2/conf-enabled/security.conf",
        "/etc/httpd/conf/httpd.conf"
    ]

    for conf_path in apache_configs:
        if os.path.exists(conf_path):
            try:
                with open(conf_path, errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        # 주석 제외
                        if stripped.startswith('#'):
                            continue
                        # Options에 Indexes가 포함되어 있으면 취약
                        if 'Options' in stripped and 'Indexes' in stripped:
                            # -Indexes는 비활성화이므로 양호
                            if '-Indexes' not in stripped:
                                vulnerable.append({
                                    "type": "apache",
                                    "file": conf_path,
                                    "line": line_num,
                                    "content": stripped
                                })
            except (PermissionError, IOError):
                pass

    # === 2. Nginx 설정 점검 ===
    nginx_configs = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/conf.d/default.conf"
    ]

    for conf_path in nginx_configs:
        if os.path.exists(conf_path):
            try:
                with open(conf_path, errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith('#'):
                            continue
                        # autoindex on이면 취약
                        if 'autoindex' in stripped.lower() and 'on' in stripped.lower():
                            vulnerable.append({
                                "type": "nginx",
                                "file": conf_path,
                                "line": line_num,
                                "content": stripped
                            })
            except (PermissionError, IOError):
                pass

    # === 3. .htaccess 점검 ===
    for root, dirs, files in os.walk(web_root):
        if '.htaccess' in files:
            htaccess_path = os.path.join(root, '.htaccess')
            try:
                with open(htaccess_path, errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith('#'):
                            continue
                        if 'Options' in stripped and 'Indexes' in stripped:
                            if '-Indexes' not in stripped:
                                vulnerable.append({
                                    "type": "htaccess",
                                    "file": htaccess_path,
                                    "line": line_num,
                                    "content": stripped
                                })
            except (PermissionError, IOError):
                pass

    # === 결과 판정 ===
    if vulnerable:
        result["status"] = "취약"
        evidence_lines = []
        for v in vulnerable[:5]:
            evidence_lines.append(f"[{v['type']}] {v['file']}:{v['line']}: {v['content']}")
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = f"디렉토리 리스팅이 활성화된 설정 {len(vulnerable)}건 탐지됨"
        result["recommendation"] = "Apache: Options에서 Indexes 제거 또는 -Indexes 설정. Nginx: autoindex off 설정. .htaccess: Options -Indexes 추가"
    else:
        # 웹 서버 설정 파일 존재 여부 확인
        found_configs = [c for c in apache_configs + nginx_configs if os.path.exists(c)]
        if found_configs:
            result["status"] = "양호"
            result["evidence"] = f"점검 완료: {', '.join(found_configs)} - 디렉토리 리스팅 비활성화 확인"
            result["reason"] = "웹 서버 설정에서 디렉토리 리스팅이 허용되지 않음"
            result["recommendation"] = "-"
        else:
            result["status"] = "N/A"
            result["evidence"] = "Apache/Nginx 설정 파일을 찾을 수 없음"
            result["reason"] = "웹 서버 설정 파일이 기본 경로에 존재하지 않아 점검 불가"
            result["recommendation"] = "웹 서버 설정 파일 경로 확인 후 수동 점검 필요"

    return result


if __name__ == "__main__":
    result = check_directory_listing()
    print(json.dumps(result, ensure_ascii=False, indent=2))
