import os
import re
import json
from datetime import datetime

def check_malicious_js(web_root="/var/www/html"):
    result = {
        "module": "A03-02",
        "ref": "WEB-XSS",
        "category": "웹",
        "title": "악성 JavaScript 삽입 탐지",
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

    # 악성 JavaScript 탐지 패턴
    patterns = [
        r'document\.cookie',
        r'\.send\s*\(',
        r'fetch\s*\(\s*["\']http',
        r'new\s+Image\(\)\.src',
        r'btoa\s*\(',
        r'XMLHttpRequest',
        r'navigator\.sendBeacon',
        r'onkeypress\s*=',
        r'onkeydown\s*=.*\.value',
        r'onkeyup\s*=.*\.value',
        r'addEventListener\s*\(\s*["\']key',
        r'window\.location\s*=.*\+.*cookie',
        r'eval\s*\(\s*atob',
    ]
    combined = re.compile('|'.join(patterns))

    # 점검 대상 확장자
    target_extensions = ('.html', '.htm', '.js', '.php', '.jsp')

    # 로그인 관련 파일 우선 점검
    login_keywords = ['login', 'signin', 'auth', 'session']

    suspects = []

    for root, dirs, files in os.walk(web_root):
        for fname in files:
            if fname.endswith(target_extensions):
                fpath = os.path.join(root, fname)
                is_login_page = any(kw in fname.lower() for kw in login_keywords)
                try:
                    with open(fpath, errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            if combined.search(line):
                                suspects.append({
                                    "file": fpath,
                                    "line": line_num,
                                    "content": line.strip()[:200],
                                    "is_login_page": is_login_page
                                })
                except (PermissionError, IOError):
                    pass

    if suspects:
        result["status"] = "취약"
        # 로그인 페이지 탐지 건수 별도 표시
        login_suspects = [s for s in suspects if s["is_login_page"]]
        other_suspects = [s for s in suspects if not s["is_login_page"]]

        evidence_lines = []
        for s in suspects[:5]:
            tag = "[로그인페이지] " if s["is_login_page"] else ""
            evidence_lines.append(f"{tag}{s['file']}:{s['line']}: {s['content'][:100]}")
        result["evidence"] = " | ".join(evidence_lines)

        reason_parts = [f"웹 디렉토리에서 악성 JavaScript 패턴 {len(suspects)}건 탐지"]
        if login_suspects:
            reason_parts.append(f"로그인 페이지 내 탐지 {len(login_suspects)}건 (계정정보 탈취 위험 높음)")
        result["reason"] = ". ".join(reason_parts)
        result["recommendation"] = "탐지된 스크립트의 정당성을 확인하고, 악성 코드 확인 시 즉시 제거. 웹 페이지 무결성 검증 체계 도입 및 CSP 헤더 적용 권장"
    else:
        result["status"] = "양호"
        result["evidence"] = f"{web_root} 하위 HTML/JS 파일 점검 완료, 악성 패턴 미탐지"
        result["reason"] = "웹 디렉토리 내 악성 JavaScript 삽입 흔적이 존재하지 않음"
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    result = check_malicious_js()
    print(json.dumps(result, ensure_ascii=False, indent=2))
