import os
import re
import json
from datetime import datetime

def check_webshell(web_root="/var/www/html"):
    result = {
        "module": "A03-01",
        "ref": "WEB-Webshell",
        "category": "웹",
        "title": "웹셸 의심 파일 탐지",
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

    # 웹셸 탐지 패턴
    patterns = [
        r'eval\s*\(',
        r'base64_decode\s*\(',
        r'system\s*\(',
        r'exec\s*\(',
        r'passthru\s*\(',
        r'shell_exec\s*\(',
        r'proc_open\s*\(',
        r'\$_GET\[.*\]\s*\(',
        r'\$_POST\[.*\]\s*\(',
        r'\$_REQUEST\[.*\]\s*\('
    ]
    combined = re.compile('|'.join(patterns))

    # 점검 대상 확장자
    target_extensions = ('.php', '.jsp', '.asp', '.aspx', '.py', '.cgi', '.pl')

    suspects = []

    for root, dirs, files in os.walk(web_root):
        for fname in files:
            if fname.endswith(target_extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            if combined.search(line):
                                suspects.append({
                                    "file": fpath,
                                    "line": line_num,
                                    "content": line.strip()[:200]
                                })
                except (PermissionError, IOError):
                    pass

    if suspects:
        result["status"] = "취약"
        # evidence에 탐지된 파일 요약
        evidence_lines = []
        for s in suspects[:5]:  # 최대 5건만 표시
            evidence_lines.append(f"{s['file']}:{s['line']}: {s['content'][:100]}")
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = f"웹 디렉토리에서 웹셸 의심 패턴이 포함된 파일 {len(suspects)}건 탐지됨"
        result["recommendation"] = "탐지된 파일의 정당성을 확인하고, 웹셸로 확인 시 즉시 삭제. 파일 업로드 기능에 확장자 필터링 및 실행 권한 제거 필요"
    else:
        result["status"] = "양호"
        result["evidence"] = f"{web_root} 하위 스크립트 파일 점검 완료, 위험 함수 미탐지"
        result["reason"] = "웹 디렉토리 내 웹셸 의심 파일이 존재하지 않음"
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    result = check_webshell()
    print(json.dumps(result, ensure_ascii=False, indent=2))
