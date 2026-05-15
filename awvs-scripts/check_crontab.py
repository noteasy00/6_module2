import os
import re
import json

def check_crontab():
    result = {
        "module": "A01-03",
        "ref": "SRV-012",
        "category": "시스템",
        "title": "crontab 악성 스케줄 점검",
        "target": "/etc/crontab, /etc/cron.d/, /var/spool/cron/",
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

    # 악성 패턴 (리버스 셸, 외부 다운로드, 인코딩 실행 등)
    suspicious_patterns = [
        r'bash\s+-i\s+>&\s*/dev/tcp',         # bash 리버스 셸
        r'/dev/tcp/',                           # TCP 리다이렉션
        r'nc\s+-e',                             # netcat 리버스 셸
        r'ncat\s.*-e',                          # ncat 리버스 셸
        r'curl\s+.*\|\s*bash',                  # curl 파이프 bash
        r'curl\s+.*\|\s*sh',                    # curl 파이프 sh
        r'wget\s+.*\|\s*bash',                  # wget 파이프 bash
        r'wget\s+.*\|\s*sh',                    # wget 파이프 sh
        r'python.*-c\s+.*import\s+socket',      # python 리버스 셸
        r'perl.*-e\s+.*socket',                 # perl 리버스 셸
        r'base64\s+-d\s*\|',                    # base64 디코딩 실행
        r'eval\s+.*base64',                     # eval base64
        r'mkfifo',                              # named pipe (리버스 셸)
        r'\\x[0-9a-fA-F]{2}',                   # 헥스 인코딩
        r'chmod\s+777',                         # 과도한 권한 부여
        r'rm\s+-rf\s+/',                        # 시스템 파괴
    ]
    combined = re.compile('|'.join(suspicious_patterns))

    # 점검 대상 경로
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/var/spool/cron/crontabs/",
    ]

    # 사용자별 crontab
    user_crontabs = []
    for cron_dir in ["/var/spool/cron/", "/var/spool/cron/crontabs/"]:
        if os.path.isdir(cron_dir):
            try:
                for fname in os.listdir(cron_dir):
                    user_crontabs.append(os.path.join(cron_dir, fname))
            except PermissionError:
                pass

    # 시스템 cron 파일들
    system_crons = ["/etc/crontab"]
    if os.path.isdir("/etc/cron.d/"):
        try:
            for fname in os.listdir("/etc/cron.d/"):
                system_crons.append(os.path.join("/etc/cron.d/", fname))
        except PermissionError:
            pass

    all_cron_files = system_crons + user_crontabs
    suspects = []
    checked_files = 0

    for cron_file in all_cron_files:
        if not os.path.isfile(cron_file):
            continue
        try:
            with open(cron_file, errors='ignore') as f:
                checked_files += 1
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    # 빈 줄, 주석, 환경변수 설정 제외
                    if not stripped or stripped.startswith("#") or "=" in stripped.split()[0] if stripped.split() else True:
                        continue
                    if combined.search(stripped):
                        suspects.append({
                            "file": cron_file,
                            "line": line_num,
                            "content": stripped[:200]
                        })
        except (PermissionError, IOError):
            pass

    if suspects:
        result["status"] = "취약"
        evidence_lines = []
        for s in suspects[:5]:
            evidence_lines.append(f"{s['file']}:{s['line']}: {s['content'][:100]}")
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = f"crontab에서 악성 의심 스케줄 {len(suspects)}건 탐지됨"
        result["recommendation"] = "탐지된 cron 항목의 정당성을 확인하고, 악성 스케줄 확인 시 즉시 제거. crontab -l 로 사용자별 등록 현황 점검"
    elif checked_files > 0:
        result["status"] = "양호"
        result["evidence"] = f"crontab 파일 {checked_files}건 점검 완료, 악성 패턴 미탐지"
        result["reason"] = "시스템 및 사용자 crontab에서 악성 의심 스케줄이 발견되지 않음"
        result["recommendation"] = "-"
    else:
        result["status"] = "N/A"
        result["evidence"] = "점검 가능한 crontab 파일 없음"
        result["reason"] = "crontab 파일에 접근할 수 없거나 존재하지 않음"
        result["recommendation"] = "crontab 파일 권한 확인 후 수동 점검 필요"

    return result


if __name__ == "__main__":
    result = check_crontab()
    print(json.dumps(result, ensure_ascii=False, indent=2))
