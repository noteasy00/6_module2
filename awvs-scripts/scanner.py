#!/usr/bin/env python3
"""
AWVS Scanner - 통합 실행 스크립트
모든 점검 모듈을 실행하고, OpenAI GPT API로 AI 분석을 수행한 뒤,
결과를 S3에 업로드합니다.

사용법:
  python3 scanner.py                          # 전체 스캔 실행
  python3 scanner.py --no-ai                  # AI 분석 없이 스캔만
  python3 scanner.py --no-s3                  # S3 업로드 없이 로컬 저장만
  python3 scanner.py --web-root /var/www/html  # 웹 루트 지정
"""

import os
import sys
import json
import socket
import argparse
from datetime import datetime


# ── .env 파일 로딩 ────────────────────────────────────────
def load_env(env_path=None):
    """스크립트 폴더의 .env 파일에서 환경변수 로딩"""
    if env_path is None:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

load_env()

# ── 점검 모듈 임포트 ──────────────────────────────────────
from check_webshell import check_webshell
from check_malicious_js import check_malicious_js
from check_directory_listing import check_directory_listing
from check_ssh_root import check_ssh_root
from check_account_lock_threshold import check_account_lock_threshold
from check_sensitive_files import check_sensitive_files
from check_crontab import check_crontab
from check_sudoers import check_sudoers
from check_ssh_backdoor_keys import check_ssh_backdoor_keys


# ── 설정 ──────────────────────────────────────────────────
S3_BUCKET = "awvs-scan-results-team6-v2"
S3_REGION = "ap-northeast-2"
OPENAI_MODEL = "gpt-4o-mini"  # 비용 절감용, gpt-4o도 가능


def get_server_info():
    """서버 기본 정보 수집"""
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = "unknown"
    return hostname, ip


def run_all_modules(web_root="/var/www/html"):
    """등록된 모든 점검 모듈 실행"""
    modules = [
        ("A03-01", "웹셸 의심 파일 탐지", lambda: check_webshell(web_root)),
        ("A03-02", "악성 JavaScript 삽입 탐지", lambda: check_malicious_js(web_root)),
        ("A05-04", "디렉토리 리스팅 점검", lambda: check_directory_listing(web_root)),
        ("A05-01", "root 계정 원격 접속 제한", lambda: check_ssh_root()),
        ("A07-01", "계정 잠금 임계값 설정", lambda: check_account_lock_threshold()),
        ("A05-05", "민감 파일 노출 점검", lambda: check_sensitive_files(web_root)),
        ("A01-03", "crontab 악성 스케줄 점검", lambda: check_crontab()),
        ("A05-06", "sudo 권한 과다 부여", lambda: check_sudoers()),
        ("A08-01", "SSH 백도어 의심 키 탐지", lambda: check_ssh_backdoor_keys()),
    ]

    results = []
    for module_id, title, func in modules:
        print(f"  [*] {module_id} {title} 점검 중...")
        try:
            result = func()
            results.append(result)
            status_icon = "!" if result["status"] == "취약" else "?" if result["status"] == "주의" else "O" if result["status"] == "양호" else "-"
            print(f"      [{status_icon}] {result['status']}")
        except Exception as e:
            print(f"      [E] 오류 발생: {e}")
            results.append({
                "module": module_id,
                "title": title,
                "status": "N/A",
                "evidence": f"모듈 실행 오류: {str(e)}",
                "reason": "점검 스크립트 실행 중 예외 발생",
                "recommendation": "스크립트 오류 확인 필요",
                "ai_analysis": {"risk_detail": "", "attack_scenario": "", "countermeasure": ""}
            })

    return results


def ai_analyze(result):
    """OpenAI GPT API로 단일 점검 결과에 대한 AI 분석 수행"""
    try:
        from openai import OpenAI
        client = OpenAI()  # OPENAI_API_KEY 환경변수 사용
    except ImportError:
        print("      [!] openai 패키지 미설치. pip install openai")
        return result
    except Exception as e:
        print(f"      [!] OpenAI 클라이언트 초기화 실패: {e}")
        return result

    # 양호/N/A인 경우 간단 분석
    if result["status"] != "취약":
        result["ai_analysis"] = {
            "risk_detail": "현재 안전한 상태입니다.",
            "attack_scenario": "해당 없음",
            "countermeasure": result.get("recommendation", "-")
        }
        return result

    prompt = f"""당신은 리눅스 서버 보안 전문가입니다. 아래 취약점 점검 결과를 분석하여 JSON으로 응답하세요.

점검 항목: {result['title']}
모듈 코드: {result['module']}
상태: {result['status']}
대상: {result.get('target', '')}
증거: {result['evidence']}
판단 근거: {result['reason']}

다음 3개 필드를 한국어로 작성하세요:
1. risk_detail: 이 취약점의 구체적 위험성 (2-3문장)
2. attack_scenario: 실제 공격 시나리오 (단계별로 2-3문장)
3. countermeasure: 구체적 대응 방안 (명령어 포함, 2-3문장)

JSON 형식으로만 응답하세요:
{{"risk_detail": "...", "attack_scenario": "...", "countermeasure": "..."}}"""

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500,
            response_format={"type": "json_object"}
        )
        ai_result = json.loads(response.choices[0].message.content)
        result["ai_analysis"] = {
            "risk_detail": ai_result.get("risk_detail", ""),
            "attack_scenario": ai_result.get("attack_scenario", ""),
            "countermeasure": ai_result.get("countermeasure", "")
        }
    except Exception as e:
        print(f"      [!] AI 분석 실패: {e}")

    return result


def upload_to_s3(scan_data, filename):
    """결과를 S3에 업로드"""
    try:
        import boto3
        s3 = boto3.client("s3", region_name=S3_REGION)
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"results/{filename}",
            Body=json.dumps(scan_data, ensure_ascii=False, indent=2),
            ContentType="application/json"
        )
        print(f"\n  [+] S3 업로드 완료: s3://{S3_BUCKET}/results/{filename}")
        return True
    except ImportError:
        print("\n  [!] boto3 패키지 미설치. pip install boto3")
        return False
    except Exception as e:
        print(f"\n  [!] S3 업로드 실패: {e}")
        return False


def save_local(scan_data, filename):
    """결과를 로컬 파일로 저장"""
    output_dir = os.path.expanduser("~/awvs-results")
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, ensure_ascii=False, indent=2)
    print(f"  [+] 로컬 저장 완료: {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(description="AWVS 통합 보안 스캐너")
    parser.add_argument("--no-ai", action="store_true", help="AI 분석 건너뛰기")
    parser.add_argument("--no-s3", action="store_true", help="S3 업로드 건너뛰기")
    parser.add_argument("--web-root", default="/var/www/html", help="웹 루트 디렉토리")
    args = parser.parse_args()

    print("=" * 60)
    print("  AWVS - AI 기반 리눅스 서버 침해흔적 분석 시스템")
    print("=" * 60)

    # 서버 정보
    hostname, ip = get_server_info()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n  서버: {hostname} ({ip})")
    print(f"  시간: {scan_time}")
    print(f"  웹루트: {args.web_root}")
    print("-" * 60)

    # 1. 모듈 실행
    print("\n[1/3] 취약점 점검 실행")
    results = run_all_modules(args.web_root)

    # 2. AI 분석
    if not args.no_ai:
        print("\n[2/3] AI 분석 수행 (OpenAI GPT)")
        for i, result in enumerate(results):
            print(f"  [*] {result['module']} AI 분석 중...")
            results[i] = ai_analyze(result)
            print(f"      완료")
    else:
        print("\n[2/3] AI 분석 건너뜀 (--no-ai)")

    # 결과 종합
    scan_data = {
        "scan_time": scan_time,
        "server": hostname,
        "server_ip": ip,
        "results": results
    }

    # 통계
    vuln_count = sum(1 for r in results if r["status"] == "취약")
    warn_count = sum(1 for r in results if r["status"] == "주의")
    safe_count = sum(1 for r in results if r["status"] == "양호")
    na_count = sum(1 for r in results if r["status"] == "N/A")
    print(f"\n  결과: 취약 {vuln_count}건 / 주의 {warn_count}건 / 양호 {safe_count}건 / N/A {na_count}건")

    # 3. 저장
    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # 로컬 저장 (항상)
    print(f"\n[3/3] 결과 저장")
    local_path = save_local(scan_data, filename)

    # S3 업로드
    if not args.no_s3:
        upload_to_s3(scan_data, filename)
    else:
        print("  S3 업로드 건너뜀 (--no-s3)")

    print("\n" + "=" * 60)
    print("  스캔 완료!")
    print("=" * 60)

    return scan_data


if __name__ == "__main__":
    main()
