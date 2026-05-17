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
from check_login_anomaly import check_login_anomaly


# ── 설정 ──────────────────────────────────────────────────
S3_BUCKET = "awvs-scan-results-team6-v2"
S3_REGION = "ap-northeast-2"
OPENAI_MODEL = "gpt-4o-mini"  # 비용 절감용, gpt-4o도 가능
PROMPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")


# ── 프롬프트 로딩 ────────────────────────────────────────
def load_prompts():
    """prompts/ 디렉토리에서 시스템 프롬프트, ATT&CK 매핑, Few-shot 예시를 로딩"""
    with open(os.path.join(PROMPTS_DIR, "system_prompt.md"), "r", encoding="utf-8") as f:
        system_prompt = f.read()
    with open(os.path.join(PROMPTS_DIR, "attack_mapping.json"), "r", encoding="utf-8") as f:
        attack_mapping = json.load(f)
    with open(os.path.join(PROMPTS_DIR, "few_shot.json"), "r", encoding="utf-8") as f:
        few_shots = json.load(f)
    return system_prompt, attack_mapping, few_shots


def build_user_prompt(result, attack_mapping, few_shots):
    """점검 결과 + ATT&CK 매핑 + Few-shot 예시를 조합하여 user 프롬프트 생성"""
    module_id = result["module"]

    # ATT&CK 매핑 정보 삽입
    mapping = attack_mapping.get(module_id, {})
    attack_context = ""
    if mapping:
        attack_context = f"""
[ATT&CK 매핑 참조]
- Tactic: {mapping.get('tactic', '')}
- Technique: {mapping.get('technique_id', '')} - {mapping.get('technique_name', '')}
- 설명: {mapping.get('description', '')}
"""
        if mapping.get("related"):
            attack_context += f"- 관련 기법: {', '.join(mapping['related'])}\n"

    # Few-shot 예시 선택 (동일 모듈 우선, 없으면 같은 유형)
    example_text = ""
    matched = [fs for fs in few_shots if fs["module"] == module_id]
    if not matched:
        # 카테고리 기반 매칭 (웹 vs 시스템)
        module_type = "web" if module_id.startswith("A03") or module_id.startswith("A05-04") or module_id.startswith("A05-05") else "system"
        matched = [fs for fs in few_shots if fs["type"] == module_type]

    if matched:
        ex = matched[0]
        example_text = f"""
[응답 품질 예시]
입력:
- 항목: {ex['input']['title']}
- 증거: {ex['input']['evidence'][:150]}

기대 출력:
{json.dumps(ex['output'], ensure_ascii=False, indent=2)}
"""

    # 실제 점검 결과
    user_prompt = f"""{attack_context}
{example_text}
[실제 분석 대상]
점검 항목: {result['title']}
모듈 코드: {result['module']}
상태: {result['status']}
대상: {result.get('target', '')}
증거: {result['evidence']}
판단 근거: {result['reason']}

위 점검 결과를 분석하여 JSON으로 응답하세요."""

    return user_prompt


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
        ("A09-01", "비정상 로그인 및 SSH 접근 탐지", lambda: check_login_anomaly()),
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


def ai_analyze(result, system_prompt, attack_mapping, few_shots):
    """
    OpenAI GPT API로 단일 점검 결과에 대한 AI 분석 수행
    prompts/ 디렉토리에서 로딩한 시스템 프롬프트, ATT&CK 매핑, Few-shot을 활용
    """
    try:
        from openai import OpenAI
        client = OpenAI()  # OPENAI_API_KEY 환경변수 사용
    except ImportError:
        print("      [!] openai 패키지 미설치. pip install openai")
        return result
    except Exception as e:
        print(f"      [!] OpenAI 클라이언트 초기화 실패: {e}")
        return result

    # 양호/N/A인 경우 간단 분석 (ATT&CK 매핑 정보는 포함)
    if result["status"] != "취약":
        mapping = attack_mapping.get(result["module"], {})
        result["ai_analysis"] = {
            "risk_detail": "현재 안전한 상태입니다.",
            "attack_scenario": "해당 없음",
            "countermeasure": result.get("recommendation", "-"),
            "mitre_tactic": mapping.get("tactic", "-"),
            "mitre_technique": f"{mapping.get('technique_id', '')} - {mapping.get('technique_name', '')}" if mapping else "-"
        }
        return result

    # 프롬프트 조립
    user_prompt = build_user_prompt(result, attack_mapping, few_shots)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            max_tokens=700,
            response_format={"type": "json_object"}
        )
        ai_result = json.loads(response.choices[0].message.content)

        # 필수 필드 검증 및 기본값 처리
        required_fields = ["risk_detail", "attack_scenario", "countermeasure", "mitre_tactic", "mitre_technique"]
        for field in required_fields:
            if not ai_result.get(field):
                mapping = attack_mapping.get(result["module"], {})
                if field == "mitre_tactic":
                    ai_result[field] = mapping.get("tactic", "Unknown")
                elif field == "mitre_technique":
                    ai_result[field] = f"{mapping.get('technique_id', '')} - {mapping.get('technique_name', '')}"
                else:
                    ai_result[field] = ""

        result["ai_analysis"] = {
            "risk_detail": ai_result.get("risk_detail", ""),
            "attack_scenario": ai_result.get("attack_scenario", ""),
            "countermeasure": ai_result.get("countermeasure", ""),
            "mitre_tactic": ai_result.get("mitre_tactic", ""),
            "mitre_technique": ai_result.get("mitre_technique", "")
        }
    except Exception as e:
        print(f"      [!] AI 분석 실패: {e}")
        # 실패 시에도 ATT&CK 매핑 정보는 채워줌
        mapping = attack_mapping.get(result["module"], {})
        result["ai_analysis"] = {
            "risk_detail": "",
            "attack_scenario": "",
            "countermeasure": "",
            "mitre_tactic": mapping.get("tactic", ""),
            "mitre_technique": f"{mapping.get('technique_id', '')} - {mapping.get('technique_name', '')}" if mapping else ""
        }

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
        print("\n[2/3] AI 분석 수행 (OpenAI GPT + ATT&CK 매핑)")
        try:
            system_prompt, attack_mapping, few_shots = load_prompts()
            print(f"      프롬프트 로딩 완료 (모듈 매핑 {len(attack_mapping)}건, Few-shot {len(few_shots)}건)")
        except FileNotFoundError as e:
            print(f"      [!] 프롬프트 파일 로딩 실패: {e}")
            print("      [!] prompts/ 디렉토리를 확인하세요. AI 분석을 건너뜁니다.")
            system_prompt, attack_mapping, few_shots = None, {}, []

        if system_prompt:
            for i, result in enumerate(results):
                print(f"  [*] {result['module']} AI 분석 중...")
                results[i] = ai_analyze(result, system_prompt, attack_mapping, few_shots)
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
