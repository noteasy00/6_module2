#!/usr/bin/env python3
"""
OpenAI API 연동 테스트 스크립트
API 키 세팅 후 이 스크립트로 연결 확인

사용법:
  export OPENAI_API_KEY="sk-..."
  python3 test_openai.py
"""

import json
import os
import sys

def test_openai():
    # 1. API 키 확인
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("[X] OPENAI_API_KEY 환경변수가 설정되지 않았습니다.")
        print("    export OPENAI_API_KEY=\"sk-...\" 실행 후 다시 시도하세요.")
        sys.exit(1)
    print(f"[O] API 키 감지됨: {api_key[:8]}...{api_key[-4:]}")

    # 2. openai 패키지 확인
    try:
        from openai import OpenAI
        print("[O] openai 패키지 정상")
    except ImportError:
        print("[X] openai 패키지 미설치")
        print("    pip install openai 실행 후 다시 시도하세요.")
        sys.exit(1)

    # 3. API 호출 테스트 (간단한 질문)
    print("[*] API 호출 테스트 중...")
    client = OpenAI()

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hello, respond with just 'OK'"}],
            max_tokens=10
        )
        print(f"[O] API 응답: {response.choices[0].message.content}")
    except Exception as e:
        print(f"[X] API 호출 실패: {e}")
        sys.exit(1)

    # 4. 실제 취약점 분석 테스트 (scanner.py와 동일한 프롬프트)
    print("[*] 취약점 분석 테스트 중...")

    sample_result = {
        "module": "A03-01",
        "title": "웹셸 의심 파일 탐지",
        "status": "취약",
        "target": "/var/www/html",
        "evidence": "/var/www/html/uploads/cmd.php:1: <?php eval(base64_decode($_POST['cmd'])); ?>",
        "reason": "웹 디렉토리에서 웹셸 의심 패턴 1건 탐지"
    }

    prompt = f"""당신은 리눅스 서버 보안 전문가입니다. 아래 취약점 점검 결과를 분석하여 JSON으로 응답하세요.

점검 항목: {sample_result['title']}
모듈 코드: {sample_result['module']}
상태: {sample_result['status']}
대상: {sample_result['target']}
증거: {sample_result['evidence']}
판단 근거: {sample_result['reason']}

다음 3개 필드를 한국어로 작성하세요:
1. risk_detail: 이 취약점의 구체적 위험성 (2-3문장)
2. attack_scenario: 실제 공격 시나리오 (단계별로 2-3문장)
3. countermeasure: 구체적 대응 방안 (명령어 포함, 2-3문장)

JSON 형식으로만 응답하세요:
{{"risk_detail": "...", "attack_scenario": "...", "countermeasure": "..."}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500,
            response_format={"type": "json_object"}
        )
        ai_result = json.loads(response.choices[0].message.content)
        print("[O] AI 분석 성공!\n")
        print("=" * 50)
        print(f"위험 상세: {ai_result.get('risk_detail', '')}")
        print(f"공격 시나리오: {ai_result.get('attack_scenario', '')}")
        print(f"대응 방안: {ai_result.get('countermeasure', '')}")
        print("=" * 50)

        # 최종 JSON 출력
        sample_result["ai_analysis"] = ai_result
        print("\n[최종 JSON 결과]")
        print(json.dumps(sample_result, ensure_ascii=False, indent=2))

    except Exception as e:
        print(f"[X] AI 분석 실패: {e}")
        sys.exit(1)

    print("\n[O] 모든 테스트 통과! scanner.py에서 --no-ai 없이 실행 가능합니다.")


if __name__ == "__main__":
    test_openai()
