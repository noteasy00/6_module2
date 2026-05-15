import os
import re


def check_account_lock_threshold():
    result = {
        "module": "A07-01",
        "ref": "U-03",
        "category": "시스템",
        "title": "계정 잠금 임계값 설정",
        "target": "/etc/pam.d/common-auth",
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

    target_file = "/etc/pam.d/common-auth"

    # 파일 존재 여부 확인
    if not os.path.exists(target_file):
        result["status"] = "N/A"
        result["evidence"] = f"{target_file} 파일 없음"
        result["reason"] = "PAM 인증 설정 파일이 존재하지 않아 점검할 수 없습니다."
        result["recommendation"] = "-"
        return result

    try:
        with open(target_file, "r") as f:
            lines = f.readlines()

        faillock_lines = []
        deny_values = []

        for line in lines:
            line_strip = line.strip()

            # 빈 줄 및 주석 제외
            if not line_strip or line_strip.startswith("#"):
                continue

            # pam_faillock 또는 pam_tally2 설정 탐지
            if "pam_faillock.so" in line_strip or "pam_tally2.so" in line_strip:
                faillock_lines.append(line_strip)

                # deny 값 추출
                deny_match = re.search(r"deny=(\d+)", line_strip)

                if deny_match:
                    deny_values.append(int(deny_match.group(1)))

        # 계정 잠금 설정 자체가 없는 경우
        if not faillock_lines:
            result["status"] = "취약"
            result["evidence"] = "pam_faillock / pam_tally2 설정 미존재"
            result["reason"] = (
                "계정 잠금 임계값 설정이 존재하지 않아 "
                "무차별 대입 공격(Brute Force)에 취약합니다."
            )
            result["recommendation"] = (
                "pam_faillock 또는 pam_tally2 모듈을 사용하여 "
                "계정 잠금 임계값을 10회 이하로 설정하십시오."
            )
            return result

        # deny 값이 없는 경우
        if not deny_values:
            result["status"] = "취약"
            result["evidence"] = " / ".join(faillock_lines)
            result["reason"] = (
                "계정 잠금 모듈은 설정되어 있으나 "
                "deny 값이 존재하지 않습니다."
            )
            result["recommendation"] = (
                "pam_faillock 또는 pam_tally2 설정에 "
                "deny 값을 추가하여 10 이하로 설정하십시오."
            )
            return result

        # 가장 큰 deny 값 기준으로 판단
        max_deny = max(deny_values)

        if max_deny <= 10:
            result["status"] = "양호"
            result["evidence"] = " / ".join(faillock_lines)
            result["reason"] = (
                f"계정 잠금 임계값이 최대 {max_deny}회로 "
                "10회 이하로 설정되어 있습니다."
            )
            result["recommendation"] = "-"

        else:
            result["status"] = "취약"
            result["evidence"] = " / ".join(faillock_lines)
            result["reason"] = (
                f"계정 잠금 임계값이 최대 {max_deny}회로 "
                "10회를 초과합니다."
            )
            result["recommendation"] = (
                "pam_faillock 또는 pam_tally2 설정의 "
                "deny 값을 10 이하로 변경하십시오."
            )

    except Exception as e:
        result["status"] = "N/A"
        result["evidence"] = str(e)
        result["reason"] = "점검 중 오류가 발생했습니다."
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    import json

    result = check_account_lock_threshold()
    print(json.dumps(result, ensure_ascii=False, indent=2))
