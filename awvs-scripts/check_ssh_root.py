import os

def check_ssh_root():
    result = {
        "module": "A05-01",
        "ref": "U-01",
        "category": "시스템",
        "title": "root 계정 원격 접속 제한",
        "target": "/etc/ssh/sshd_config",
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

    config_file = "/etc/ssh/sshd_config"

    # SSH 설정 파일 존재 여부 확인
    if not os.path.exists(config_file):
        result["status"] = "N/A"
        result["evidence"] = "SSH 설정 파일이 존재하지 않음"
        result["reason"] = "SSH 서비스를 사용하지 않거나 OpenSSH가 설치되지 않음"
        result["recommendation"] = "-"
        return result

    found = False

    try:
        with open(config_file, "r") as f:
            for line in f:
                line = line.strip()

                # 빈 줄 및 주석 제외
                if not line or line.startswith("#"):
                    continue

                # PermitRootLogin 설정 확인
                if line.startswith("PermitRootLogin"):
                    found = True
                    result["evidence"] = line

                    parts = line.split()

                    if len(parts) < 2:
                        continue

                    value = parts[1].lower()

                    # root 직접 접속 허용
                    if value == "yes":
                        result["status"] = "취약"
                        result["reason"] = "SSH 원격 접속에서 root 계정 직접 로그인이 허용되어 있음"
                        result["recommendation"] = "PermitRootLogin 값을 no로 변경하여 root 직접 접속을 차단하세요."
                        return result

                    # root 직접 접속 차단
                    elif value in ["no", "prohibit-password", "forced-commands-only"]:
                        result["status"] = "양호"
                        result["reason"] = "SSH 원격 접속에서 root 계정 직접 로그인이 제한되어 있음"
                        result["recommendation"] = "-"
                        return result

        # PermitRootLogin 설정이 없는 경우
        if not found:
            result["status"] = "취약"
            result["evidence"] = "PermitRootLogin 설정이 명시되지 않음"
            result["reason"] = "SSH 설정 파일에 root 로그인 제한 설정이 존재하지 않음"
            result["recommendation"] = "PermitRootLogin no 설정을 명시적으로 추가하세요."

    except Exception as e:
        result["status"] = "N/A"
        result["evidence"] = str(e)
        result["reason"] = "점검 중 오류 발생"
        result["recommendation"] = "파일 권한 및 SSH 설정 상태를 확인하세요."

    return result


if __name__ == "__main__":
    import json
    result = check_ssh_root()
    print(json.dumps(result, ensure_ascii=False, indent=2))
