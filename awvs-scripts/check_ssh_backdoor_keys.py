import os
import re

def parse_ssh_line(line):
    """
    SSH authorized_keys 한 줄을 구조적으로 분해
    return: options, key_type, key, comment
    """
    parts = line.split()

    if len(parts) < 2:
        return None

    options = []
    i = 0

    # options (key_type 나오기 전까지)
    while i < len(parts) and "=" in parts[i]:
        options.append(parts[i])
        i += 1

    if i >= len(parts):
        return None

    key_type = parts[i]
    i += 1

    if i >= len(parts):
        return None

    key = parts[i]
    i += 1

    comment = " ".join(parts[i:]) if i < len(parts) else ""

    return options, key_type, key, comment


def mask_key(line):
    """SSH 키 원문을 마스킹하여 증거로 안전하게 표시"""
    parsed = parse_ssh_line(line)
    if not parsed:
        return line[:60] + "..." if len(line) > 60 else line

    options, key_type, key, comment = parsed
    masked_key = key[:12] + "..." + key[-8:] if len(key) > 20 else key
    parts = []
    if options:
        # command= 옵션은 값도 축약
        masked_opts = []
        for opt in options:
            if opt.startswith("command=") and len(opt) > 30:
                masked_opts.append("command=\"...\"")
            else:
                masked_opts.append(opt)
        parts.append(",".join(masked_opts))
    parts.append(key_type)
    parts.append(masked_key)
    if comment:
        parts.append(comment)
    return " ".join(parts)


def check_ssh_backdoor_keys():

    file_path = "/root/.ssh/authorized_keys"

    result = {
        "module": "A08-01",
        "ref": "U-23",
        "category": "시스템",
        "title": "SSH 백도어 의심 키 존재 여부",
        "target": file_path,
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

    # === 파일 존재 여부 ===
    if not os.path.exists(file_path):
        result["status"] = "N/A"
        result["evidence"] = "파일 없음"
        result["reason"] = "authorized_keys 파일이 존재하지 않아 점검 불가"
        result["recommendation"] = "-"
        return result

    # === 위험 옵션 ===
    dangerous_options = [
        "command=",
        "from=",
        "no-port-forwarding",
        "no-agent-forwarding",
        "no-X11-forwarding",
        "no-pty"
    ]

    # === AWS EC2 기본 root 키 화이트리스트 ===
    aws_ec2_whitelist = [
        "Please login as the user",
    ]

    # === 키워드 기반 의심 ===
    suspicious_patterns = [
        r"\btest\b",
        r"\bdebug\b",
        r"\bbackup\b",
        r"\btemp\b",
        r"attacker",
        r"evil",
        r"unauthorized"
    ]

    suspicious_found = []
    invalid_lines = []
    valid_keys = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parsed = parse_ssh_line(line)

            # === 형식 오류 ===
            if not parsed:
                invalid_lines.append(line)
                continue

            options, key_type, key, comment = parsed
            valid_keys.append(line)

            # === AWS EC2 기본 키 화이트리스트 체크 ===
            is_whitelisted = False
            for wl in aws_ec2_whitelist:
                if wl in line:
                    is_whitelisted = True
                    break
            if is_whitelisted:
                continue

            full_text = " ".join(options + [comment]).lower()

            # === 1. 위험 옵션 탐지 ===
            for opt in options:
                for danger in dangerous_options:
                    if danger in opt:
                        suspicious_found.append(line)
                        break

            # === 2. 패턴 기반 탐지 ===
            for pattern in suspicious_patterns:
                if re.search(pattern, full_text):
                    suspicious_found.append(line)
                    break

        # === 판단 로직 ===
        if suspicious_found:
            result["status"] = "취약"
            result["evidence"] = "\n".join(mask_key(k) for k in set(suspicious_found))
            result["reason"] = "SSH 키에서 위험 옵션(command/from/no-forwarding 등) 또는 의심 패턴 탐지"
            result["recommendation"] = "의심 SSH 키 제거 및 authorized_keys 재검증 필요"

        elif invalid_lines:
            result["status"] = "취약"
            result["evidence"] = "\n".join(line[:60] + "..." if len(line) > 60 else line for line in invalid_lines)
            result["reason"] = "SSH 공개키 형식이 올바르지 않은 항목 존재"
            result["recommendation"] = "authorized_keys 파일 정리 및 비정상 키 제거"

        elif valid_keys:
            result["status"] = "양호"
            result["evidence"] = f"정상 SSH 공개키 {len(valid_keys)}건 확인 (키 내용 마스킹 처리)"
            result["reason"] = "정상 SSH 공개키만 존재"
            result["recommendation"] = "-"

        else:
            result["status"] = "취약"
            result["evidence"] = "유효한 SSH 공개키 없음"
            result["reason"] = "authorized_keys 파일이 비어 있음"
            result["recommendation"] = "승인된 SSH 키 등록 필요"

    except Exception as e:
        result["status"] = "취약"
        result["evidence"] = str(e)
        result["reason"] = "파일 읽기 중 오류 발생"
        result["recommendation"] = "파일 권한 및 상태 확인 필요"

    return result


if __name__ == "__main__":
    import json
    result = check_ssh_backdoor_keys()
    print(json.dumps(result, ensure_ascii=False, indent=2))