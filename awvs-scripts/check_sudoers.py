import os
import stat
import pwd
import grp
import json
import re
from glob import glob


def check_sudoers():
    result = {
        "module": "A05-04",
        "ref": "U-63",
        "category": "시스템",
        "title": "sudo 권한 과다 부여",
        "target": "/etc/sudoers, /etc/sudoers.d/*, sudo 그룹",
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

    sudoers_path = "/etc/sudoers"
    sudoers_dir = "/etc/sudoers.d"

    ignored_files = {
        "/etc/sudoers.d/90-cloud-init-users"
    }

    evidence_lines = []
    reason_lines = []
    recommendation_lines = []
    vulnerable = False

    if not os.path.exists(sudoers_path):
        result["status"] = "N/A"
        result["evidence"] = "/etc/sudoers 파일이 존재하지 않음"
        result["reason"] = "sudoers 정책 파일이 없어 sudo 권한 설정을 점검할 수 없음"
        result["recommendation"] = "sudo 패키지 설치 여부와 /etc/sudoers 파일 존재 여부 확인 필요"
        return result

    try:
        st = os.stat(sudoers_path)
        owner = pwd.getpwuid(st.st_uid).pw_name
        mode = stat.S_IMODE(st.st_mode)
        mode_oct = format(mode, "03o")

        evidence_lines.append(f"/etc/sudoers owner={owner}, permission={mode_oct}")

        if owner != "root":
            vulnerable = True
            reason_lines.append(f"/etc/sudoers 파일 소유자가 root가 아님(현재: {owner})")
            recommendation_lines.append("chown root /etc/sudoers")

        if mode > 0o640:
            vulnerable = True
            reason_lines.append(f"/etc/sudoers 파일 권한이 640을 초과함(현재: {mode_oct})")
            recommendation_lines.append("chmod 640 /etc/sudoers")

    except Exception as e:
        result["status"] = "N/A"
        result["evidence"] = f"/etc/sudoers 상태 확인 실패: {e}"
        result["reason"] = "sudoers 파일 상태를 확인할 수 없어 점검 불가"
        result["recommendation"] = "root 권한으로 점검 수행 필요"
        return result

    policy_files = [sudoers_path]

    if os.path.isdir(sudoers_dir):
        for path in glob(os.path.join(sudoers_dir, "*")):
            if os.path.isfile(path):
                policy_files.append(path)

    nopasswd_all_pattern = re.compile(r"NOPASSWD\s*:\s*ALL", re.IGNORECASE)
    broad_all_pattern = re.compile(
        r"^\s*(?P<subject>[A-Za-z0-9_.%-]+)\s+ALL\s*=\s*\(\s*ALL(?::ALL)?\s*\)\s*ALL\s*$",
        re.IGNORECASE
    )

    allowed_default_subjects = {"root", "%sudo", "%admin"}
    suspicious_rules = []

    for file_path in policy_files:
        if file_path in ignored_files:
            evidence_lines.append(f"예외 처리된 기본 정책 파일: {file_path}")
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    stripped = line.strip()

                    if not stripped or stripped.startswith("#"):
                        continue

                    if nopasswd_all_pattern.search(stripped):
                        vulnerable = True
                        suspicious_rules.append(f"{file_path}:{line_no}: {stripped}")
                        continue

                    match = broad_all_pattern.match(stripped)
                    if match:
                        subject = match.group("subject")

                        if subject not in allowed_default_subjects:
                            vulnerable = True
                            suspicious_rules.append(f"{file_path}:{line_no}: {stripped}")

        except Exception as e:
            evidence_lines.append(f"{file_path} 읽기 실패: {e}")

    if suspicious_rules:
        shown_rules = suspicious_rules[:5]
        evidence_lines.append("광범위 sudo 권한 탐지: " + " | ".join(shown_rules))
        reason_lines.append("일반 사용자에게 NOPASSWD:ALL 또는 광범위 sudo 권한이 부여되어 있음")
        recommendation_lines.append("불필요한 NOPASSWD:ALL 및 일반 사용자 대상 ALL=(ALL) ALL 권한 제거")

    try:
        sudo_group = grp.getgrnam("sudo")
        sudo_users = sudo_group.gr_mem

        if sudo_users:
            evidence_lines.append("sudo 그룹 사용자: " + ", ".join(sudo_users))
        else:
            evidence_lines.append("sudo 그룹 사용자 없음")

    except KeyError:
        evidence_lines.append("sudo 그룹이 존재하지 않음")

    if vulnerable:
        result["status"] = "취약"
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = " / ".join(reason_lines)
        result["recommendation"] = " / ".join(recommendation_lines)
    else:
        result["status"] = "양호"
        result["evidence"] = " | ".join(evidence_lines)
        result["reason"] = (
            "/etc/sudoers 파일 소유자가 root이고 권한이 640 이하이며, "
            "일반 사용자 대상 NOPASSWD:ALL 또는 광범위 sudo 권한이 탐지되지 않음"
        )
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    result = check_sudoers()
    print(json.dumps(result, ensure_ascii=False, indent=2))