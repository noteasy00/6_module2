import os
import re
import json
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta


def check_login_anomaly():
    result = {
        "module": "A09-01",
        "ref": "U-66",
        "category": "시스템",
        "title": "비정상 로그인 및 SSH 접근 탐지",
        "target": "/var/log/auth.log, rsyslog, sshd",
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

    auth_log = "/var/log/auth.log"

    FAILED_THRESHOLD = 5
    INVALID_THRESHOLD = 3
    TIME_WINDOW_MINUTES = 5
    SUCCESS_AFTER_FAIL_WINDOW_MINUTES = 10
    MAX_LINES = 5000

    normal_evidence = []
    anomaly_evidence = []
    reason_lines = []
    recommendation_lines = []

    vulnerable = False
    warning = False

    if not os.path.exists(auth_log):
        result["status"] = "취약"
        result["evidence"] = "/var/log/auth.log 파일이 존재하지 않음"
        result["reason"] = "인증 로그 파일이 존재하지 않아 로그인 이상행위 분석이 불가능함"
        result["recommendation"] = "rsyslog 설정 및 인증 로그 기록 정책 확인 필요"
        return result

    normal_evidence.append("/var/log/auth.log 파일 존재 확인")

    try:
        rsyslog_status = subprocess.run(
            ["systemctl", "is-active", "rsyslog"],
            capture_output=True,
            text=True
        ).stdout.strip()

        normal_evidence.append(f"rsyslog status={rsyslog_status}")

        if rsyslog_status != "active":
            vulnerable = True
            anomaly_evidence.append(f"rsyslog 비활성 상태 탐지: status={rsyslog_status}")
            reason_lines.append(f"rsyslog 서비스가 active 상태가 아님(현재: {rsyslog_status})")
            recommendation_lines.append("systemctl enable --now rsyslog 명령으로 로그 서비스를 활성화")

    except Exception as e:
        normal_evidence.append(f"rsyslog 상태 확인 실패: {e}")

    try:
        with open(auth_log, "r", encoding="utf-8", errors="ignore") as f:
            lines = deque(f, maxlen=MAX_LINES)
            lines = list(lines)

        normal_evidence.append(f"최근 로그 {len(lines)}줄 분석")

    except Exception as e:
        result["status"] = "N/A"
        result["evidence"] = f"{auth_log} 읽기 실패: {e}"
        result["reason"] = "인증 로그 파일을 읽을 수 없어 점검 불가"
        result["recommendation"] = "root 권한으로 점검 수행 필요"
        return result

    failed_pattern = re.compile(
        r"(?P<time>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    invalid_pattern = re.compile(
        r"(?P<time>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    accepted_pattern = re.compile(
        r"(?P<time>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    def parse_time(time_str):
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
        except Exception:
            return None

    def format_time(dt):
        if dt is None:
            return "시간 파싱 실패"
        return dt.strftime("%m-%d %H:%M:%S")

    failed_by_ip = defaultdict(list)
    invalid_by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)

    root_success_logs = []
    night_login_logs = []

    total_failed = 0
    total_invalid = 0

    for line in lines:
        failed_match = failed_pattern.search(line)
        if failed_match:
            total_failed += 1
            ip = failed_match.group("ip")
            log_time = parse_time(failed_match.group("time"))
            failed_by_ip[ip].append((log_time, line.strip()))
            continue

        invalid_match = invalid_pattern.search(line)
        if invalid_match:
            total_invalid += 1
            ip = invalid_match.group("ip")
            user = invalid_match.group("user")
            log_time = parse_time(invalid_match.group("time"))
            invalid_by_ip[ip].append((log_time, user, line.strip()))
            continue

        accepted_match = accepted_pattern.search(line)
        if accepted_match:
            ip = accepted_match.group("ip")
            user = accepted_match.group("user")
            log_time = parse_time(accepted_match.group("time"))
            accepted_by_ip[ip].append((log_time, user, line.strip()))

            if user == "root":
                root_success_logs.append((log_time, ip, line.strip()))

            if log_time and 0 <= log_time.hour < 6:
                night_login_logs.append((log_time, ip, user, line.strip()))

    # 1. 반복 로그인 실패 탐지
    brute_force_findings = []

    for ip, events in failed_by_ip.items():
        times = [t for t, _ in events if t is not None]
        total_count = len(events)

        detected = False

        if len(times) >= FAILED_THRESHOLD:
            times.sort()

            for i in range(len(times)):
                start = times[i]
                end = start + timedelta(minutes=TIME_WINDOW_MINUTES)
                window_times = [t for t in times if start <= t <= end]

                if len(window_times) >= FAILED_THRESHOLD:
                    detected = True
                    brute_force_findings.append(
                        f"IP={ip}, 실패 {len(window_times)}회/{TIME_WINDOW_MINUTES}분, "
                        f"시간={format_time(window_times[0])}~{format_time(window_times[-1])}"
                    )
                    break

        if not detected and total_count >= FAILED_THRESHOLD:
            first_time = format_time(events[0][0])
            last_time = format_time(events[-1][0])
            brute_force_findings.append(
                f"IP={ip}, Failed password 총 {total_count}회, 시간={first_time}~{last_time}"
            )

    if brute_force_findings:
        warning = True
        anomaly_evidence.append("반복 로그인 실패: " + " | ".join(brute_force_findings[:5]))
        reason_lines.append("동일 IP에서 반복적인 Failed password 로그가 발생함")
        recommendation_lines.append("반복 실패 IP 확인 및 SSH 접근 제한, 계정 잠금 정책 적용 검토")

    # mock_setup.sh처럼 IP가 여러 개로 분산된 경우 보조 탐지
    if total_failed >= FAILED_THRESHOLD and not brute_force_findings:
        failed_ips = sorted(failed_by_ip.keys())
        anomaly_evidence.append(
            f"전체 Failed password {total_failed}건 탐지, IP={', '.join(failed_ips[:10])}"
        )
        warning = True
        reason_lines.append("반복적인 로그인 실패 로그가 다수 발생함")
        recommendation_lines.append("로그인 실패 원인 및 외부 접근 IP 확인 필요")

    # 2. Invalid user 탐지
    invalid_findings = []

    for ip, events in invalid_by_ip.items():
        total_count = len(events)
        users = sorted(set(user for _, user, _ in events))
        times = [t for t, _, _ in events if t is not None]

        if total_count >= INVALID_THRESHOLD:
            first_time = format_time(times[0]) if times else "시간 파싱 실패"
            last_time = format_time(times[-1]) if times else "시간 파싱 실패"

            invalid_findings.append(
                f"IP={ip}, Invalid user {total_count}회, "
                f"계정={','.join(users[:5])}, 시간={first_time}~{last_time}"
            )

    if invalid_findings:
        warning = True
        anomaly_evidence.append("Invalid user 접근: " + " | ".join(invalid_findings[:5]))
        reason_lines.append("존재하지 않는 계정에 대한 반복 접근이 발생하여 계정 탐색 시도가 의심됨")
        recommendation_lines.append("비정상 접근 IP 차단 및 SSH 접근 허용 대역 제한 검토")

    # 3. root 계정 SSH 로그인 성공 탐지
    if root_success_logs:
        vulnerable = True

        root_details = []
        for log_time, ip, log in root_success_logs[:3]:
            root_details.append(f"IP={ip}, 시간={format_time(log_time)}, 로그={log}")

        anomaly_evidence.append("root SSH 로그인 성공: " + " | ".join(root_details))
        reason_lines.append("root 계정 SSH 로그인 성공 흔적이 존재함")
        recommendation_lines.append("PermitRootLogin no 설정 권장")

    # 4. 반복 실패 후 성공 탐지
    success_after_fail_findings = []

    for ip, failed_events in failed_by_ip.items():
        if ip not in accepted_by_ip:
            continue

        failed_times = [t for t, _ in failed_events if t is not None]
        accepted_events = [
            (t, user, log)
            for t, user, log in accepted_by_ip[ip]
            if t is not None
        ]

        if not failed_times or not accepted_events:
            continue

        for accepted_time, user, log in accepted_events:
            start = accepted_time - timedelta(minutes=SUCCESS_AFTER_FAIL_WINDOW_MINUTES)
            related_failed = [t for t in failed_times if start <= t <= accepted_time]

            if len(related_failed) >= FAILED_THRESHOLD:
                success_after_fail_findings.append(
                    f"IP={ip}, 실패 {len(related_failed)}회 후 로그인 성공, "
                    f"계정={user}, 성공시간={format_time(accepted_time)}"
                )
                break

    if success_after_fail_findings:
        vulnerable = True
        anomaly_evidence.append("반복 실패 후 로그인 성공: " + " | ".join(success_after_fail_findings[:5]))
        reason_lines.append("반복 로그인 실패 이후 로그인 성공이 발생하여 계정 탈취 가능성이 있음")
        recommendation_lines.append("해당 계정 비밀번호 변경, 접속 IP 조사, SSH 인증 정책 강화 필요")

    # 5. 비정상 시간대 로그인 탐지
    if night_login_logs:
        warning = True

        night_details = []
        for log_time, ip, user, log in night_login_logs[:3]:
            night_details.append(
                f"IP={ip}, 계정={user}, 시간={format_time(log_time)}"
            )

        anomaly_evidence.append("비정상 시간대 로그인(00:00~06:00): " + " | ".join(night_details))
        reason_lines.append("비업무 시간대 SSH 로그인 성공 흔적이 존재함")
        recommendation_lines.append("해당 시간대 접속 주체 및 작업 내역 확인 필요")

    # 최종 판정
    if vulnerable:
        result["status"] = "취약"
        result["evidence"] = " | ".join(anomaly_evidence)
        result["reason"] = " | ".join(reason_lines)
        result["recommendation"] = " / ".join(recommendation_lines)

    elif warning:
        result["status"] = "주의"
        result["evidence"] = " | ".join(anomaly_evidence)
        result["reason"] = " | ".join(reason_lines)
        result["recommendation"] = " / ".join(recommendation_lines)

    else:
        result["status"] = "양호"
        result["evidence"] = " | ".join(normal_evidence) + " | 로그인 이상행위 미탐지"
        result["reason"] = "인증 로그가 존재하며 반복 로그인 실패, Invalid user, root 로그인, 반복 실패 후 성공 등 이상행위가 탐지되지 않음"
        result["recommendation"] = "-"

    return result


if __name__ == "__main__":
    result = check_login_anomaly()
    print(json.dumps(result, ensure_ascii=False, indent=2))