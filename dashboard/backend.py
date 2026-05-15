"""
AWVS 대시보드 백엔드 모듈
Streamlit 대시보드에서 import해서 사용

사용법:
    from backend import trigger_scan, get_latest_scan, get_all_scans

필요 패키지:
    pip install boto3 requests
"""

import json
import boto3
import requests
from datetime import datetime

# ── 설정 ──────────────────────────────────────────────────
API_GATEWAY_URL = "https://rxb381zufb.execute-api.ap-northeast-2.amazonaws.com/prod/scan"
S3_BUCKET = "awvs-scan-results-team6-v2"
S3_REGION = "ap-northeast-2"
S3_PREFIX = "results/"


def trigger_scan():
    """
    API Gateway를 통해 스캔 실행
    Lambda → SSM → EC2 scanner.py 트리거

    Returns:
        dict: {"status": "Success/Failed", "output": "...", "error": "..."}
    """
    try:
        response = requests.post(API_GATEWAY_URL, timeout=300)
        result = response.json()

        # body가 문자열이면 한번 더 파싱
        if isinstance(result.get("body"), str):
            result = json.loads(result["body"])

        return {"success": True, "data": result}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "스캔 타임아웃 (5분 초과)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_s3_client():
    """S3 클라이언트 생성"""
    return boto3.client("s3", region_name=S3_REGION)


def get_latest_scan():
    """
    S3에서 가장 최근 스캔 결과 가져오기

    Returns:
        dict: 스캔 결과 JSON (scan_time, server, server_ip, results[])
        None: 결과 없음
    """
    try:
        s3 = get_s3_client()
        response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=S3_PREFIX)

        if "Contents" not in response:
            return None

        # 최신 파일 찾기
        files = [f for f in response["Contents"] if f["Key"].endswith(".json")]
        if not files:
            return None

        latest = sorted(files, key=lambda x: x["LastModified"], reverse=True)[0]
        obj = s3.get_object(Bucket=S3_BUCKET, Key=latest["Key"])
        data = json.loads(obj["Body"].read().decode("utf-8"))
        data["_s3_key"] = latest["Key"]
        return data
    except Exception as e:
        return {"error": str(e)}


def get_all_scans(limit=10):
    """
    S3에서 최근 스캔 결과 목록 가져오기

    Args:
        limit: 최대 조회 건수

    Returns:
        list[dict]: 스캔 결과 리스트 (최신순)
    """
    try:
        s3 = get_s3_client()
        response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=S3_PREFIX)

        if "Contents" not in response:
            return []

        files = [f for f in response["Contents"] if f["Key"].endswith(".json")]
        files = sorted(files, key=lambda x: x["LastModified"], reverse=True)[:limit]

        scans = []
        for f in files:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=f["Key"])
            data = json.loads(obj["Body"].read().decode("utf-8"))
            data["_s3_key"] = f["Key"]
            scans.append(data)

        return scans
    except Exception as e:
        return [{"error": str(e)}]


def parse_scan_summary(scan_data):
    """
    스캔 결과를 대시보드 메트릭용으로 파싱

    Args:
        scan_data: get_latest_scan()의 리턴값

    Returns:
        dict: {
            "scan_time", "server", "server_ip",
            "total", "vuln_count", "warn_count", "safe_count", "na_count",
            "risk_level", "results"
        }
    """
    if not scan_data or "error" in scan_data:
        return None

    results = scan_data.get("results", [])
    vuln = sum(1 for r in results if r["status"] == "취약")
    warn = sum(1 for r in results if r["status"] == "주의")
    safe = sum(1 for r in results if r["status"] == "양호")
    na = sum(1 for r in results if r["status"] == "N/A")

    if vuln >= 3:
        risk_level = "Critical"
    elif vuln >= 1:
        risk_level = "High"
    elif warn >= 1:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "scan_time": scan_data.get("scan_time", ""),
        "server": scan_data.get("server", ""),
        "server_ip": scan_data.get("server_ip", ""),
        "total": len(results),
        "vuln_count": vuln,
        "warn_count": warn,
        "safe_count": safe,
        "na_count": na,
        "risk_level": risk_level,
        "results": results
    }


def get_vuln_items(scan_data):
    """취약 항목만 필터링"""
    if not scan_data:
        return []
    return [r for r in scan_data.get("results", []) if r["status"] == "취약"]


def get_warn_items(scan_data):
    """주의 항목만 필터링"""
    if not scan_data:
        return []
    return [r for r in scan_data.get("results", []) if r["status"] == "주의"]


# ── 테스트용 ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== S3 최신 스캔 결과 조회 ===")
    scan = get_latest_scan()
    if scan and "error" not in scan:
        summary = parse_scan_summary(scan)
        print(f"스캔 시간: {summary['scan_time']}")
        print(f"서버: {summary['server']} ({summary['server_ip']})")
        print(f"위험도: {summary['risk_level']}")
        print(f"취약: {summary['vuln_count']} / 주의: {summary['warn_count']} / 양호: {summary['safe_count']} / N/A: {summary['na_count']}")
        print("\n[취약 항목]")
        for v in get_vuln_items(scan):
            print(f"  - {v['module']} {v['title']}: {v['evidence'][:80]}")
    else:
        print("스캔 결과 없음 또는 오류:", scan)
