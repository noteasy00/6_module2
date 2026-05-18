"""
AWVS 대시보드 - Streamlit
S3 스캔 결과를 읽어 시각화하고, API Gateway로 스캔을 트리거하는 대시보드

실행:
    cd ~/awvs-scripts/dashboard   (또는 로컬)
    streamlit run app.py --server.port 8501 --server.address 0.0.0.0

필요 패키지:
    pip install streamlit pandas boto3 requests
"""

import sys
import os
import streamlit as st
import pandas as pd
from backend import (
    trigger_scan,
    get_latest_scan,
    get_all_scans,
    parse_scan_summary,
    get_vuln_items,
    get_warn_items
)

# generate_report.py 경로 탐색 (Git 구조 + EC2 배포 구조 모두 지원)
_script_dir = os.path.dirname(os.path.abspath(__file__))
for _candidate in [
    os.path.join(_script_dir, ".."),               # Git: dashboard/ → 프로젝트 루트
    os.path.join(_script_dir, "..", "awvs-scripts"),  # Git: dashboard/ → awvs-scripts/
    os.path.expanduser("~/awvs-scripts"),           # EC2: /home/ubuntu/awvs-scripts/
]:
    if os.path.exists(os.path.join(_candidate, "generate_report.py")):
        sys.path.insert(0, _candidate)
        break
from generate_report import generate_xlsx_bytes

# ── 페이지 설정 ───────────────────────────────────────────
st.set_page_config(page_title="AI Cyber Sentinel", layout="wide")

# ── 사이드바 ──────────────────────────────────────────────
st.sidebar.title("AWVS 진단 컨트롤러")

# 스캔 트리거 버튼
if st.sidebar.button("스캔 실행 (API Gateway)"):
    with st.spinner("EC2 서버에서 스캔 실행 중... (최대 3분 소요)"):
        result = trigger_scan()
    if result["success"]:
        st.sidebar.success("스캔 완료! 페이지를 새로고침하면 결과가 반영됩니다.")
    else:
        st.sidebar.error(f"스캔 실패: {result['error']}")

st.sidebar.divider()

# 이전 스캔 이력 선택
scan_list = get_all_scans(limit=5)
if scan_list and "error" not in scan_list[0]:
    scan_options = [f"{s.get('scan_time', '알 수 없음')} ({s.get('_s3_key', '').split('/')[-1]})" for s in scan_list]
    selected_idx = st.sidebar.selectbox("스캔 이력 선택", range(len(scan_options)), format_func=lambda i: scan_options[i])
    scan_data = scan_list[selected_idx]
else:
    scan_data = None

st.sidebar.divider()

# 엑셀 보고서 다운로드
if scan_data and "error" not in scan_data:
    try:
        xlsx_bytes = generate_xlsx_bytes(scan_data)
        scan_time_str = scan_data.get("scan_time", "").replace(" ", "_").replace(":", "")
        st.sidebar.download_button(
            label="📥 엑셀 보고서 다운로드",
            data=xlsx_bytes,
            file_name=f"awvs_report_{scan_time_str}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )
    except Exception as e:
        st.sidebar.warning(f"보고서 생성 실패: {e}")

st.sidebar.divider()
st.sidebar.info("""
**인프라 정보**
- EC2: `3.36.43.34`
- DVWA: Port 80
- Juice Shop: Port 3000
- S3: `awvs-scan-results-team6-v2`
""")

# ── 메인 타이틀 ───────────────────────────────────────────
st.title("AI 기반 Linux 침해 흔적 진단 시스템")

if not scan_data:
    st.info("스캔 결과가 없습니다. 사이드바에서 '스캔 실행'을 눌러주세요.")
    st.stop()

# ── 데이터 파싱 ───────────────────────────────────────────
summary = parse_scan_summary(scan_data)
if not summary:
    st.error("스캔 데이터 파싱 실패")
    st.stop()

st.caption(f"서버: {summary['server']} ({summary['server_ip']}) | 스캔 시간: {summary['scan_time']} | 분석 엔진: GPT-4o-mini")

# ── 1. 상단 메트릭 ────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
m1.metric("위험 수준", summary["risk_level"])
m2.metric("취약 항목", f"{summary['vuln_count']}건")
m3.metric("주의 항목", f"{summary['warn_count']}건")
m4.metric("양호 항목", f"{summary['safe_count']}건")

st.divider()

# ── 2. 진단 결과 테이블 ───────────────────────────────────
col_left, col_right = st.columns([1, 1.5])

with col_left:
    st.subheader("전체 점검 결과")
    rows = []
    for r in summary["results"]:
        if r["status"] == "취약":
            icon = "🔴 취약"
        elif r["status"] == "주의":
            icon = "🟡 주의"
        elif r["status"] == "양호":
            icon = "🟢 양호"
        else:
            icon = "⚪ N/A"
        rows.append({
            "모듈": r["module"],
            "카테고리": r["category"],
            "항목": r["title"],
            "결과": icon
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

with col_right:
    st.subheader("취약 항목 상세")
    vuln_items = get_vuln_items(scan_data)
    if vuln_items:
        for v in vuln_items:
            with st.expander(f"🔴 {v['module']} - {v['title']}"):
                st.markdown(f"**대상:** `{v['target']}`")
                # 증거 데이터를 코드 블록 + 줄바꿈 처리
                evidence_raw = v.get('evidence', '')[:500]
                evidence_lines = evidence_raw.replace(" | ", "\n")
                st.markdown("**증거:**")
                st.code(evidence_lines, language="text")
                st.markdown(f"**판단 근거:** {v['reason']}")
                st.markdown("---")
                st.markdown(f"**권고 조치:** {v['recommendation']}")
    else:
        st.success("취약 항목이 없습니다.")

    warn_items = get_warn_items(scan_data)
    if warn_items:
        st.subheader("주의 항목 상세")
        for w in warn_items:
            with st.expander(f"🟡 {w['module']} - {w['title']}"):
                st.markdown(f"**대상:** `{w['target']}`")
                evidence_raw = w.get('evidence', '')[:500]
                evidence_lines = evidence_raw.replace(" | ", "\n")
                st.markdown("**증거:**")
                st.code(evidence_lines, language="text")
                st.markdown(f"**판단 근거:** {w['reason']}")

st.divider()

# ── 3. AI 분석 리포트 ─────────────────────────────────────
st.subheader("AI 보안 분석 리포트")
tab1, tab2 = st.tabs(["침해 시나리오 분석", "조치 방안"])

with tab1:
    has_ai = False
    for r in summary["results"]:
        ai = r.get("ai_analysis", {})
        if ai.get("attack_scenario") and ai["attack_scenario"] not in ("해당 없음", "-", ""):
            has_ai = True
            st.markdown(f"### {r['module']} {r['title']}")

            # ATT&CK 매핑 뱃지
            mitre_technique = ai.get("mitre_technique", "")
            mitre_tactic = ai.get("mitre_tactic", "")
            if mitre_technique and mitre_technique != "-":
                st.markdown(f"🎯 **ATT&CK:** `{mitre_technique}` | Tactic: `{mitre_tactic}`")

            # 위험성과 공격 시나리오를 구분된 카드로 표시
            risk_col, scenario_col = st.columns(2)
            with risk_col:
                st.markdown("**⚠️ 위험성**")
                st.info(ai.get("risk_detail", "-"))
            with scenario_col:
                st.markdown("**🗺️ 공격 시나리오**")
                st.warning(ai.get("attack_scenario", "-"))

            st.divider()
    if not has_ai:
        st.info("AI 분석 결과가 없습니다. 스캔 시 --no-ai 옵션 없이 실행하면 AI 분석이 포함됩니다.")

with tab2:
    has_countermeasure = False

    # 우선순위별로 분류
    critical_items = []  # 취약 항목
    warning_items = []   # 주의 항목
    safe_items = []      # 양호 항목

    for r in summary["results"]:
        ai = r.get("ai_analysis", {})
        if not ai.get("countermeasure") or ai["countermeasure"] in ("-", ""):
            continue
        item = {"module": r["module"], "title": r["title"], "status": r["status"], "ai": ai}
        if r["status"] == "취약":
            critical_items.append(item)
        elif r["status"] == "주의":
            warning_items.append(item)
        else:
            safe_items.append(item)

    if critical_items or warning_items:
        has_countermeasure = True

        # 긴급 조치 (취약)
        if critical_items:
            st.markdown("### 🔴 긴급 조치 (Critical)")
            st.caption("즉시 대응이 필요한 취약 항목입니다.")
            for idx, item in enumerate(critical_items, 1):
                ai = item["ai"]
                mitre_tag = ""
                if ai.get("mitre_technique") and ai["mitre_technique"] != "-":
                    mitre_tag = f" `{ai['mitre_technique']}`"
                with st.expander(f"**P{idx}** | {item['module']} - {item['title']}{mitre_tag}", expanded=(idx <= 3)):
                    st.markdown(f"**대응 방안:**")
                    st.success(ai.get("countermeasure", "-"))

        # 권고 조치 (주의)
        if warning_items:
            st.markdown("### 🟡 권고 조치 (Warning)")
            st.caption("개선이 권고되는 주의 항목입니다.")
            for idx, item in enumerate(warning_items, 1):
                ai = item["ai"]
                with st.expander(f"{item['module']} - {item['title']}"):
                    st.markdown(f"**대응 방안:**")
                    st.info(ai.get("countermeasure", "-"))

    if not has_countermeasure:
        st.info("조치 방안 데이터가 없습니다.")

# ── 4. 원본 JSON 확인 ─────────────────────────────────────
with st.expander("원본 JSON 데이터 보기"):
    st.json(scan_data)
