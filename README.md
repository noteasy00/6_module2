# AWVS - AI 기반 Linux 침해흔적 진단 시스템

생성형 AI(GPT-4o-mini)와 MITRE ATT&CK 프레임워크를 활용한 주요정보통신기반시설 취약점 자동 진단 도구입니다.

## 프로젝트 구조

```
6_module2/
├── awvs-scripts/           # 취약점 진단 자동화 도구
│   ├── scanner.py           # 통합 스캐너 (모듈 실행 + AI 분석 + S3 업로드)
│   ├── check_webshell.py        # A03-01 웹셸 의심 파일 탐지
│   ├── check_malicious_js.py    # A03-02 악성 JavaScript 삽입 탐지
│   ├── check_directory_listing.py # A05-04 디렉토리 리스팅 점검
│   ├── check_ssh_root.py        # A05-01 root 계정 원격 접속 제한
│   ├── check_account_lock_threshold.py # A07-01 계정 잠금 임계값 설정
│   ├── check_sensitive_files.py # A05-05 민감 파일 노출 점검
│   ├── check_crontab.py         # A01-03 crontab 악성 스케줄 점검
│   ├── check_sudoers.py         # A05-06 sudo 권한 과다 부여
│   ├── check_ssh_backdoor_keys.py # A08-01 SSH 백도어 의심 키 탐지
│   ├── check_login_anomaly.py   # A09-01 비정상 로그인 및 SSH 접근 탐지
│   ├── prompts/                 # AI 분석 프롬프트 (코드와 분리)
│   │   ├── system_prompt.md      # 시스템 프롬프트
│   │   ├── attack_mapping.json   # 모듈별 MITRE ATT&CK 매핑
│   │   └── few_shot.json         # Few-shot 응답 예시
│   ├── mock_setup.sh            # 모의 취약 환경 구축 스크립트
│   ├── mock_cleanup.sh          # 모의 환경 정리 스크립트
│   └── test_openai.py           # OpenAI API 연동 테스트
├── awvs-lambda/             # AWS Lambda 함수
│   └── lambda_function.py    # SSM을 통한 EC2 원격 스캔 트리거
├── awvs-target/             # 취약 웹 애플리케이션 (테스트 대상)
│   └── docker-compose.yml    # DVWA + Juice Shop
├── dashboard/               # Streamlit 대시보드
│   ├── app.py                # 대시보드 프론트엔드
│   └── backend.py            # S3 조회 및 API Gateway 연동
└── requirements.txt          # Python 의존 패키지
```

## 클라우드 아키텍처

```
[Streamlit Dashboard] → [API Gateway] → [Lambda] → [SSM RunCommand] → [EC2]
        ↑                                                                  │
        │                                                                  ▼
        └──────────── [S3 Bucket] ←──── scanner.py ←──── [OpenAI GPT-4o-mini]
```

| 구성 요소 | 서비스 | 용도 |
|-----------|--------|------|
| 대시보드 | EC2 + Streamlit (Port 8501) | 진단 결과 시각화 |
| API 트리거 | API Gateway + Lambda | 스캔 원격 실행 |
| 원격 실행 | SSM RunShellScript | EC2에서 scanner.py 실행 |
| 진단 대상 | EC2 (3.36.43.34) | DVWA, Juice Shop |
| 결과 저장 | S3 (awvs-scan-results-team6-v2) | JSON 스캔 결과 |
| AI 분석 | OpenAI GPT-4o-mini | 위험 분석 + ATT&CK 매핑 |

## 진단 모듈 (10개)

| 코드 | 카테고리 | 점검 항목 | ATT&CK Technique |
|------|----------|-----------|-------------------|
| A03-01 | 웹 | 웹셸 의심 파일 탐지 | T1505.003 Web Shell |
| A03-02 | 웹 | 악성 JavaScript 삽입 탐지 | T1185 Browser Session Hijacking |
| A05-04 | 웹 | 디렉토리 리스팅 점검 | T1083 File and Directory Discovery |
| A05-01 | 시스템 | root 계정 원격 접속 제한 | T1078.003 Valid Accounts |
| A07-01 | 시스템 | 계정 잠금 임계값 설정 | T1110.001 Brute Force |
| A05-05 | 웹 | 민감 파일 노출 점검 | T1005 Data from Local System |
| A01-03 | 시스템 | crontab 악성 스케줄 점검 | T1053.003 Cron |
| A05-06 | 시스템 | sudo 권한 과다 부여 | T1548.003 Sudo Abuse |
| A08-01 | 시스템 | SSH 백도어 의심 키 탐지 | T1098.004 SSH Authorized Keys |
| A09-01 | 시스템 | 비정상 로그인 및 SSH 접근 탐지 | T1110 Brute Force |

## 설치 및 실행

### 1. 패키지 설치

```bash
pip install -r requirements.txt
```

### 2. 환경 변수 설정

```bash
# awvs-scripts/.env 파일 생성
OPENAI_API_KEY=sk-your-api-key-here
```

### 3. 취약점 진단 실행

```bash
cd awvs-scripts

# 전체 스캔 (AI 분석 + S3 업로드)
sudo python3 scanner.py

# AI 분석 없이 스캔만
sudo python3 scanner.py --no-ai

# S3 업로드 없이 로컬 저장만
sudo python3 scanner.py --no-s3

# 웹 루트 지정
sudo python3 scanner.py --web-root /var/www/html
```

### 4. 대시보드 실행

```bash
cd dashboard
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

### 5. 모의 취약 환경 (테스트용)

```bash
# 취약 환경 구축
sudo bash awvs-scripts/mock_setup.sh

# 스캔 실행
sudo python3 awvs-scripts/scanner.py

# 환경 정리
sudo bash awvs-scripts/mock_cleanup.sh
```

## 기술 스택

- Python 3, Streamlit, Pandas, Boto3, OpenAI API
- AWS: EC2, Lambda, API Gateway, SSM, S3
- Docker: DVWA, Juice Shop
- AI: GPT-4o-mini + MITRE ATT&CK 프레임워크
