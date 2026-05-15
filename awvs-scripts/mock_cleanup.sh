#!/bin/bash
# ============================================================
# 모의 취약 환경 클린업 스크립트 (11개 항목)
# 사용법: sudo bash mock_cleanup.sh
# ============================================================

echo "=== 모의 취약 환경 클린업 시작 ==="

# 1. sshd_config 복원
echo "[1/11] sshd_config 복원"
sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# 2. SSH 백도어 키 제거
echo "[2/11] SSH 백도어 키 제거"
sed -i '/attacker@evil-server/d' /root/.ssh/authorized_keys 2>/dev/null
# mock_setup이 생성한 파일이 비어있으면 제거 (빈 파일 = 모듈에서 취약 판정)
if [ -f /root/.ssh/authorized_keys ] && [ ! -s /root/.ssh/authorized_keys ]; then
  rm -f /root/.ssh/authorized_keys
  echo "  authorized_keys 빈 파일 제거 완료"
fi

# 3. 계정 잠금 - 클린업 불필요 (기본 상태 유지)
echo "[3/11] 계정 잠금 - 변경 없음"

# 4. sudoers 클린업
echo "[4/11] sudoers NOPASSWD 제거"
rm -f /etc/sudoers.d/99-vulnerable

# 5. auth.log - 가짜 로그 제거
echo "[5/11] auth.log 가짜 로그 제거"
sed -i '/203.0.113/d' /var/log/auth.log

# 6. 웹셸 삭제
echo "[6/11] 웹셸 샘플 삭제"
rm -f /var/www/html/uploads/cmd.php
rm -f /var/www/html/uploads/backdoor.php

# 7. 민감 파일 삭제
echo "[7/11] 민감 파일 삭제"
rm -f /var/www/html/.env
rm -f /var/www/html/config.bak

# 8. 악성 JavaScript 삭제
echo "[8/11] 악성 JavaScript 샘플 삭제"
rm -f /var/www/html/infected.html
rm -f /var/www/html/uploads/tracker.js

# 9. 디렉토리 리스팅 비활성화
echo "[9/11] 디렉토리 리스팅 복원"
if [ -f /etc/apache2/apache2.conf ]; then
  sed -i 's/Options Indexes/Options -Indexes/g' /etc/apache2/apache2.conf
  sed -i 's/Options Indexes/Options -Indexes/g' /etc/apache2/conf-enabled/security.conf 2>/dev/null
  systemctl reload apache2 2>/dev/null
  echo "  Apache -Indexes 복원 완료"
elif [ -f /etc/nginx/sites-enabled/default ]; then
  sed -i '/autoindex on/d' /etc/nginx/sites-enabled/default 2>/dev/null
  systemctl reload nginx 2>/dev/null
  echo "  Nginx autoindex 제거 완료"
else
  echo "  Apache/Nginx 설정 파일 없음 - 건너뜀"
fi

# 10. 추가 민감 파일 삭제
echo "[10/11] 추가 민감 파일 삭제"
rm -f /var/www/html/backup.sql
rm -rf /var/www/html/.git

# 11. crontab 악성 스케줄 제거
echo "[11/11] crontab 악성 스케줄 제거"
sed -i '/AWVS-MOCK-CRON/d' /etc/crontab
# 203.0.113.99 관련 잔여 라인도 제거 (중복 실행 대비)
sed -i '/203\.0\.113\.99/d' /etc/crontab
# 사용자 crontab 테스트 파일 제거
rm -f /var/spool/cron/crontabs/suspicious

echo ""
echo "=== 클린업 완료 (11개 항목) ==="
echo "확인:"
grep PermitRootLogin /etc/ssh/sshd_config | head -1
ls /root/.ssh/authorized_keys 2>/dev/null || echo "  authorized_keys 파일 없음 (정상)"
ls /var/www/html/uploads/ 2>/dev/null || echo "  uploads/ 비어있음"
ls /etc/sudoers.d/99-vulnerable 2>/dev/null || echo "  sudoers 취약 설정 없음"
ls /var/www/html/infected.html 2>/dev/null || echo "  악성 JS 샘플 없음"
grep -n "Options.*Indexes" /etc/apache2/apache2.conf 2>/dev/null || echo "  디렉토리 리스팅 비활성화 확인"
ls /var/www/html/backup.sql 2>/dev/null || echo "  민감 파일(backup.sql) 없음"
grep "AWVS-MOCK-CRON" /etc/crontab 2>/dev/null || echo "  crontab 악성 스케줄 없음"
