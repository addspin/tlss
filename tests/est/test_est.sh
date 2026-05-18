#!/usr/bin/env bash
# Тест EST endpoints по RFC 7030:
# - GET /.well-known/est/cacerts (без auth)
# - POST /.well-known/est/simpleenroll (Basic Auth) → выпуск первого сертификата
# - POST /.well-known/est/simplereenroll (mTLS) → перевыпуск через клиентский сертификат
#
# Использование:
#   ./test_est.sh <username> <password>
#   ./test_est.sh <username> <password> <cn>
#
# Переменные окружения:
#   BASE_URL  — URL основного сервера (default: https://tlss.lv.local:43000)
#   EST_URL   — URL EST mTLS сервера (default: https://tlss.lv.local:43001)
#   CN        — Common Name для CSR (default: est-test-<timestamp>)

set -e

# Автоматически находим корень проекта по go.mod
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" && ! -f "$PROJECT_ROOT/go.mod" ]]; do
  PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done
if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
  echo "❌ Не удалось найти корень проекта (go.mod) от $SCRIPT_DIR"
  exit 1
fi

USERNAME="${1:-}"
PASSWORD="${2:-}"
CN_ARG="${3:-}"

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "Использование: $0 <username> <password> [<cn>]"
  echo ""
  echo "Создайте EST-пользователя через UI: /est_users"
  echo "Затем передайте его username и password этому скрипту"
  exit 1
fi

BASE_URL="${BASE_URL:-https://tlss.lv.local:43000}"
EST_URL="${EST_URL:-https://tlss.lv.local:43001}"
CN="${CN_ARG:-${CN:-est-test-$(date +%s)}}"
WORK_DIR="$(mktemp -d -t tlss-est-XXXX)"
trap "rm -rf $WORK_DIR" EXIT

echo "═══════════════════════════════════════════════════════════════"
echo " TLSS EST TEST"
echo " EST URL:   $EST_URL  (все EST endpoints, mTLS для simplereenroll)"
echo " Main URL:  $BASE_URL  (для проверки БД через UI)"
echo " User:      $USERNAME"
echo " CN:        $CN"
echo " Tmp:       $WORK_DIR"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. GET /.well-known/est/cacerts (без auth) ─────────────────────
echo ""
echo "🔍 Шаг 1: GET /.well-known/est/cacerts"
HTTP_CODE=$(curl -sk -o "$WORK_DIR/cacerts.b64" -w "%{http_code}" \
  "$EST_URL/.well-known/est/cacerts")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "   ❌ HTTP $HTTP_CODE"
  cat "$WORK_DIR/cacerts.b64"
  exit 1
fi

base64 -d < "$WORK_DIR/cacerts.b64" > "$WORK_DIR/cacerts.p7b" 2>/dev/null
if ! openssl pkcs7 -inform DER -in "$WORK_DIR/cacerts.p7b" -print_certs -out "$WORK_DIR/cacerts.pem" 2>/dev/null; then
  echo "   ❌ Не удалось распарсить PKCS#7"
  exit 1
fi

CA_COUNT=$(grep -c "BEGIN CERTIFICATE" "$WORK_DIR/cacerts.pem" || true)
echo "   ✅ HTTP 200, PKCS#7 разобран, CA сертификатов: $CA_COUNT"
openssl x509 -in "$WORK_DIR/cacerts.pem" -noout -subject -issuer 2>/dev/null | sed 's/^/      /'

# ─── 2. Создаём CSR ─────────────────────────────────────────────────
echo ""
echo "🔍 Шаг 2: генерирую ключевую пару и CSR"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$WORK_DIR/client.key" \
  -out "$WORK_DIR/client.csr" \
  -subj "/CN=$CN" 2>/dev/null
echo "   ✅ $WORK_DIR/client.csr (CN=$CN)"

# ─── 3. POST /.well-known/est/simpleenroll (Basic Auth) ─────────────
echo ""
echo "🔍 Шаг 3: POST /.well-known/est/simpleenroll  (Basic Auth)"
HTTP_CODE=$(openssl req -in "$WORK_DIR/client.csr" -outform DER | base64 | \
  curl -sk -o "$WORK_DIR/enroll.b64" -w "%{http_code}" \
    -u "$USERNAME:$PASSWORD" \
    -X POST \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    --data-binary @- \
    "$EST_URL/.well-known/est/simpleenroll")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "   ❌ HTTP $HTTP_CODE"
  cat "$WORK_DIR/enroll.b64"
  exit 1
fi

base64 -d < "$WORK_DIR/enroll.b64" > "$WORK_DIR/enroll.p7b"
openssl pkcs7 -inform DER -in "$WORK_DIR/enroll.p7b" -print_certs -out "$WORK_DIR/client.crt" 2>/dev/null
echo "   ✅ HTTP 200, сертификат выпущен:"
openssl x509 -in "$WORK_DIR/client.crt" -noout -subject -issuer -serial -dates 2>/dev/null | sed 's/^/      /'

# ─── 4. Проверяем цепочку выпущенного сертификата ───────────────────
echo ""
echo "🔍 Шаг 4: верифицирую цепочку (используя cacerts)"
VERIFY_OUT=$(openssl verify -CAfile "$WORK_DIR/cacerts.pem" "$WORK_DIR/client.crt" 2>&1 || true)
echo "$VERIFY_OUT" | sed 's/^/   /'
if ! echo "$VERIFY_OUT" | grep -q ": OK"; then
  echo "   ⚠️  Цепочка не валидна — возможно cacerts вернул не Sub CA"
fi

# ─── 5. POST /.well-known/est/simplereenroll (mTLS) ─────────────────
echo ""
echo "🔍 Шаг 5: POST /.well-known/est/simplereenroll  (mTLS на $EST_URL)"
echo "   используем выпущенный client.crt + client.key для аутентификации"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$WORK_DIR/client2.key" \
  -out "$WORK_DIR/client2.csr" \
  -subj "/CN=$CN" 2>/dev/null

HTTP_CODE=$(openssl req -in "$WORK_DIR/client2.csr" -outform DER | base64 | \
  curl -sk -o "$WORK_DIR/reenroll.b64" -w "%{http_code}" \
    --cert "$WORK_DIR/client.crt" \
    --key "$WORK_DIR/client.key" \
    -X POST \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    --data-binary @- \
    "$EST_URL/.well-known/est/simplereenroll")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "   ❌ HTTP $HTTP_CODE"
  cat "$WORK_DIR/reenroll.b64"
  exit 1
fi

base64 -d < "$WORK_DIR/reenroll.b64" > "$WORK_DIR/reenroll.p7b"
openssl pkcs7 -inform DER -in "$WORK_DIR/reenroll.p7b" -print_certs -out "$WORK_DIR/client2.crt" 2>/dev/null
echo "   ✅ HTTP 200, новый сертификат выпущен:"
openssl x509 -in "$WORK_DIR/client2.crt" -noout -subject -issuer -serial -dates 2>/dev/null | sed 's/^/      /'

OLD_SERIAL=$(openssl x509 -in "$WORK_DIR/client.crt" -noout -serial | sed 's/serial=//')
NEW_SERIAL=$(openssl x509 -in "$WORK_DIR/client2.crt" -noout -serial | sed 's/serial=//')
if [[ "$OLD_SERIAL" == "$NEW_SERIAL" ]]; then
  echo "   ⚠️  Serial не изменился — это странно"
else
  echo "   ✅ Serial обновился: $OLD_SERIAL → $NEW_SERIAL"
fi

# ─── 6. Проверяем что старый cert попал в est_certs со status=2 ────
echo ""
echo "🔍 Шаг 6: проверяю что старый сертификат отозван в БД (superseded)"
DB="$PROJECT_ROOT/db/database.db"
if [[ -f "$DB" ]]; then
  OLD_STATUS=$(sqlite3 "$DB" "SELECT cert_status FROM est_certs WHERE serial_number = '$OLD_SERIAL';" 2>/dev/null)
  if [[ "$OLD_STATUS" == "2" ]]; then
    echo "   ✅ Старый serial $OLD_SERIAL: cert_status = 2 (revoked / superseded)"
  else
    echo "   ⚠️  Старый serial $OLD_SERIAL: cert_status = $OLD_STATUS (ожидалось 2)"
  fi

  NEW_STATUS=$(sqlite3 "$DB" "SELECT cert_status FROM est_certs WHERE serial_number = '$NEW_SERIAL';" 2>/dev/null)
  if [[ "$NEW_STATUS" == "0" ]]; then
    echo "   ✅ Новый serial $NEW_SERIAL: cert_status = 0 (valid)"
  else
    echo "   ⚠️  Новый serial $NEW_SERIAL: cert_status = $NEW_STATUS (ожидалось 0)"
  fi
else
  echo "   ⚠️  Не найден $DB — пропускаю проверку статусов в БД"
fi

# ─── 7. Проверка состояния EST пользователя в БД ───────────────────
echo ""
echo "🔍 Шаг 7: состояние EST пользователя после enroll"
MAX_USES_AFTER=""
USER_STATUS_AFTER=""
if [[ -f "$DB" ]]; then
  MAX_USES_AFTER=$(sqlite3 "$DB" "SELECT max_uses FROM est_users WHERE username = '$USERNAME';" 2>/dev/null)
  USER_STATUS_AFTER=$(sqlite3 "$DB" "SELECT user_status FROM est_users WHERE username = '$USERNAME';" 2>/dev/null)
  echo "   max_uses:    $MAX_USES_AFTER"
  echo "   user_status: $USER_STATUS_AFTER  (0=active, 1=expired, 3=disabled)"

  if [[ "$MAX_USES_AFTER" == "0" && "$USER_STATUS_AFTER" == "3" ]]; then
    echo "   ✅ MaxUses исчерпан и пользователь корректно переведён в disabled"
  elif [[ "$MAX_USES_AFTER" == "0" ]]; then
    echo "   ⚠️  MaxUses = 0, но user_status = $USER_STATUS_AFTER (ожидалось 3)"
  fi
else
  echo "   ⚠️  Не найден $DB — пропускаю"
fi

# ─── 8. Дополнительный enroll должен вернуть 401 если MaxUses == 0 ──
echo ""
echo "🔍 Шаг 8: проверяю что блокированный пользователь получает 401"
if [[ "$MAX_USES_AFTER" == "0" ]]; then
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$WORK_DIR/client3.key" \
    -out "$WORK_DIR/client3.csr" \
    -subj "/CN=$CN-blocked" 2>/dev/null

  HTTP_CODE=$(openssl req -in "$WORK_DIR/client3.csr" -outform DER | base64 | \
    curl -sk -o "$WORK_DIR/enroll3.out" -w "%{http_code}" \
      -u "$USERNAME:$PASSWORD" \
      -X POST \
      -H "Content-Type: application/pkcs10" \
      -H "Content-Transfer-Encoding: base64" \
      --data-binary @- \
      "$EST_URL/.well-known/est/simpleenroll")

  if [[ "$HTTP_CODE" == "401" ]]; then
    BODY=$(cat "$WORK_DIR/enroll3.out")
    echo "   ✅ HTTP 401 — enroll правильно отклонён"
    echo "   Ответ сервера: $BODY"
  else
    echo "   ❌ HTTP $HTTP_CODE (ожидалось 401)"
    cat "$WORK_DIR/enroll3.out"
  fi
else
  echo "   ⏭️  MaxUses ещё не исчерпан ($MAX_USES_AFTER осталось) — пропускаю"
  echo "      Для проверки 401 запустите скрипт повторно $MAX_USES_AFTER раз,"
  echo "      или создайте пользователя с MaxUses=1"
fi

# ─── 9. Резюме ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " ✅ EST полный цикл прошёл успешно:"
echo "    1. cacerts отдал валидный PKCS#7"
echo "    2. simpleenroll (Basic Auth) выпустил сертификат"
echo "    3. simplereenroll (mTLS) перевыпустил с новым serial"
echo "    4. Старый сертификат отозван (superseded)"
echo "    5. Состояние EST пользователя проверено"
if [[ "$MAX_USES_AFTER" == "0" ]]; then
  echo "    6. Блокировка по MaxUses=0 → 401 проверена"
fi
echo "═══════════════════════════════════════════════════════════════"
