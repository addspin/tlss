#!/usr/bin/env bash
# Тест OCSP-респондера по RFC 6960 / RFC 5019:
# - AIA (id-ad-ocsp) в выпущенном сертификате
# - POST /ocsp с DER-запросом
# - GET /ocsp/{base64} по RFC 6960 A.1.1
# - unauthorized на неизвестный serial (RFC 5019 §2.2.3)
# - заголовки кэширования (RFC 5019 §6)
#
# Использование:
#   ./test_ocsp.sh                 # берёт последний сертификат из certs
#   ./test_ocsp.sh <serial>        # ищет serial в certs / user_certs / est_certs
#
# Переменные окружения:
#   OCSP_URL — переопределить URL респондера (по умолчанию берётся из AIA сертификата)
#   DB       — путь к базе

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

DB="${DB:-$PROJECT_ROOT/db/database.db}"
WORK_DIR="$(mktemp -d -t tlss-ocsp-XXXX)"
trap "rm -rf $WORK_DIR" EXIT

if [[ ! -f "$DB" ]]; then
  echo "❌ База данных не найдена: $DB"
  exit 1
fi

SERIAL="${1:-}"

echo "═══════════════════════════════════════════════════════════════"
echo " TLSS OCSP TEST"
echo " DB:   $DB"
echo " Tmp:  $WORK_DIR"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Достаём тестовый сертификат ─────────────────────────────────
echo ""
CERT_FILE="$WORK_DIR/cert.pem"
if [[ -n "$SERIAL" ]]; then
  echo "🔍 Шаг 1: ищу сертификат с serial=$SERIAL"
  for table in certs user_certs est_certs; do
    sqlite3 "$DB" "SELECT public_key FROM $table WHERE serial_number = '$SERIAL';" > "$CERT_FILE" 2>/dev/null || true
    if [[ -s "$CERT_FILE" ]]; then
      echo "   найдено в таблице: $table"
      break
    fi
  done
else
  echo "🔍 Шаг 1: беру последний сертификат из certs"
  sqlite3 "$DB" "SELECT public_key FROM certs WHERE cert_status IN (0,1,2) ORDER BY id DESC LIMIT 1;" > "$CERT_FILE"
fi

if [[ ! -s "$CERT_FILE" ]]; then
  echo "❌ Сертификат не найден"
  exit 1
fi

CN=$(openssl x509 -in "$CERT_FILE" -noout -subject | sed 's/.*CN=//; s/,.*//; s|/.*||')
ACTUAL_SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | sed 's/serial=//')
echo "   CN:     $CN"
echo "   Serial: $ACTUAL_SERIAL"

# ─── 2. Проверяем AIA в сертификате ─────────────────────────────────
echo ""
echo "🔍 Шаг 2: проверяю расширение AIA (id-ad-ocsp) в сертификате"
AIA_OCSP=$(openssl x509 -in "$CERT_FILE" -noout -ocsp_uri 2>/dev/null || true)
if [[ -z "$AIA_OCSP" ]]; then
  echo "   ⚠️  AIA отсутствует — сертификат выпущен до внедрения OCSP"
  echo "      Перевыпустите сертификат, чтобы клиенты сами находили респондер"
else
  echo "   ✅ OCSP URI: $AIA_OCSP"
fi

RESPONDER_URL="${OCSP_URL:-${AIA_OCSP:-http://tlss.lv.local:8080/ocsp}}"
echo "   Использую респондер: $RESPONDER_URL"

# ─── 3. Экспортируем цепочку CA ─────────────────────────────────────
echo ""
echo "🔍 Шаг 3: экспортирую Root CA и Sub CA из базы"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Root' AND cert_status=0;" > "$WORK_DIR/root_ca.pem"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Sub'  AND cert_status=0;" > "$WORK_DIR/sub_ca.pem"
cat "$WORK_DIR/root_ca.pem" "$WORK_DIR/sub_ca.pem" > "$WORK_DIR/chain.pem"

if [[ ! -s "$WORK_DIR/sub_ca.pem" ]]; then
  echo "❌ Активный Sub CA не найден в базе"
  exit 1
fi
echo "   ✅ chain.pem собран"

# ─── 4. POST-запрос ─────────────────────────────────────────────────
echo ""
echo "🔍 Шаг 4: POST $RESPONDER_URL  (RFC 6960 A.1.1)"
# -no_nonce: реализация следует облегчённому профилю RFC 5019, nonce не поддерживается
POST_OUT=$(openssl ocsp \
  -issuer "$WORK_DIR/sub_ca.pem" \
  -cert "$CERT_FILE" \
  -url "$RESPONDER_URL" \
  -no_nonce \
  -CAfile "$WORK_DIR/chain.pem" \
  -resp_text 2>&1 || true)

echo "$POST_OUT" | awk '/Cert Status:|This Update:|Next Update:|Revocation Time:|Revocation Reason:|Responder Id:|Produced At:/' | sed 's/^[ \t]*/   /'

if echo "$POST_OUT" | grep -q "Response verify OK"; then
  echo "   ✅ Подпись ответа проверена (Response verify OK)"
else
  echo "   ⚠️  Подпись не подтверждена:"
  echo "$POST_OUT" | grep -iE "verify|error" | sed 's/^/      /'
fi

CERT_STATUS=$(echo "$POST_OUT" | awk '/Cert Status:/{print $3; exit}')

# ─── 5. GET-запрос ──────────────────────────────────────────────────
echo ""
echo "🔍 Шаг 5: GET $RESPONDER_URL/{base64}  (RFC 6960 A.1.1)"
openssl ocsp \
  -issuer "$WORK_DIR/sub_ca.pem" \
  -cert "$CERT_FILE" \
  -no_nonce \
  -reqout "$WORK_DIR/req.der" >/dev/null 2>&1

# base64 → URL-кодирование только небезопасных символов алфавита base64
B64=$(base64 < "$WORK_DIR/req.der" | tr -d '\n')
ENCODED=$(printf '%s' "$B64" | sed 's/+/%2B/g; s|/|%2F|g; s/=/%3D/g')

HTTP_CODE=$(curl -sS -o "$WORK_DIR/get_resp.der" -w "%{http_code}" \
  -D "$WORK_DIR/get_headers.txt" \
  "${RESPONDER_URL%/}/$ENCODED" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "   ❌ HTTP $HTTP_CODE"
else
  GET_STATUS=$(openssl ocsp -respin "$WORK_DIR/get_resp.der" -resp_text -noverify 2>/dev/null \
    | awk '/Cert Status:/{print $3; exit}')
  echo "   ✅ HTTP 200, Cert Status: ${GET_STATUS:-?}"
  if [[ -n "$CERT_STATUS" && "$GET_STATUS" == "$CERT_STATUS" ]]; then
    echo "   ✅ Статус совпадает с POST-ответом"
  elif [[ -n "$CERT_STATUS" ]]; then
    echo "   ⚠️  Статус отличается от POST: GET=$GET_STATUS POST=$CERT_STATUS"
  fi
fi

# ─── 6. Заголовки кэширования ───────────────────────────────────────
echo ""
echo "🔍 Шаг 6: заголовки кэширования (RFC 5019 §6)"
if [[ -f "$WORK_DIR/get_headers.txt" ]]; then
  grep -iE "^(content-type|cache-control|expires|last-modified|etag):" "$WORK_DIR/get_headers.txt" \
    | sed 's/^/   /' || echo "   ⚠️  Заголовки не найдены"
else
  echo "   ⚠️  Заголовки не получены"
fi

# ─── 7. Статус Sub CA через Root CA ─────────────────────────────────
echo ""
echo "🔍 Шаг 7: статус Sub CA через Root CA (ветка scopeCoreSubCA)"
if [[ -s "$WORK_DIR/root_ca.pem" ]]; then
  SUBCA_SERIAL=$(openssl x509 -in "$WORK_DIR/sub_ca.pem" -noout -serial | sed 's/serial=//')
  echo "   Sub CA serial: $SUBCA_SERIAL"

  SUBCA_OUT=$(openssl ocsp \
    -issuer "$WORK_DIR/root_ca.pem" \
    -cert "$WORK_DIR/sub_ca.pem" \
    -url "$RESPONDER_URL" \
    -no_nonce \
    -CAfile "$WORK_DIR/root_ca.pem" \
    -resp_text 2>&1 || true)

  SUBCA_STATUS=$(echo "$SUBCA_OUT" | awk '/Cert Status:/{print $3; exit}')
  if [[ -n "$SUBCA_STATUS" ]]; then
    echo "   ✅ Root CA ответил про Sub CA: $SUBCA_STATUS"
    if echo "$SUBCA_OUT" | grep -q "Response verify OK"; then
      echo "   ✅ Ответ подписан Root CA, подпись проверена"
    else
      echo "   ⚠️  Подпись не подтверждена:"
      echo "$SUBCA_OUT" | grep -iE "verify|error" | head -3 | sed 's/^/      /'
    fi
  else
    echo "   ⚠️  Статус не получен:"
    echo "$SUBCA_OUT" | grep -iE "error|responder|unauthorized" | head -3 | sed 's/^/      /'
  fi
else
  echo "   ⏭️  Активный Root CA не найден — пропускаю"
fi

# ─── 8. Неизвестный serial → unauthorized ───────────────────────────
echo ""
echo "🔍 Шаг 8: неизвестный serial должен дать unauthorized (RFC 5019 §2.2.3)"
UNKNOWN_OUT=$(openssl ocsp \
  -issuer "$WORK_DIR/sub_ca.pem" \
  -serial 0xDEADBEEFDEADBEEF \
  -url "$RESPONDER_URL" \
  -no_nonce \
  -resp_text 2>&1 || true)

if echo "$UNKNOWN_OUT" | grep -qi "unauthorized"; then
  echo "   ✅ Ответ: unauthorized (6) — респондер не работает как оракул"
else
  echo "   ⚠️  Ожидался unauthorized, получено:"
  echo "$UNKNOWN_OUT" | grep -iE "status|error|responder" | head -3 | sed 's/^/      /'
fi

# ─── 9. Резюме ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
case "$CERT_STATUS" in
  good)
    echo " ✅ СЕРТИФИКАТ ВАЛИДЕН (OCSP: good)"
    ;;
  revoked)
    echo " 🛑 СЕРТИФИКАТ ОТОЗВАН (OCSP: revoked)"
    echo "$POST_OUT" | awk '/Revocation Time:|Revocation Reason:/' | sed 's/^[ \t]*/    /'
    ;;
  unknown)
    echo " ⚠️  OCSP: unknown — сертификат не найден у этого издателя"
    ;;
  *)
    echo " ⚠️  Статус не определён, см. вывод выше"
    ;;
esac
echo "═══════════════════════════════════════════════════════════════"
