#!/usr/bin/env bash
# Тест работы CRL по RFC 5280:
# - проверяет CDP в выпущенном сертификате
# - скачивает Sub CA и Root CA CRL
# - валидирует цепочку с CRL check
#
# Использование:
#   ./test_crl.sh                          # берёт последний выпущенный сертификат из est_certs
#   ./test_crl.sh <serial>                 # ищет сертификат по serial в certs / user_certs / est_certs
#   BASE_URL=https://host:port ./test_crl.sh  # переопределить URL сервера
#   DB=path/to/database.db ./test_crl.sh   # переопределить путь к БД

set -e

# Автоматически находим корень проекта: поднимаемся вверх от расположения скрипта,
# пока не найдём go.mod (маркер корня Go-проекта)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" && ! -f "$PROJECT_ROOT/go.mod" ]]; do
  PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done
if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
  echo "❌ Не удалось найти корень проекта (go.mod) от $SCRIPT_DIR"
  exit 1
fi

BASE_URL="${BASE_URL:-https://tlss.lv.local:43000}"
DB="${DB:-$PROJECT_ROOT/db/database.db}"
WORK_DIR="$(mktemp -d -t tlss-crl-XXXX)"
trap "rm -rf $WORK_DIR" EXIT

if [[ ! -f "$DB" ]]; then
  echo "❌ База данных не найдена: $DB"
  echo "   Укажите DB=... вручную"
  exit 1
fi

echo "═══════════════════════════════════════════════════════════════"
echo " TLSS CRL TEST"
echo " URL:  $BASE_URL"
echo " DB:   $DB"
echo " Tmp:  $WORK_DIR"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Получить тестовый сертификат ───────────────────────────────
SERIAL="${1:-}"
CERT_FILE="$WORK_DIR/test.pem"

if [[ -n "$SERIAL" ]]; then
  echo ""
  echo "🔍 Шаг 1: ищу сертификат с serial=$SERIAL"
  for table in certs user_certs est_certs; do
    sqlite3 "$DB" "SELECT public_key FROM $table WHERE serial_number = '$SERIAL';" > "$CERT_FILE" 2>/dev/null || true
    if [[ -s "$CERT_FILE" ]]; then
      echo "   найдено в таблице: $table"
      break
    fi
  done
else
  echo ""
  echo "🔍 Шаг 1: беру последний сертификат из est_certs"
  sqlite3 "$DB" "SELECT public_key FROM est_certs ORDER BY id DESC LIMIT 1;" > "$CERT_FILE"
fi

if [[ ! -s "$CERT_FILE" ]]; then
  echo "❌ Сертификат не найден"
  exit 1
fi

CN=$(openssl x509 -in "$CERT_FILE" -noout -subject | sed 's/.*CN=//; s/,.*//; s/\/.*//')
ACTUAL_SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | sed 's/serial=//')
echo "   CN: $CN"
echo "   Serial: $ACTUAL_SERIAL"

# ─── 2. CDP + Issuer в сертификате ──────────────────────────────────
echo ""
echo "🔍 Шаг 2: CRL Distribution Points, Issuer и Authority Key Identifier"
CDP=$(openssl x509 -in "$CERT_FILE" -text -noout | awk '/CRL Distribution/,/Signature/' | grep "URI:" | sed 's/.*URI://')
CERT_ISSUER=$(openssl x509 -in "$CERT_FILE" -noout -issuer | sed 's/issuer=//')
CERT_AKI=$(openssl x509 -in "$CERT_FILE" -text -noout | awk '/Authority Key Identifier/{getline; print}' | tr -d ' :' | tr '[:lower:]' '[:upper:]')
if [[ -z "$CDP" ]]; then
  echo "   ⚠️  CDP отсутствует (сертификат выпущен до фикса конфига)"
else
  echo "   CDP:    $CDP"
fi
echo "   Issuer: $CERT_ISSUER"
echo "   AKI:    $CERT_AKI"

# ─── 3. Скачать оба CRL ─────────────────────────────────────────────
echo ""
echo "🔍 Шаг 3: скачиваю Sub CA CRL и Root CA CRL"
curl -sk "$BASE_URL/api/v1/crl/subca/pem" -o "$WORK_DIR/subca.crl"
curl -sk "$BASE_URL/api/v1/crl/rootca/pem" -o "$WORK_DIR/rootca.crl"

if ! openssl crl -in "$WORK_DIR/subca.crl" -noout 2>/dev/null; then
  echo "❌ Sub CA CRL не парсится"
  head -3 "$WORK_DIR/subca.crl"
  exit 1
fi
if ! openssl crl -in "$WORK_DIR/rootca.crl" -noout 2>/dev/null; then
  echo "❌ Root CA CRL не парсится"
  head -3 "$WORK_DIR/rootca.crl"
  exit 1
fi
echo "   ✅ оба CRL валидны"

# ─── 4. Содержимое Sub CA CRL ───────────────────────────────────────
echo ""
echo "📋 Шаг 4: Sub CA CRL"
openssl crl -in "$WORK_DIR/subca.crl" -text -noout | \
  awk '/Issuer:|Last Update:|Next Update:|CRL Number:/' | sed 's/^/   /'

CRL_SUBCA_ISSUER=$(openssl crl -in "$WORK_DIR/subca.crl" -noout -issuer | sed 's/issuer=//')
CRL_SUBCA_AKI=$(openssl crl -in "$WORK_DIR/subca.crl" -text -noout | awk '/Authority Key Identifier/{getline; print}' | tr -d ' :' | tr '[:lower:]' '[:upper:]')

REVOKED_IN_SUBCA=$(openssl crl -in "$WORK_DIR/subca.crl" -text -noout | grep -c "Serial Number:" || true)
echo "   Записей: $REVOKED_IN_SUBCA"

# Прямая проверка: есть ли serial нашего сертификата в Sub CA CRL?
SERIAL_NO_COLONS=$(echo "$ACTUAL_SERIAL" | tr -d ':' | tr '[:lower:]' '[:upper:]')
if openssl crl -in "$WORK_DIR/subca.crl" -text -noout | grep -qi "Serial Number:.*$SERIAL_NO_COLONS"; then
  IN_CRL_LIST="да"
else
  IN_CRL_LIST="нет"
fi
echo "   Наш serial в списке: $IN_CRL_LIST"

# Проверка соответствия issuer
if [[ "$CERT_AKI" == "$CRL_SUBCA_AKI" ]]; then
  ISSUER_MATCH="да"
else
  ISSUER_MATCH="НЕТ — cert.AKI=$CERT_AKI vs crl.AKI=$CRL_SUBCA_AKI"
fi
echo "   AKI cert == AKI CRL signer: $ISSUER_MATCH"

# ─── 5. Содержимое Root CA CRL ──────────────────────────────────────
echo ""
echo "📋 Шаг 5: Root CA CRL (отозванные Sub CA)"
openssl crl -in "$WORK_DIR/rootca.crl" -text -noout | \
  awk '/Issuer:|Last Update:|Next Update:|CRL Number:/' | sed 's/^/   /'

REVOKED_IN_ROOTCA=$(openssl crl -in "$WORK_DIR/rootca.crl" -text -noout | grep -c "Serial Number:" || true)
echo "   Записей: $REVOKED_IN_ROOTCA"

# ─── 6. Экспорт CA chain из БД + проверка CDP в Sub CA ─────────────
echo ""
echo "🔍 Шаг 6: экспортирую Root CA и Sub CA из БД, проверяю CDP в Sub CA"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Root' AND cert_status=0;" > "$WORK_DIR/root_ca.pem"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Sub' AND cert_status=0;" > "$WORK_DIR/sub_ca.pem"
cat "$WORK_DIR/root_ca.pem" "$WORK_DIR/sub_ca.pem" > "$WORK_DIR/chain.pem"
cat "$WORK_DIR/subca.crl" "$WORK_DIR/rootca.crl" > "$WORK_DIR/crls.pem"

# Проверяем CDP в активном Sub CA сертификате
SUBCA_CDP=$(openssl x509 -in "$WORK_DIR/sub_ca.pem" -text -noout 2>/dev/null | \
  awk '/CRL Distribution/,/Signature Algorithm/' | grep "URI:" | sed 's/.*URI://')
EXPECTED_ROOTCA_URL="$BASE_URL/api/v1/crl/rootca/pem"
if [[ -z "$SUBCA_CDP" ]]; then
  SUBCA_CDP_OK="нет"
  echo "   ⚠️  Sub CA НЕ содержит CDP — был выпущен до фикса конфига"
  echo "      Нужно перевыпустить Sub CA, чтобы openssl мог проверить его revocation"
elif [[ "$SUBCA_CDP" != "$EXPECTED_ROOTCA_URL" ]]; then
  SUBCA_CDP_OK="мимо"
  echo "   ⚠️  Sub CA CDP указывает не на rootca/pem:"
  echo "      получено:  $SUBCA_CDP"
  echo "      ожидалось: $EXPECTED_ROOTCA_URL"
else
  SUBCA_CDP_OK="да"
  echo "   ✅ Sub CA CDP корректный: $SUBCA_CDP"
fi

echo "   ✅ chain.pem + crls.pem собраны"

# ─── 7. Валидация openssl verify ────────────────────────────────────
echo ""
echo "🔍 Шаг 7: openssl verify -crl_check_all"
VERIFY_OUT=$(openssl verify -crl_check_all \
  -CAfile "$WORK_DIR/chain.pem" \
  -CRLfile "$WORK_DIR/crls.pem" \
  "$CERT_FILE" 2>&1 || true)

echo "$VERIFY_OUT" | sed 's/^/   /'

# ─── 8. Резюме ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"

if echo "$VERIFY_OUT" | grep -qi "revoked"; then
  echo " 🛑 СЕРТИФИКАТ ОТОЗВАН (корректно попал в CRL)"
elif echo "$VERIFY_OUT" | grep -q ": OK"; then
  if [[ "$IN_CRL_LIST" == "да" && "$ISSUER_MATCH" != "да" ]]; then
    echo " ⚠️  СЕРТИФИКАТ В СПИСКЕ CRL, НО ISSUER НЕ СОВПАДАЕТ"
    echo "    Cert подписан другим Sub CA (вероятно, superseded/перевыпущенным)."
    echo "    Текущий активный Sub CA подписывает новый CRL, и openssl"
    echo "    отбрасывает его — issuer ≠ AKI cert'а. Это ПРАВИЛЬНОЕ поведение."
    echo "    Нужно: использовать тот Sub CA, который реально подписал cert."
  else
    echo " ✅ СЕРТИФИКАТ ВАЛИДЕН (нет в CRL, цепочка корректна)"
  fi
elif echo "$VERIFY_OUT" | grep -qi "unable to get certificate CRL"; then
  echo " ⚠️  openssl не нашёл CRL для одного из CA в цепочке"
  if [[ "$SUBCA_CDP_OK" != "да" ]]; then
    echo "    Причина: Sub CA не имеет правильного CDP на rootca/pem"
    echo "    → Перевыпустите Sub CA после фикса конфига"
  fi
else
  echo " ⚠️  Неоднозначный результат, см. вывод выше"
fi
if [[ "$SUBCA_CDP_OK" != "да" ]]; then
  echo ""
  echo " ℹ️  Sub CA нуждается в перевыпуске для полного соответствия RFC 5280"
fi
echo "═══════════════════════════════════════════════════════════════"
