#!/usr/bin/env bash
# Сквозная сверка статуса отзыва: база данных ↔ CRL ↔ OCSP.
#
# Проверяет, что все три источника согласованы с учётом правил:
#   cert_status=2, signing_ca_id=0  → есть в CRL,   OCSP: revoked
#   cert_status=2, signing_ca_id>0  → НЕТ в CRL,    OCSP: revoked  (внешний CA)
#   cert_status=0|1                 → НЕТ в CRL,    OCSP: good
#
# Использование:
#   ./test_revocation.sh              # берёт последний отозванный сертификат
#   ./test_revocation.sh <serial>     # конкретный серийный номер
#
# Переменные окружения:
#   CRL_URL  — база CRL-эндпоинтов (по умолчанию http://tlss.lv.local:8080)
#   OCSP_URL — URL респондера       (по умолчанию $CRL_URL/ocsp)
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
CRL_URL="${CRL_URL:-http://tlss.lv.local:8080}"
OCSP_URL="${OCSP_URL:-${CRL_URL%/}/ocsp}"
WORK_DIR="$(mktemp -d -t tlss-revocation-XXXX)"
trap "rm -rf $WORK_DIR" EXIT

if [[ ! -f "$DB" ]]; then
  echo "❌ База данных не найдена: $DB"
  exit 1
fi

SERIAL="${1:-}"

# to_epoch переводит дату в unix-время. Понимает формат openssl
# ("Aug 14 05:45:12 2026 GMT") и RFC3339 из базы ("2026-08-14T09:45:12+04:00").
# Поддерживает BSD date (macOS) и GNU date; при неудаче возвращает пустую строку.
to_epoch() {
  local s="$1"
  # RFC3339: убираем двоеточие в офсете, BSD date его не понимает
  local rfc="${s/+0([0-9]):/+0\1}"
  rfc=$(printf '%s' "$s" | sed 's/\([+-][0-9][0-9]\):\([0-9][0-9]\)$/\1\2/; s/Z$/+0000/')

  date -j -f "%b %e %H:%M:%S %Y %Z" "$s"   +%s 2>/dev/null && return 0
  date -j -f "%Y-%m-%dT%H:%M:%S%z"  "$rfc" +%s 2>/dev/null && return 0
  date -d "$s" +%s 2>/dev/null && return 0
  echo ""
}

echo "═══════════════════════════════════════════════════════════════"
echo " TLSS REVOCATION CONSISTENCY TEST  (БД ↔ CRL ↔ OCSP)"
echo " CRL:  $CRL_URL"
echo " OCSP: $OCSP_URL"
echo " DB:   $DB"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Выбираем сертификат и читаем его состояние в базе ───────────
echo ""
if [[ -z "$SERIAL" ]]; then
  echo "🔍 Шаг 1: ищу последний отозванный сертификат"
  SERIAL=$(sqlite3 "$DB" "
    SELECT serial_number FROM (
      SELECT serial_number, id FROM certs      WHERE cert_status = 2
      UNION ALL
      SELECT serial_number, id FROM user_certs WHERE cert_status = 2
      UNION ALL
      SELECT serial_number, id FROM est_certs  WHERE cert_status = 2
    ) ORDER BY id DESC LIMIT 1;")

  if [[ -z "$SERIAL" ]]; then
    echo "   Отозванных нет, беру последний валидный"
    SERIAL=$(sqlite3 "$DB" "SELECT serial_number FROM certs WHERE cert_status = 0 ORDER BY id DESC LIMIT 1;")
  fi
else
  echo "🔍 Шаг 1: проверяю serial=$SERIAL"
fi

if [[ -z "$SERIAL" ]]; then
  echo "❌ В базе нет ни одного сертификата для проверки"
  exit 1
fi

# Ищем сертификат во всех таблицах: конечные + Sub CA
ROW=""
for table in certs user_certs est_certs; do
  ROW=$(sqlite3 -separator '|' "$DB" \
    "SELECT '$table', cert_status, signing_ca_id, COALESCE(common_name,''), COALESCE(reason_revoke,''), COALESCE(data_revoke,'')
     FROM $table WHERE serial_number = '$SERIAL';" 2>/dev/null || true)
  [[ -n "$ROW" ]] && break
done
if [[ -z "$ROW" ]]; then
  # Возможно, это сертификат Sub CA - у него нет signing_ca_id
  ROW=$(sqlite3 -separator '|' "$DB" \
    "SELECT 'ca_certs', cert_status, -1, COALESCE(common_name,''), COALESCE(reason_revoke,''), COALESCE(data_revoke,'')
     FROM ca_certs WHERE serial_number = '$SERIAL' AND type_ca = 'Sub';" 2>/dev/null || true)
fi
if [[ -z "$ROW" ]]; then
  echo "❌ Сертификат с serial=$SERIAL не найден ни в одной таблице"
  exit 1
fi

IFS='|' read -r TABLE DB_STATUS SIGNING_CA CN REASON REVOKED_AT <<< "$ROW"

case "$DB_STATUS" in
  0) DB_STATUS_NAME="valid" ;;
  1) DB_STATUS_NAME="expired" ;;
  2) DB_STATUS_NAME="revoked" ;;
  *) DB_STATUS_NAME="unknown($DB_STATUS)" ;;
esac

echo "   Таблица:      $TABLE"
echo "   CN:           $CN"
echo "   Serial:       $SERIAL"
echo "   cert_status:  $DB_STATUS ($DB_STATUS_NAME)"
if [[ "$SIGNING_CA" == "-1" ]]; then
  echo "   Издатель:     Core Root CA (сертификат Sub CA)"
elif [[ "$SIGNING_CA" == "0" ]]; then
  echo "   Издатель:     Core Sub CA (signing_ca_id=0)"
else
  echo "   Издатель:     внешний CA (signing_ca_id=$SIGNING_CA)"
fi
if [[ "$DB_STATUS" == "2" ]]; then
  # В базе время хранится с локальным офсетом, в CRL и OCSP по RFC 5280 §5.1.2.6
  # оно обязано быть в Zulu - показываем оба представления, чтобы не путало
  DB_REVOKED_EPOCH=$(to_epoch "$REVOKED_AT")
  if [[ -n "$DB_REVOKED_EPOCH" ]]; then
    DB_REVOKED_UTC=$(date -u -r "$DB_REVOKED_EPOCH" "+%b %e %H:%M:%S %Y GMT" 2>/dev/null \
                  || date -u -d "@$DB_REVOKED_EPOCH" "+%b %e %H:%M:%S %Y GMT" 2>/dev/null)
    echo "   Отозван:      $REVOKED_AT ($REASON)"
    echo "                 = $DB_REVOKED_UTC  ← в этом виде ожидается в CRL и OCSP"
  else
    echo "   Отозван:      $REVOKED_AT ($REASON)"
  fi
fi

# ─── 2. Ожидаемое поведение ─────────────────────────────────────────
echo ""
echo "🔍 Шаг 2: ожидаемое поведение для этой комбинации"
if [[ "$DB_STATUS" == "2" ]]; then
  EXPECT_OCSP="revoked"
  if [[ "$SIGNING_CA" == "0" || "$SIGNING_CA" == "-1" ]]; then
    EXPECT_CRL="да"
  else
    # Сертификаты внешних CA намеренно исключены из нашего CRL:
    # он подписан Core Sub CA и для них неприменим
    EXPECT_CRL="нет"
  fi
else
  EXPECT_OCSP="good"
  EXPECT_CRL="нет"
fi
echo "   В CRL:  $EXPECT_CRL"
echo "   В OCSP: $EXPECT_OCSP"

# ─── 3. Готовим цепочку CA ──────────────────────────────────────────
echo ""
echo "🔍 Шаг 3: экспортирую издателя из базы"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Root' AND cert_status=0;" > "$WORK_DIR/root_ca.pem"
sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE type_ca='Sub'  AND cert_status=0;" > "$WORK_DIR/sub_ca.pem"

ISSUER_FILE="$WORK_DIR/sub_ca.pem"
CRL_PATH="/api/v1/crl/subca/pem"
if [[ "$SIGNING_CA" == "-1" ]]; then
  # Sub CA сертификат выпущен Root CA
  ISSUER_FILE="$WORK_DIR/root_ca.pem"
  CRL_PATH="/api/v1/crl/rootca/pem"
elif [[ "$SIGNING_CA" != "0" ]]; then
  # Внешний CA: сначала пробуем Sub, затем Root в этой группе
  sqlite3 "$DB" "SELECT public_key FROM ca_certs_ext
    WHERE entity_ca_id = $SIGNING_CA AND cert_status = 0
    ORDER BY CASE type_ca WHEN 'Sub' THEN 1 WHEN 'Intermediate' THEN 2 ELSE 3 END
    LIMIT 1;" > "$WORK_DIR/ext_ca.pem"
  if [[ -s "$WORK_DIR/ext_ca.pem" ]]; then
    ISSUER_FILE="$WORK_DIR/ext_ca.pem"
  else
    echo "   ⚠️  Внешний CA entity_ca_id=$SIGNING_CA не найден в ca_certs_ext"
  fi
fi
echo "   Издатель: $(openssl x509 -in "$ISSUER_FILE" -noout -subject 2>/dev/null | sed 's/subject=//')"

# Сертификат проверяемого объекта нужен для OCSP-запроса
CERT_FILE="$WORK_DIR/cert.pem"
if [[ "$TABLE" == "ca_certs" ]]; then
  sqlite3 "$DB" "SELECT public_key FROM ca_certs WHERE serial_number = '$SERIAL';" > "$CERT_FILE"
else
  sqlite3 "$DB" "SELECT public_key FROM $TABLE WHERE serial_number = '$SERIAL';" > "$CERT_FILE"
fi

# ─── 4. Статус в CRL ────────────────────────────────────────────────
echo ""
echo "🔍 Шаг 4: статус в CRL ($CRL_PATH)"
CRL_REVOKED_AT=""
if curl -sS -f -o "$WORK_DIR/crl.pem" "${CRL_URL%/}$CRL_PATH" 2>/dev/null; then
  openssl crl -in "$WORK_DIR/crl.pem" -text -noout > "$WORK_DIR/crl.txt" 2>/dev/null || true

  # openssl дополняет серийный номер до чётного числа hex-цифр ведущим нулём,
  # поэтому сверяем с обоими вариантами записи
  SERIAL_PADDED="$SERIAL"
  (( ${#SERIAL} % 2 )) && SERIAL_PADDED="0$SERIAL"

  if grep -qiE "Serial Number: *(${SERIAL}|${SERIAL_PADDED})\$" "$WORK_DIR/crl.txt"; then
    ACTUAL_CRL="да"
    # Дата отзыва идёт следующей строкой после серийного номера
    CRL_REVOKED_AT=$(grep -iA1 -E "Serial Number: *(${SERIAL}|${SERIAL_PADDED})\$" "$WORK_DIR/crl.txt" \
      | awk -F': ' '/Revocation Date:/{print $2; exit}')
  else
    ACTUAL_CRL="нет"
  fi

  CRL_COUNT=$(grep -c "Serial Number:" "$WORK_DIR/crl.txt" || true)
  echo "   Записей в CRL: $CRL_COUNT"
  echo "   Наш serial:    $ACTUAL_CRL"
  [[ -n "$CRL_REVOKED_AT" ]] && echo "   Revocation Date: $CRL_REVOKED_AT"
else
  ACTUAL_CRL="ошибка"
  echo "   ❌ Не удалось скачать CRL с ${CRL_URL%/}$CRL_PATH"
fi

# ─── 5. Статус в OCSP ───────────────────────────────────────────────
echo ""
echo "🔍 Шаг 5: статус в OCSP ($OCSP_URL)"
OCSP_OUT=$(openssl ocsp \
  -issuer "$ISSUER_FILE" \
  -cert "$CERT_FILE" \
  -url "$OCSP_URL" \
  -no_nonce \
  -resp_text 2>&1 || true)

ACTUAL_OCSP=$(echo "$OCSP_OUT" | awk '/Cert Status:/{print $3; exit}')
OCSP_REVOKED_AT=$(echo "$OCSP_OUT" | awk -F': ' '/Revocation Time:/{print $2; exit}')
OCSP_REASON=$(echo "$OCSP_OUT" | awk -F': ' '/Revocation Reason:/{print $2; exit}' | awk '{print $1}')

if [[ -z "$ACTUAL_OCSP" ]]; then
  ACTUAL_OCSP="ошибка"
  echo "   ❌ Статус не получен:"
  echo "$OCSP_OUT" | grep -iE "error|responder|unauthorized" | head -3 | sed 's/^/      /'
else
  echo "   Cert Status:     $ACTUAL_OCSP"
  [[ -n "$OCSP_REVOKED_AT" ]] && echo "   Revocation Time: $OCSP_REVOKED_AT"
  [[ -n "$OCSP_REASON" ]] && echo "   Revocation Reason: $OCSP_REASON"
fi

# ─── 6. Сверка ──────────────────────────────────────────────────────
echo ""
echo "🔍 Шаг 6: сверка источников"
FAILED=0

printf "   %-22s %-10s %-10s %s\n" "Источник" "Ожидалось" "Получено" "Итог"
printf "   %-22s %-10s %-10s " "CRL" "$EXPECT_CRL" "$ACTUAL_CRL"
if [[ "$ACTUAL_CRL" == "$EXPECT_CRL" ]]; then
  echo "✅"
else
  echo "❌"
  FAILED=1
fi

printf "   %-22s %-10s %-10s " "OCSP" "$EXPECT_OCSP" "$ACTUAL_OCSP"
if [[ "$ACTUAL_OCSP" == "$EXPECT_OCSP" ]]; then
  echo "✅"
else
  echo "❌"
  FAILED=1
fi

# Для отозванных дополнительно сверяем причину и момент отзыва
if [[ "$DB_STATUS" == "2" && "$ACTUAL_OCSP" == "revoked" ]]; then
  # OCSP печатает каноничное имя причины, база хранит значение из UI
  if [[ -n "$OCSP_REASON" ]]; then
    if [[ "$(echo "$OCSP_REASON" | tr '[:upper:]' '[:lower:]')" == "$(echo "$REASON" | tr '[:upper:]' '[:lower:]')" ]]; then
      printf "   %-22s %-14s %-14s ✅\n" "Reason" "$REASON" "$OCSP_REASON"
    else
      printf "   %-22s %-14s %-14s ❌\n" "Reason" "$REASON" "$OCSP_REASON"
      FAILED=1
    fi
  fi

  # Время в базе хранится с локальным офсетом, в протоколах - в UTC.
  # Сравниваем момент времени, а не строки.
  OCSP_EPOCH=$(to_epoch "$OCSP_REVOKED_AT")
  if [[ -n "$DB_REVOKED_EPOCH" && -n "$OCSP_EPOCH" ]]; then
    if [[ "$DB_REVOKED_EPOCH" == "$OCSP_EPOCH" ]]; then
      printf "   %-22s %-14s %-14s ✅\n" "Время отзыва: БД=OCSP" "$DB_REVOKED_EPOCH" "$OCSP_EPOCH"
    else
      printf "   %-22s %-14s %-14s ❌\n" "Время отзыва: БД=OCSP" "$DB_REVOKED_EPOCH" "$OCSP_EPOCH"
      echo "      БД:   $REVOKED_AT"
      echo "      OCSP: $OCSP_REVOKED_AT"
      FAILED=1
    fi
  fi

  CRL_EPOCH=$(to_epoch "$CRL_REVOKED_AT")
  if [[ -n "$CRL_EPOCH" && -n "$OCSP_EPOCH" ]]; then
    if [[ "$CRL_EPOCH" == "$OCSP_EPOCH" ]]; then
      printf "   %-22s %-14s %-14s ✅\n" "Время отзыва: CRL=OCSP" "$CRL_EPOCH" "$OCSP_EPOCH"
    else
      printf "   %-22s %-14s %-14s ❌\n" "Время отзыва: CRL=OCSP" "$CRL_EPOCH" "$OCSP_EPOCH"
      echo "      CRL:  $CRL_REVOKED_AT"
      echo "      OCSP: $OCSP_REVOKED_AT"
      FAILED=1
    fi
  fi
fi

# ─── 7. Резюме ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ "$FAILED" == "0" ]]; then
  echo " ✅ БД, CRL и OCSP СОГЛАСОВАНЫ"
  echo "    $CN ($SERIAL) — $DB_STATUS_NAME"
else
  echo " ❌ РАСХОЖДЕНИЕ МЕЖДУ ИСТОЧНИКАМИ"
  echo "    $CN ($SERIAL) — в базе $DB_STATUS_NAME"
  echo "    Если сертификат недавно отозван, убедитесь что CRL перегенерирован:"
  echo "    статус отзыва пишется в CRL сразу, но кэш клиента может отставать"
fi
echo "═══════════════════════════════════════════════════════════════"
[[ "$FAILED" == "0" ]]
