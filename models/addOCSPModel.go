package models

// OCSPCertificate представляет модель для OCSP-сертификата
type OCSPCertificate struct {
	Id        int    `db:"id"`
	CreatedAt string `db:"create_time"` // Время создания в формате RFC3339
	Domain    string `db:"domain"`      // Доменное имя сервера

	// Основная информация о сертификате
	SerialNumber string `db:"serial_number"` // Серийный номер сертификата
	IssuerName   string `db:"issuer_name"`   // Distinguished Name субъекта
	PublicKey    string `db:"public_key"`    // Публичный ключ
	PrivateKey   string `db:"private_key"`   // Приватный ключ для подписи

	// Статус и причина отзыва
	CertStatus   int    `db:"cert_status"`   // 0 - valid, 1 - expired, 2 - revoked
	ReasonRevoke string `db:"reason_revoke"` // Причина отзыва
	DataRevoke   string `db:"data_revoke"`   // Дата отзыва в формате RFC3339

	// Период действия
	CertCreateTime string `db:"cert_create_time"` // Начало срока действия в формате RFC3339
	CertExpireTime string `db:"cert_expire_time"` // Окончание срока действия в формате RFC3339

	// Поля специфичные для OCSP-респондера
	OCSPSigningEKU bool `db:"ocsp_signing_eku"` // Расширение id-kp-OCSPSigning
	OCSPNoCheck    bool `db:"ocsp_nocheck"`     // Расширение id-pkix-ocsp-nocheck Инструктирует клиентов НЕ ПРОВЕРЯТЬ статус отзыва самого сертификата OCSP-респондера

	// Информация об издателе
	IssuerSubCASerialNumber string `db:"issuer_subca_serial_number"` // серийный номер промежуточного CA
	IssuerNameHash          string `db:"issuer_name_hash"`           // хеш имени промежуточного CA
	IssuerKeyHash           string `db:"issuer_key_hash"`            // хеш публичного ключа промежуточного CA
	HashAlgorithm           string `db:"hash_algorithm"`             // Алгоритм хеширования SHA256 и выше

	// Поля для OCSP-ответов
	ThisUpdate     string `db:"this_update"`     // Время создания OCSP-ответа
	NextUpdate     string `db:"next_update"`     // Когда клиент должен проверить снова задать в конфигурации?
	OCSPExtensions string `db:"ocsp_extensions"` // Расширения OCSP в JSON, Позволяет включать дополнительную информацию в OCSP-ответы, не определенную в основной спецификации

}

// SchemaOCSPCertificate определяет SQL-схему для таблицы OCSP-сертификатов
var SchemaOCSPCertificate = `
CREATE TABLE IF NOT EXISTS ocsp_cert (
    id INTEGER PRIMARY KEY,
    create_time TEXT,
    domain TEXT,
    serial_number TEXT,
    issuer_name TEXT,
    public_key TEXT,
    private_key TEXT,
    cert_status INTEGER,
    reason_revoke TEXT,
    data_revoke TEXT,
    cert_create_time TEXT,
    cert_expire_time TEXT,
    ocsp_signing_eku BOOLEAN,
    ocsp_nocheck BOOLEAN,
    issuer_subca_serial_number TEXT,
    issuer_name_hash TEXT,
    issuer_key_hash TEXT,
    hash_algorithm TEXT,
    this_update TEXT,
    next_update TEXT,
    ocsp_extensions TEXT
);`
