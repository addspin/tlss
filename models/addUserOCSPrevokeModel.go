package models

// OCSPCertificate представляет модель для OCSP-сертификата
type UserOCSPRevoke struct {
	Id             int    `db:"id"`
	CommonName     string `db:"common_name"`
	CertCreateTime string `db:"cert_create_time"`
	CertExpireTime string `db:"cert_expire_time"`
	DaysLeft       int    `db:"days_left"`
	SerialNumber   string `db:"serial_number"`
	DataRevoke     string `db:"data_revoke"`
	ReasonRevoke   string `db:"reason_revoke"`
	CertStatus     int    `db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
}

// SchemaUserOCSPRevoke определяет SQL-схему для таблицы OCSP-сертификатов
var SchemaUserOCSPRevoke = `
CREATE TABLE IF NOT EXISTS user_ocsp_revoke (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   common_name TEXT NOT NULL DEFAULT '',
   cert_create_time TEXT NOT NULL DEFAULT '',
   cert_expire_time TEXT NOT NULL DEFAULT '',
   days_left INTEGER NOT NULL DEFAULT 0,
   serial_number TEXT NOT NULL DEFAULT '' UNIQUE,
   data_revoke TEXT NOT NULL DEFAULT '',
   reason_revoke TEXT NOT NULL DEFAULT '',
   cert_status INTEGER NOT NULL DEFAULT 0,
   issuer_name TEXT NOT NULL DEFAULT '',
   issuer_subca_serial_number TEXT NOT NULL DEFAULT '',
   issuer_name_hash TEXT NOT NULL DEFAULT '',
   issuer_key_hash TEXT NOT NULL DEFAULT '',
   hash_algorithm TEXT NOT NULL DEFAULT '',
   this_update TEXT NOT NULL DEFAULT '',
   next_update TEXT NOT NULL DEFAULT ''
);`
