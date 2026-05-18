package models

// ESTCert — структура сертификата, выпущенного через EST endpoint или UI
type ESTCert struct {
	Id             int    `json:"id" db:"id"`
	ESTUserId      int    `json:"ESTUserId" db:"est_user_id"`
	SerialNumber   string `json:"serial_number" db:"serial_number"`
	SigningCAId    int    `json:"SigningCAId" db:"signing_ca_id"` // 0 - Core CA, >0 - entity_ca.id
	CommonName     string `json:"CommonName" db:"common_name"`
	SAN            string `json:"SAN" db:"san"`
	PublicKey      string `json:"public_key" db:"public_key"`   // PEM сертификата
	PrivateKey     string `json:"private_key" db:"private_key"` // AES-encrypted PEM ключа
	Password       string `json:"Password" db:"password"`       // AES-encrypted пароль для экспорта ключа
	Algorithm      string `json:"Algorithm" db:"algorithm"`
	KeyLength      int    `json:"KeyLength" db:"key_length"`
	TTL            int    `json:"TTL" db:"ttl"`
	CertCreateTime string `json:"cert_create_time" db:"cert_create_time"`
	CertExpireTime string `json:"cert_expire_time" db:"cert_expire_time"`
	DaysLeft       int    `json:"DaysLeft" db:"days_left"`
	DataRevoke     string `json:"data_revoke" db:"data_revoke"`
	ReasonRevoke   string `json:"ReasonRevoke" db:"reason_revoke"`
	CertStatus     int    `json:"cert_status" db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
}

var SchemaESTCerts = `
CREATE TABLE IF NOT EXISTS est_certs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	est_user_id INTEGER NOT NULL,
	serial_number TEXT NOT NULL UNIQUE,
	signing_ca_id INTEGER NOT NULL DEFAULT 0,
	common_name TEXT,
	san TEXT,
	public_key TEXT NOT NULL,
	private_key TEXT,
	password TEXT,
	algorithm TEXT,
	key_length INTEGER,
	ttl INTEGER,
	cert_create_time TEXT,
	cert_expire_time TEXT,
	days_left INTEGER,
	data_revoke TEXT NOT NULL DEFAULT '',
	reason_revoke TEXT NOT NULL DEFAULT '',
	cert_status INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY (est_user_id) REFERENCES est_users(id)
);
CREATE INDEX IF NOT EXISTS idx_est_certs_serial ON est_certs(serial_number);
CREATE INDEX IF NOT EXISTS idx_est_certs_user ON est_certs(est_user_id);
`
