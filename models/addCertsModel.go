package models

type Certs struct {
	Id               int    `db:"id"`
	ServerId         int    `db:"server_id"`
	Algorithm        string `db:"algorithm"`
	KeyLength        int    `db:"key_length"`
	TTL              int    `db:"ttl"`
	Domain           string `db:"domain"`
	Wildcard         bool   `db:"wildcard"`
	Recreate         bool   `db:"recreate"`
	CommonName       string `db:"common_name"`
	CountryName      string `db:"country_name"`
	StateProvince    string `db:"state_province"`
	LocalityName     string `db:"locality_name"`
	AppType          string `db:"app_type"`
	Organization     string `db:"organization"`
	OrganizationUnit string `db:"organization_unit"`
	Email            string `db:"email"`
	// Password         string `db:"password"`
	// CaName           string `db:"cert_ca_name"`
	// CaKey            string `db:"cert_ca_key"`
	PublicKey      string `db:"public_key"`
	PrivateKey     string `db:"private_key"`
	CertCreateTime string `db:"cert_create_time"`
	CertExpireTime string `db:"cert_expire_time"`
	DaysLeft       int    `db:"days_left"`
	SerialNumber   string `db:"serial_number"`
	DataRevoke     string `db:"data_revoke"`
	ReasonRevoke   string `db:"reason_revoke"`
	CertStatus     int    `db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
}

// структура для добавления сертификата
type CertsData struct {
	Id               string `json:"id"`
	ServerId         string `json:"server_id"`
	Algorithm        string `json:"algorithm"`
	KeyLength        string `json:"key_length"`
	TTL              string `json:"ttl"`
	Domain           string `json:"domain"`
	Wildcard         string `json:"wildcard"`
	Recreate         string `json:"recreate"`
	CommonName       string `json:"common_name"`
	CountryName      string `json:"country_name"`
	StateProvince    string `json:"state_province"`
	LocalityName     string `json:"locality_name"`
	AppType          string `json:"app_type"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Email            string `json:"email"`
	// Password         string `json:"password"`
	// CaName           string `json:"cert_ca_name"`
	// CaKey            string `json:"cert_ca_key"`
	PublicKey      string `json:"public_key"`
	PrivateKey     string `json:"private_key"`
	CertCreateTime string `json:"cert_create_time"`
	CertExpireTime string `json:"cert_expire_time"`
	DaysLeft       string `json:"days_left"`
	SerialNumber   string `json:"serial_number"`
	DataRevoke     string `json:"data_revoke"`
	ReasonRevoke   string `json:"reason_revoke"`
	CertStatus     string `json:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
}

var SchemaCerts = `
CREATE TABLE IF NOT EXISTS  certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id INTEGER,
	algorithm TEXT,
	key_length INTEGER,
	ttl INTEGER,
	domain TEXT,
	wildcard BOOLEAN,
	recreate BOOLEAN,
	app_type TEXT,
	common_name TEXT,
	country_name TEXT,
	state_province TEXT,
	locality_name TEXT,
	organization TEXT,
	organization_unit TEXT,
	email TEXT,
	public_key TEXT,
	private_key TEXT,
	cert_create_time TEXT,
	cert_expire_time TEXT,
	days_left INTEGER,
	serial_number TEXT,
	data_revoke TEXT,
	reason_revoke TEXT,
	cert_status INTEGER
);`
