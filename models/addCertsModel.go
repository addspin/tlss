package models

// структура для добавления сертификата
type CertsData struct {
	Id               int    `json:"id" db:"id"`
	ServerId         int    `json:"ServerId" db:"server_id"`
	Algorithm        string `json:"Algorithm" db:"algorithm"`
	KeyLength        int    `json:"KeyLength" db:"key_length"`
	TTL              int    `json:"TTL" db:"ttl"`
	Domain           string `json:"Domain" db:"domain"`
	Wildcard         bool   `json:"Wildcard" db:"wildcard"`
	Recreate         bool   `json:"Recreate" db:"recreate"`
	ServerStatus     string `json:"ServerStatus" db:"server_status"` // online, offline
	SaveOnServer     bool   `json:"SaveOnServer" db:"save_on_server"`
	CommonName       string `json:"CommonName" db:"common_name"`
	SAN              string `json:"SAN" db:"san"`
	CountryName      string `json:"CountryName" db:"country_name"`
	StateProvince    string `json:"StateProvince" db:"state_province"`
	LocalityName     string `json:"LocalityName" db:"locality_name"`
	AppType          string `json:"AppType" db:"app_type"`
	Organization     string `json:"Organization" db:"organization"`
	OrganizationUnit string `json:"OrganizationUnit" db:"organization_unit"`
	Email            string `json:"Email" db:"email"`
	// Password         string `json:"password"`
	// CaName           string `json:"cert_ca_name"`
	// CaKey            string `json:"cert_ca_key"`
	PublicKey      string `json:"public_key" db:"public_key"`
	PrivateKey     string `json:"private_key" db:"private_key"`
	CertCreateTime string `json:"cert_create_time" db:"cert_create_time"`
	CertExpireTime string `json:"cert_expire_time" db:"cert_expire_time"`
	DaysLeft       int    `json:"DaysLeft" db:"days_left"`
	SerialNumber   string `json:"serial_number" db:"serial_number"`
	DataRevoke     string `json:"data_revoke" db:"data_revoke"`
	ReasonRevoke   string `json:"ReasonRevoke" db:"reason_revoke"`
	CertStatus     int    `json:"cert_status" db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
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
	save_on_server BOOLEAN,
	app_type TEXT,
	common_name TEXT,
	san TEXT,
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
