package models

// type UserCerts struct {
// 	Id               int    `db:"id"`
// 	EntityId         int    `db:"entity_id"`
// 	Algorithm        string `db:"algorithm"`
// 	KeyLength        int    `db:"key_length"`
// 	TTL              int    `db:"ttl"`
// 	Recreate         bool   `db:"recreate"`
// 	CommonName       string `db:"common_name"`
// 	CountryName      string `db:"country_name"`
// 	StateProvince    string `db:"state_province"`
// 	LocalityName     string `db:"locality_name"`
// 	Organization     string `db:"organization"`
// 	OrganizationUnit string `db:"organization_unit"`
// 	Email            string `db:"email"`
// 	Password         string `db:"password"`
// 	// CaName           string `db:"cert_ca_name"`
// 	// CaKey            string `db:"cert_ca_key"`
// 	PublicKey      string `db:"public_key"`
// 	PrivateKey     string `db:"private_key"`
// 	CertCreateTime string `db:"cert_create_time"`
// 	CertExpireTime string `db:"cert_expire_time"`
// 	DaysLeft       int    `db:"days_left"`
// 	SerialNumber   string `db:"serial_number"`
// 	DataRevoke     string `db:"data_revoke"`
// 	ReasonRevoke   string `db:"reason_revoke"`
// 	CertStatus     int    `db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
// }

// структура для добавления сертификата
type UserCertsData struct {
	Id               int    `json:"Id" db:"id"`
	EntityId         int    `json:"EntityId" db:"entity_id"`
	Algorithm        string `json:"Algorithm" db:"algorithm"`
	KeyLength        int    `json:"KeyLength" db:"key_length"`
	TTL              int    `json:"TTL" db:"ttl"`
	Recreate         bool   `json:"Recreate" db:"recreate"`
	CommonName       string `json:"CommonName" db:"common_name"`
	SAN              string `json:"SAN" db:"san"`
	OID              string `json:"OID" db:"oid"`
	OIDValues        string `json:"OIDValues" db:"oid_values"`
	CountryName      string `json:"CountryName" db:"country_name"`
	StateProvince    string `json:"StateProvince" db:"state_province"`
	LocalityName     string `json:"LocalityName" db:"locality_name"`
	Organization     string `json:"Organization" db:"organization"`
	OrganizationUnit string `json:"OrganizationUnit" db:"organization_unit"`
	Email            string `json:"Email" db:"email"`
	Password         string `json:"Password" db:"password"`
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
	CertStatus     int    `json:"CertStatus" db:"cert_status"` // 0 - valid, 1 - expired, 2 - revoked
}

var SchemaUserCerts = `
CREATE TABLE IF NOT EXISTS  user_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_id INTEGER,
	algorithm TEXT,
	key_length INTEGER,
	ttl INTEGER,
	recreate BOOLEAN,
	common_name TEXT,
	san TEXT,
	oid TEXT,
	oid_values TEXT,
	country_name TEXT,
	state_province TEXT,
	locality_name TEXT,
	organization TEXT,
	organization_unit TEXT,
	email TEXT,
	password TEXT,
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
