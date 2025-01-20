package models

type CertsData struct {
	Id               int    `db:"id"`
	Algorithm        string `db:"algorithm"`
	KeyLength        int    `db:"key_length"`
	TTL              int    `db:"ttl"`
	Domain           string `db:"domain"`
	CommonName       string `db:"common_name"`
	CountryName      string `db:"country_name"`
	StateProvince    string `db:"state_province"`
	LocalityName     string `db:"locality_name"`
	Organization     string `db:"organization"`
	OrganizationUnit string `db:"organization_unit"`
	Email            string `db:"email"`
	Password         string `db:"password"`
	CaName           string `db:"cert_ca_name"`
	CaKey            string `db:"cert_ca_key"`
	CertName         string `db:"cert_name"`
	CertKey          string `db:"cert_key"`
	CertCreateTime   string `db:"cert_create_time"`
	CertExpireTime   string `db:"cert_expire_time"`
}

var SchemaCerts = `
CREATE TABLE IF NOT EXISTS  certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	algorithm TEXT,
	key_length INTEGER,
	ttl INTEGER,
	domain TEXT,
	common_name TEXT,
	country_name TEXT,
	state_province TEXT,
	locality_name TEXT,
	organization TEXT,
	organization_unit TEXT,
	email TEXT,
	password TEXT,
	cert_ca_name TEXT,
	cert_ca_key TEXT,
	cert_name TEXT,
	cert_key TEXT,
	cert_create_time TEXT,
	cert_expire_time TEXT
);`
