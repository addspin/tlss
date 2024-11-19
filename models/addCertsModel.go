package models

type Certs struct {
	Id             int    `db:"id"`
	Hostname       string `db:"hostname"`
	CaName         string `db:"cert_ca_name"`
	CertName       string `db:"cert_name"`
	CertCreateTime string `db:"cert_create_time"`
	CertExpireTime string `db:"cert_expire_time"`
}

var SchemaCerts = `
CREATE TABLE certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname TEXT,
	cert_ca_name TEXT,
	cert_name TEXT,
	cert_create_time TEXT,
	cert_expire_time TEXT
);`
