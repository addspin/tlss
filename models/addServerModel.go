package models

type AddServer struct {
	Id             int    `db:"id"`
	Hostname       string `db:"hostname"`
	CertConfigPath string `db:"cert_config_path"`
	CertCaName     string `db:"cert_ca_name"`
	CertName       string `db:"cert_name"`
}

var Schema = `
CREATE TABLE add_server (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname TEXT,
	cert_config_path TEXT,
	cert_ca_name TEXT,
	cert_name TEXT
);`
