package models

type SSHKey struct {
	Id         int    `json:"id" db:"id"`
	ServerName string `json:"ServerName" db:"server_name"`
	PublicKey  string `json:"public_key" db:"public_key"`
	PrivateKey string `json:"private_key" db:"private_key"`
}

var SchemaSSHKey = `
CREATE TABLE IF NOT EXISTS ssh_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	server_name TEXT,
	public_key TEXT,
	private_key TEXT
);`
