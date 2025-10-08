package models

type SSHKey struct {
	Id         int    `json:"id" db:"id"`
	NameSSHKey string `json:"nameSSHKey" db:"name_ssh_key"`
	PublicKey  string `json:"public_key" db:"public_key"`
	PrivateKey string `json:"private_key" db:"private_key"`
	KeyLength  int    `json:"keyLength" db:"key_length"`
	Algorithm  string `json:"algorithm" db:"algorithm"`
}

var SchemaSSHKey = `
CREATE TABLE IF NOT EXISTS ssh_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	name_ssh_key TEXT,
	public_key TEXT,
	private_key TEXT,
	key_length INTEGER,
	algorithm TEXT
);`
