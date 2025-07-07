package models

type Server struct {
	Id             int    `db:"id"`
	Hostname       string `db:"hostname"`
	Port           int    `db:"port"`
	Username       string `db:"username"`
	CertConfigPath string `db:"cert_config_path"`
	ServerStatus   string `db:"server_status"`
}

// структура для добавления сервера
type ServerData struct {
	Id          int    `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TlssSSHport int    `json:"tlssSSHport"`
	Path        string `json:"path"`
}

var SchemaServer = `
CREATE TABLE IF NOT EXISTS server (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname TEXT,
	port INTEGER,
	username TEXT,
	cert_config_path TEXT,
	server_status TEXT DEFAULT 'offline'
);`
