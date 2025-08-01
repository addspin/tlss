package models

// структура для добавления сущности
type OIDData struct {
	Id             int    `json:"Id" db:"id"`
	OIDName        string `json:"OIDName" db:"oid_name"`
	OIDDescription string `json:"OIDDescription" db:"oid_description"`
}

var SchemaOID = `
CREATE TABLE IF NOT EXISTS oid (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	oid_name TEXT,
	oid_description TEXT
);`
