package models

// структура для добавления сущности
type EntityData struct {
	Id                int    `json:"Id" db:"id"`
	EntityName        string `json:"EntityName" db:"entity_name"`
	EntityDescription string `json:"EntityDescription" db:"entity_description"`
}

type EntityCAData struct {
	Id                  int    `json:"Id" db:"id"`
	EntityCAName        string `json:"EntityCAName" db:"entity_ca_name"`
	EntityCADescription string `json:"EntityCADescription" db:"entity_ca_description"`
}

var SchemaEntity = `
CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_name TEXT,
	entity_description TEXT
);`

var SchemaEntityCA = `
CREATE TABLE IF NOT EXISTS entity_ca (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_ca_name TEXT,
	entity_ca_description TEXT
);`
