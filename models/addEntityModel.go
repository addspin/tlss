package models

// структура для добавления сущности
type EntityData struct {
	Id                int    `json:"Id" db:"id"`
	EntityName        string `json:"EntityName" db:"entity_name"`
	EntityDescription string `json:"EntityDescription" db:"entity_description"`
}

var SchemaEntity = `
CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_name TEXT,
	entity_description TEXT
);`
