package models

type Entity struct {
	Id                int    `db:"id"`
	EntityName        string `db:"entity_name"`
	EntityDescription string `db:"entity_description"`
}

// структура для добавления сервера
type EntityData struct {
	Id                string `json:"id"`
	EntityName        string `json:"entity_name"`
	EntityDescription string `json:"entity_description"`
}

var SchemaEntity = `
CREATE TABLE IF NOT EXISTS entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_name TEXT,
	entity_description TEXT
);`
