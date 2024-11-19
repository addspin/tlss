package models

type Key struct {
	Id  int    `db:"id"`
	Key string `db:"key_data"`
}

var SchemaKey = `
CREATE TABLE secret_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	key_data TEXT
);`
