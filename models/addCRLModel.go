package models

type CRL struct {
	Id      int    `db:"id"`
	TypeCRL string `db:"type_crl"` // Root, Sub, Bundle
	DataCRL string `db:"data_crl"`
}

var SchemaCRL = `
CREATE TABLE IF NOT EXISTS crl (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	type_crl TEXT UNIQUE,
	data_crl TEXT
);`
