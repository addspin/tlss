package models

import "time"

type StateCA struct {
	Id        int       `db:"id"`
	State     bool      `db:"state"`
	CreatedAt time.Time `db:"created_at"`
}

var SchemaStateCA = `
CREATE TABLE IF NOT EXISTS state_ca (
    id INTEGER PRIMARY KEY,
	state BOOLEAN,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
