package models

type Users struct {
	Id       int    `db:"id"`
	Username string `db:"username"`
	Password string `db:"password"`
}

var UsersData = `
CREATE TABLE IF NOT EXISTS  users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT
);`
