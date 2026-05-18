package models

// структура  пользователей для первичной авторизации через EST для basic auth
type ESTUser struct {
	Id             int    `json:"Id" db:"id"`
	Username       string `json:"username" db:"username"`
	PasswordHash   string `json:"password_hash" db:"password_hash"`
	MaxUses        int    `json:"max_uses" db:"max_uses"`       // 1 - можно использовать, 0 - нельзя
	UserStatus     int    `json:"user_status" db:"user_status"` // 0 - active, 1 - expired, 3 - disabled
	UserCreateTime string `json:"user_create_time" db:"user_create_time"`
	UserExpireTime string `json:"user_expire_time" db:"user_expire_time"` // елси истекает переводит MaxUses в 0 и UserStatus в 1
	TTL            int    `json:"TTL" db:"ttl"`                           // время жизни
	DaysLeft       int    `json:"DaysLeft" db:"days_left"`                // осталось дней
	SigningCAId    int    `json:"SigningCAId" db:"signing_ca_id"`         // id подписывающего ca
}

var SchemaESTUser = `
CREATE TABLE IF NOT EXISTS est_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT,
	password_hash TEXT,
	max_uses INTEGER NOT NULL DEFAULT 1,
	user_status INTEGER NOT NULL DEFAULT 0,
	user_create_time TEXT,
	user_expire_time TEXT,
	ttl INTEGER NOT NULL DEFAULT 0,
	days_left INTEGER NOT NULL DEFAULT 0,
	signing_ca_id INTEGER DEFAULT 0
);`
