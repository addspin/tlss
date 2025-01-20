package models

import "time"

type RootCA struct {
	Id               int       `db:"id"`
	State            bool      `db:"state"`
	CreatedAt        time.Time `db:"create_time"`
	TTL              int       `db:"ttl"`
	CommonName       string    `db:"common_name"`
	CountryName      string    `db:"country_name"`
	StateProvince    string    `db:"state_province"`
	LocalityName     string    `db:"locality_name"`
	Organization     string    `db:"organization"`
	OrganizationUnit string    `db:"organization_unit"`
	Email            string    `db:"email"`
}

var SchemaRootCAtlss = `
CREATE TABLE IF NOT EXISTS root_ca_tlss (
    id INTEGER PRIMARY KEY,
    state BOOLEAN,
    create_time DATETIME DEFAULT (datetime('now', 'localtime')),
    ttl INTEGER,
    common_name TEXT,
    country_name TEXT,
    state_province TEXT,
    locality_name TEXT,
    organization TEXT,
    organization_unit TEXT,
    email TEXT
);`
