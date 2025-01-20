package models

import "time"

type SubCA struct {
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
	PublicKey        string    `db:"public_key"`
	PrivateKey       string    `db:"private_key"`
}

var SchemaSubCAtlss = `
CREATE TABLE IF NOT EXISTS sub_ca_tlss (
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
    email TEXT,
    public_key TEXT,
    private_key TEXT
);`
