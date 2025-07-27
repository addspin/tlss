package models

type RootCA struct {
	Id               int    `db:"id"`
	CreatedAt        string `db:"create_time"`
	TTL              int    `db:"ttl"`
	CommonName       string `db:"common_name"`
	CountryName      string `db:"country_name"`
	StateProvince    string `db:"state_province"`
	LocalityName     string `db:"locality_name"`
	Organization     string `db:"organization"`
	OrganizationUnit string `db:"organization_unit"`
	Email            string `db:"email"`
	PublicKey        string `db:"public_key"`
	SerialNumber     string `db:"serial_number"`
	DataRevoke       string `db:"data_revoke"`
	ReasonRevoke     string `db:"reason_revoke"`
	RootCAStatus     int    `db:"root_ca_status"` // 0 - valid, 1 - expired, 2 - revoked
}

var SchemaRootCAtlss = `
CREATE TABLE IF NOT EXISTS root_ca_tlss (
    id INTEGER PRIMARY KEY,
    create_time TEXT,
    ttl INTEGER,
    common_name TEXT,
    country_name TEXT,
    state_province TEXT,
    locality_name TEXT,
    organization TEXT,
    organization_unit TEXT,
    email TEXT,
    public_key TEXT,
    root_ca_status INTEGER,
	serial_number TEXT,
	data_revoke TEXT,
	reason_revoke TEXT
);`
