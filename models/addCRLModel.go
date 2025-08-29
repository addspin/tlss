package models

type CRLInfo struct {
	Version                int    `db:"version"`
	SignatureAlgorithm     string `db:"signature_algorithm"`
	IssuerName             string `db:"issuer_name"` //отличительное имя (Distinguished Name) удостоверяющего центра, выпустившего CRL
	LastUpdate             string `db:"last_update"`
	NextUpdate             string `db:"next_update"`
	CrlNumber              int    `db:"crl_number"`               // последовательный номер для отслеживания обновлений
	AuthorityKeyIdentifier string `db:"authority_key_identifier"` // идентификатор ключа удостоверяющего центра
	CrlURL                 string `db:"crl_url"`                  // URL-адрес CRL
}

var SchemaCrlInfoSubCA = `
CREATE TABLE IF NOT EXISTS sub_ca_crl_info (
	version INTEGER,
	signature_algorithm TEXT,
	issuer_name TEXT,
	last_update TEXT,
	next_update TEXT,
	crl_number INTEGER,
	authority_key_identifier TEXT,
	crl_url TEXT
);`

var SchemaCrlInfoRootCA = `
CREATE TABLE IF NOT EXISTS root_ca_crl_info (
	version INTEGER,
	signature_algorithm TEXT,
	issuer_name TEXT,
	last_update TEXT,
	next_update TEXT,
	crl_number INTEGER,
	authority_key_identifier TEXT,
	crl_url TEXT
);`
