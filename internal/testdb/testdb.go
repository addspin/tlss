// Package testdb creates a throwaway SQLite database with the full TLSS schema,
// for use from _test.go files across packages. It exists as a regular (non-test)
// file because Go does not allow importing *_test.go files from other packages.
//
// The database lives entirely under t.TempDir() and is closed and removed
// automatically when the test finishes - nothing here is meant to be committed
// as data, only the schema-creation code itself.
package testdb

import (
	"path/filepath"
	"testing"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// schemas mirrors the CREATE TABLE statements applied by main.go at startup.
var schemas = []string{
	models.SchemaServer,
	models.SchemaKey,
	models.SchemaCerts,
	models.SchemaCA,
	models.SchemaCrlInfoSubCA,
	models.SchemaCrlInfoRootCA,
	models.SchemaCRL,
	models.SchemaSSHKey,
	models.UsersData,
	models.SchemaEntity,
	models.SchemaEntityCA,
	models.SchemaCAExt,
	models.SchemaOID,
	models.SchemaUserCerts,
	models.SchemaAPIKey,
	models.SchemaESTUser,
	models.SchemaESTCerts,
}

// New creates a fresh SQLite database file under t.TempDir(), applies the full
// TLSS schema and returns both an open connection and the file path (needed by
// code such as middleware.APIKeyAuth that opens its own connection via
// viper.GetString("database.path") instead of taking a *sqlx.DB parameter).
//
// The connection is closed automatically via t.Cleanup.
func New(t *testing.T) (db *sqlx.DB, path string) {
	t.Helper()

	path = filepath.Join(t.TempDir(), "tlss-test.db")
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("testdb: failed to open %s: %v", path, err)
	}
	t.Cleanup(func() { db.Close() })

	for _, schema := range schemas {
		if _, err := db.Exec(schema); err != nil {
			t.Fatalf("testdb: failed to apply schema: %v\n%s", err, schema)
		}
	}

	return db, path
}
