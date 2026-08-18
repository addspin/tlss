package estControllers

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"go.mozilla.org/pkcs7"
)

// SimpleReenroll обрабатывает POST /.well-known/est/simplereenroll (RFC 7030).
// Аутентификация через mTLS — клиент предъявляет ранее выпущенный сертификат.
// После успешной выдачи нового сертификата старый отзывается.
func SimpleReenroll(c fiber.Ctx) error {
	oldCert, ok := c.Locals("est_cert").(models.ESTCert)
	if !ok {
		return c.Status(401).SendString("Unauthorized")
	}

	csrDER, err := decodeCSRBody(c.Body())
	if err != nil {
		slog.Error("EST SimpleReenroll: CSR decode error", "error", err)
		return c.Status(400).SendString("Invalid CSR: " + err.Error())
	}

	// RFC 7030 §4.2.2: Subject и SubjectAltName в запросе обязаны совпадать
	// с соответствующими полями обновляемого сертификата. Клиент предъявил его
	// по mTLS, поэтому сравнение возможно. Без этой проверки владелец любого
	// действующего сертификата смог бы выпустить сертификат на чужое имя.
	clientCert, ok := c.Locals("est_client_cert").(*x509.Certificate)
	if !ok {
		slog.Error("EST SimpleReenroll: client certificate is missing in context")
		return c.Status(401).SendString("Client certificate required")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		slog.Error("EST SimpleReenroll: cannot parse CSR", "error", err)
		return c.Status(400).SendString("Invalid CSR")
	}
	if err := checkIdentityUnchanged(csr, clientCert); err != nil {
		slog.Warn("EST SimpleReenroll: identity mismatch",
			"cn", clientCert.Subject.CommonName,
			"serial", oldCert.SerialNumber,
			"reason", err)
		return c.Status(403).SendString("Subject and SubjectAltName must match the certificate being renewed")
	}

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("EST SimpleReenroll: database error", "error", err)
		return c.Status(503).SendString("Service unavailable")
	}
	defer db.Close()

	if oldCert.TTL <= 0 {
		return c.Status(500).SendString("Invalid TTL in previous certificate")
	}

	certDER, err := crypts.SignCSR(csrDER, db, oldCert.SigningCAId, oldCert.TTL)
	if err != nil {
		slog.Error("EST SimpleReenroll: signing error", "error", err)
		return c.Status(400).SendString(err.Error())
	}

	// Сохраняем новый сертификат
	if err := saveESTCert(db, oldCert.ESTUserId, oldCert.SigningCAId, oldCert.TTL, certDER); err != nil {
		slog.Error("EST SimpleReenroll: save cert error", "error", err)
		return c.Status(500).SendString("Failed to save certificate")
	}

	// Отзываем старый сертификат
	now := time.Now().Format(time.RFC3339)
	_, err = db.Exec(`UPDATE est_certs SET cert_status = 2, data_revoke = ?, reason_revoke = ?
		WHERE id = ?`, now, "superseded", oldCert.Id)
	if err != nil {
		slog.Error("EST SimpleReenroll: failed to revoke old cert", "error", err, "id", oldCert.Id)
	}

	p7der, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		slog.Error("EST SimpleReenroll: pkcs7 error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	slog.Info("EST SimpleReenroll: certificate renewed",
		"old_serial", oldCert.SerialNumber, "cn", oldCert.CommonName)
	c.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	c.Set("Content-Transfer-Encoding", "base64")
	return c.SendString(base64.StdEncoding.EncodeToString(p7der))
}

// checkIdentityUnchanged сверяет Subject и SubjectAltName из CSR с обновляемым
// сертификатом (RFC 7030 §4.2.2). Subject сравнивается побайтово по DER, SAN -
// как множества, поэтому порядок значений роли не играет.
//
// Атрибут ChangeSubjectName (RFC 6402), которым клиент мог бы запросить смену
// имени, не поддерживается: любое расхождение считается ошибкой.
func checkIdentityUnchanged(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	if !bytes.Equal(csr.RawSubject, cert.RawSubject) {
		return fmt.Errorf("subject changed: %q -> %q", cert.Subject.String(), csr.Subject.String())
	}
	if err := sameStrings("DNS names", csr.DNSNames, cert.DNSNames); err != nil {
		return err
	}
	if err := sameStrings("email addresses", csr.EmailAddresses, cert.EmailAddresses); err != nil {
		return err
	}
	if err := sameStrings("IP addresses", ipsToStrings(csr.IPAddresses), ipsToStrings(cert.IPAddresses)); err != nil {
		return err
	}
	if err := sameStrings("URIs", urisToStrings(csr.URIs), urisToStrings(cert.URIs)); err != nil {
		return err
	}
	return nil
}

// sameStrings сравнивает два набора значений SAN без учёта порядка
func sameStrings(label string, got, want []string) error {
	if len(got) != len(want) {
		return fmt.Errorf("%s count changed: %d -> %d", label, len(want), len(got))
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	for i := range g {
		if g[i] != w[i] {
			return fmt.Errorf("%s changed: %q -> %q", label, w[i], g[i])
		}
	}
	return nil
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func urisToStrings(uris []*url.URL) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}
