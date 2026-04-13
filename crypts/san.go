package crypts

import (
	"net"
	"strings"
)

type SANResult struct {
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
}

func ParseSAN(primaryName, sanString, email string, wildcard bool) SANResult {
	var r SANResult

	// Основное имя
	if primaryName != "" {
		if ip := net.ParseIP(primaryName); ip != nil {
			r.IPAddresses = append(r.IPAddresses, ip)
		} else {
			r.DNSNames = append(r.DNSNames, primaryName)
			if wildcard {
				r.DNSNames = append(r.DNSNames, "*."+primaryName)
			}
		}
	}

	// Email из формы
	if email != "" && strings.Contains(email, "@") {
		r.EmailAddresses = append(r.EmailAddresses, email)
	}

	// Разбираем SAN строку
	if sanString == "" {
		return r
	}

	seen := make(map[string]bool)
	if primaryName != "" {
		seen[primaryName] = true
		seen["*."+primaryName] = true
	}
	if email != "" {
		seen[email] = true
	}

	for _, san := range strings.Split(sanString, ",") {
		san = strings.TrimSpace(san)
		if san == "" || seen[san] {
			continue
		}
		seen[san] = true

		if ip := net.ParseIP(san); ip != nil {
			r.IPAddresses = append(r.IPAddresses, ip)
		} else if strings.Contains(san, "@") {
			r.EmailAddresses = append(r.EmailAddresses, san)
		} else {
			r.DNSNames = append(r.DNSNames, san)
		}
	}

	return r
}
