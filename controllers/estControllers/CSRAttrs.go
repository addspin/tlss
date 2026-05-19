package estControllers

import (
	"encoding/asn1"
	"encoding/base64"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

// CSRAttrs обрабатывает GET /.well-known/est/csrattrs.
//
// Режим выбирается через config.yaml estCSRAttrs.rfc9908:
//
//	true  → RFC 9908: id-aa-extensionReqTemplate + Extensions SEQUENCE в SET
//	false → RFC 7030: id-ExtensionReq + bare OID в SET
//
// Сервер принимает из CSR:
//   - Subject.CommonName  (OID 2.5.4.3)
//   - SubjectAltName ext  (OID 2.5.29.17) — DNS / IP / Email / URI
//
// Остальные расширения (KeyUsage, ExtKeyUsage, BasicConstraints)
// устанавливаются сервером и игнорируются из CSR.
func CSRAttrs(c fiber.Ctx) error {
	useRFC9908 := viper.GetBool("estCSRAttrs.rfc9908")

	var body []byte
	var err error

	if useRFC9908 {
		body, err = buildRFC9908()
	} else {
		body, err = buildRFC7030()
	}

	if err != nil {
		slog.Error("EST CSRAttrs: encoding error", "error", err, "rfc9908", useRFC9908)
		return c.Status(500).SendString("encoding error")
	}

	c.Set("Content-Type", "application/csrattrs")
	c.Set("Content-Transfer-Encoding", "base64")
	slog.Info("EST CSRAttrs: response served", "size", len(body), "rfc9908", useRFC9908)
	return c.SendString(base64.StdEncoding.EncodeToString(body))
}

// buildRFC7030 формирует CsrAttrs по RFC 7030 §4.5.2.
//
// Структура:
//
//	CsrAttrs SEQUENCE {
//	  OID 2.5.4.3                        ← commonName (AttrOrOID::=oid)
//	  Attribute SEQUENCE {               ← AttrOrOID::=attribute
//	    OID 1.2.840.113549.1.9.14        ← id-ExtensionReq
//	    SET { OID 2.5.29.17 }            ← subjectAltName bare OID
//	  }
//	}
func buildRFC7030() ([]byte, error) {
	oidCommonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	oidExtensionRequest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidSubjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}

	cnOID, err := asn1.Marshal(oidCommonName)
	if err != nil {
		return nil, err
	}
	extReqOID, err := asn1.Marshal(oidExtensionRequest)
	if err != nil {
		return nil, err
	}
	sanOID, err := asn1.Marshal(oidSubjectAltName)
	if err != nil {
		return nil, err
	}

	setBytes := tlv(0x31, sanOID)
	attrBytes := tlv(0x30, append(extReqOID, setBytes...))
	return tlv(0x30, append(cnOID, attrBytes...)), nil
}

// buildRFC9908 формирует CsrAttrs по RFC 9908 (hint-режим: extnValue заполняет клиент).
//
// Структура:
//
//	CsrAttrs SEQUENCE {
//	  OID 2.5.4.3                              ← commonName (AttrOrOID::=oid)
//	  Attribute SEQUENCE {                     ← AttrOrOID::=attribute
//	    OID 1.2.840.113549.1.9.16.2.62         ← id-aa-extensionReqTemplate
//	    SET {
//	      Extensions SEQUENCE {               ← SEQUENCE OF ExtensionTemplate
//	        ExtensionTemplate SEQUENCE {
//	          OID 2.5.29.17                   ← extnID = subjectAltName
//	          // critical: отсутствует (DEFAULT FALSE)
//	          // extnValue: отсутствует (OPTIONAL — клиент заполняет сам)
//	        }
//	      }
//	    }
//	  }
//	}
func buildRFC9908() ([]byte, error) {
	oidCommonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	// id-aa-extensionReqTemplate (RFC 9908 §4)
	oidExtReqTemplate := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 62}
	oidSubjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}

	cnOID, err := asn1.Marshal(oidCommonName)
	if err != nil {
		return nil, err
	}
	extReqTemplateOID, err := asn1.Marshal(oidExtReqTemplate)
	if err != nil {
		return nil, err
	}
	sanOID, err := asn1.Marshal(oidSubjectAltName)
	if err != nil {
		return nil, err
	}

	// ExtensionTemplate ::= SEQUENCE { extnID OID }
	extTemplate := tlv(0x30, sanOID)
	// Extensions ::= SEQUENCE OF ExtensionTemplate
	extensions := tlv(0x30, extTemplate)
	// SET { Extensions }
	setBytes := tlv(0x31, extensions)
	// Attribute ::= SEQUENCE { id-aa-extensionReqTemplate, SET { Extensions } }
	attrBytes := tlv(0x30, append(extReqTemplateOID, setBytes...))
	return tlv(0x30, append(cnOID, attrBytes...)), nil
}

// tlv формирует TLV (tag-length-value) с корректным BER/DER кодированием длины.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	l := len(content)
	switch {
	case l < 128:
		out = append(out, byte(l))
	case l < 256:
		out = append(out, 0x81, byte(l))
	default:
		out = append(out, 0x82, byte(l>>8), byte(l&0xff))
	}
	return append(out, content...)
}
