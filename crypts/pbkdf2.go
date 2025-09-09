package crypts

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	KeySize    = 32     // Размер ключа в байтах (AES-256)
	Iterations = 100000 // Количество итераций PBKDF2
)

type PWD struct {
	GlobalSalt []byte
	PWDKey     []byte
}

var PWDKey = PWD{}

func (p *PWD) CreatePWDKeyFromUserInput(password, userSalt []byte) []byte {
	PWDKey.GlobalSalt = userSalt
	p.PWDKey = pbkdf2.Key(password, userSalt, Iterations, KeySize, sha256.New)
	return p.PWDKey
}
