package crypts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// const (
// 	key = "your_secret_key_here" // замените на свой секретный ключ
// )

type Aes struct {
	Key []byte // ключ шифрования
}

// создаем глобальну переменную для хранения расышированного ключа
var AesSecretKey = Aes{}

func (a *Aes) Encrypt(plaintext, key []byte) ([]byte, error) {
	return a.encrypt(plaintext, key)
}

func (a *Aes) Decrypt(ciphertext, key []byte) ([]byte, error) {
	return a.decrypt(ciphertext, key)
}

func (a *Aes) encrypt(plaintext, key []byte) ([]byte, error) {
	a.Key = key
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (a *Aes) decrypt(ciphertext, key []byte) ([]byte, error) {
	a.Key = key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
