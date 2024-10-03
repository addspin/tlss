// Зашифровываем сообщение
plaintext := []byte("Hello, World!")
ciphertext, err := encrypt(plaintext)
if err != nil {
	fmt.Println(err)
	return
}

// Расшифровываем сообщение
ciphertextBytes, err := hex.DecodeString(ciphertextHex)
if err != nil {
	fmt.Println(err)
	return
}

plaintext, err = decrypt(ciphertextBytes)
if err != nil {
	fmt.Println(err)
	return
}

fmt.Println(string(plaintext)) // Hello, World!