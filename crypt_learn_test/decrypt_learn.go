package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Load RSA private key
func loadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Invalid private key format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Decrypt AES key with RSA
func decryptAESKey(encryptedAESKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedAESKey)
}

// Decrypt file using AES-256-GCM
func decryptFile(encryptedFile, decryptedFile string, aesKey []byte) error {
	encData, err := ioutil.ReadFile(encryptedFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	nonce := encData[:12]
	ciphertext := encData[12:]

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(decryptedFile, plaintext, 0644)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run decrypt.go <encrypted_file>")
		return
	}
	encryptedFile := os.Args[1]
	keyFile := strings.TrimSuffix(encryptedFile, ".enc") + ".key.enc"
	decryptedFile := "decrypted_" + strings.TrimSuffix(encryptedFile, ".enc")

	// Load RSA private key
	privateKey, err := loadRSAPrivateKey("private.pem")
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	// Load and decrypt AES key
	encryptedAESKey, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Println("Error reading encrypted AES key:", err)
		return
	}

	aesKey, err := decryptAESKey(encryptedAESKey, privateKey)
	if err != nil {
		fmt.Println("Error decrypting AES key:", err)
		return
	}

	// Decrypt file
	err = decryptFile(encryptedFile, decryptedFile, aesKey)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}

	fmt.Println("File decrypted:", decryptedFile)
}