package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// Generate RSA keys
func generateRSAKeys(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Encrypt AES key with RSA
func encryptAESKey(aesKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
}

// Encrypt file using AES-256-GCM
func encryptFile(inputFile, outputFile string, aesKey []byte) ([]byte, error) {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Save encrypted file
	err = ioutil.WriteFile(outputFile, append(nonce, ciphertext...), 0644)
	if err != nil {
		return nil, err
	}

	return aesKey, nil
}

// Save RSA keys
func saveRSAKeys(privateKey *rsa.PrivateKey) error {
	privFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer privFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	pem.Encode(privFile, privPEM)

	pubFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pem.Encode(pubFile, pubPEM)

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run encrypt.go <file>")
		return
	}
	inputFile := os.Args[1]
	outputFile := inputFile + ".enc"
	keyFile := inputFile + ".key.enc"

	// Generate RSA keys (2048 bits)
	privateKey, err := generateRSAKeys(2048)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		return
	}

	// Save RSA keys
	err = saveRSAKeys(privateKey)
	if err != nil {
		fmt.Println("Error saving RSA keys:", err)
		return
	}

	// Generate AES-256 key
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Encrypt file with AES-256
	_, err = encryptFile(inputFile, outputFile, aesKey)
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	// Encrypt AES key with RSA
	encryptedAESKey, err := encryptAESKey(aesKey, &privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting AES key:", err)
		return
	}

	// Save encrypted AES key
	err = ioutil.WriteFile(keyFile, encryptedAESKey, 0644)
	if err != nil {
		fmt.Println("Error saving encrypted AES key:", err)
		return
	}

	fmt.Println("File encrypted:", outputFile)
	fmt.Println("Encrypted AES key saved:", keyFile)
	fmt.Println("RSA keys saved as private.pem and public.pem")
}