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
	"os"
	"encoding/binary"
)

// Increment nonce for each chunk
func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// Load RSA private key from file
func loadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privKeyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Decrypt AES key using RSA private key
func decryptAESKey(encryptedAESKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedAESKey)
}

// Stream decrypt file using AES-256-GCM
// Modified decryption method
func decryptFileStream(inputFile, outputFile string, aesKey []byte) error {
    // Open the encrypted input file
    inFile, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer inFile.Close()

    // Create the output file
    outFile, err := os.Create(outputFile)
    if err != nil {
        return err
    }
    defer outFile.Close()

    // Create AES-GCM cipher
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    // Read and decrypt file chunk by chunk
    for {
        // Read nonce (12 bytes)
        nonce := make([]byte, 12)
        _, err := io.ReadFull(inFile, nonce)
        if err != nil {
            if err == io.EOF {
                break
            }
            return err
        }

        // Read encrypted chunk length (4 bytes)
        lenBytes := make([]byte, 4)
        if _, err := io.ReadFull(inFile, lenBytes); err != nil {
            return err
        }
        ciphertextLen := binary.BigEndian.Uint32(lenBytes)

        // Read encrypted chunk
        ciphertext := make([]byte, ciphertextLen)
        if _, err := io.ReadFull(inFile, ciphertext); err != nil {
            return err
        }

        // Decrypt chunk
        plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
        if err != nil {
            return err
        }

        // Write decrypted data to output file
        if _, err := outFile.Write(plaintext); err != nil {
            return err
        }
    }

    fmt.Println("File successfully decrypted:", outputFile)
    return nil
}

// Main function to execute decryption
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run decrypt.go <encrypted_file> <encrypted_key_file>")
		return
	}

	encryptedFile := os.Args[1]
	encryptedKeyFile := os.Args[2]
	outputFile := encryptedFile + ".dec"

	// Load private RSA key
	privateKey, err := loadRSAPrivateKey("private.pem")
	if err != nil {
		fmt.Println("Error loading private RSA key:", err)
		return
	}

	// Read encrypted AES key
	encryptedAESKey, err := os.ReadFile(encryptedKeyFile)
	if err != nil {
		fmt.Println("Error reading encrypted AES key:", err)
		return
	}

	// Decrypt AES key using RSA private key
	aesKey, err := decryptAESKey(encryptedAESKey, privateKey)
	if err != nil {
		fmt.Println("Error decrypting AES key:", err)
		return
	}

	// Debugging AES key
	fmt.Printf("🔑 AES Key after decryption: %x\n", aesKey)

	// Decrypt file using AES-256-GCM in streaming mode
	err = decryptFileStream(encryptedFile, outputFile, aesKey)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}
}
