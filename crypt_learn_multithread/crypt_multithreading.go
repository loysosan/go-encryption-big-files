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

// Generate RSA key pair
func generateRSAKeys(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Encrypt AES key using RSA public key
func encryptAESKey(aesKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	fmt.Printf("🔑 AES Key before encryption: %x\n", aesKey)
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
}

// Modified encryption method
func encryptFileStream(inputFile, outputFile string, aesKey []byte) error {
    // Open input file
    inFile, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer inFile.Close()

    // Create output file
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

    // Process file in chunks
    buffer := make([]byte, 1024*1024) // 1 MB chunks
    for {
        // Read file chunk
        n, err := inFile.Read(buffer)
        if err != nil && err != io.EOF {
            return err
        }
        if n == 0 {
            break
        }

        // Create a unique nonce for each chunk
        chunkNonce := make([]byte, 12)
        if _, err := io.ReadFull(rand.Reader, chunkNonce); err != nil {
            return err
        }

        // Encrypt chunk
        ciphertext := aesGCM.Seal(nil, chunkNonce, buffer[:n], nil)

        // Write nonce before encrypted chunk
        if _, err := outFile.Write(chunkNonce); err != nil {
            return err
        }
        
        // Write encrypted chunk length (4 bytes)
        lenBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(lenBytes, uint32(len(ciphertext)))
        if _, err := outFile.Write(lenBytes); err != nil {
            return err
        }

        // Write encrypted chunk to output file
        if _, err := outFile.Write(ciphertext); err != nil {
            return err
        }
    }

    fmt.Println("File successfully encrypted:", outputFile)
    return nil
}

// Save RSA keys to PEM files
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

// Increment nonce to make it unique per chunk
func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run encrypt.go <file>")
		return
	}
	inputFile := os.Args[1]
	outputFile := inputFile + ".enc"
	keyFile := inputFile + ".key.enc"

	// Generate RSA key pair (2048-bit)
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

	// Generate AES-256 key (32 bytes)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Encrypt file using streaming AES-GCM
	err = encryptFileStream(inputFile, outputFile, aesKey)
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	// Encrypt AES key with RSA public key
	encryptedAESKey, err := encryptAESKey(aesKey, &privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting AES key:", err)
		return
	}

	// Save encrypted AES key
	err = os.WriteFile(keyFile, encryptedAESKey, 0644)
	if err != nil {
		fmt.Println("Error saving encrypted AES key:", err)
		return
	}

	fmt.Println("Encrypted file:", outputFile)
	fmt.Println("Encrypted AES key saved:", keyFile)
	fmt.Println("RSA keys saved in private.pem and public.pem")
}
