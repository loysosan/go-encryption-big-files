package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// DecryptWork represents decryption work for a goroutine
type DecryptWork struct {
	data       []byte
	nonce      []byte
	index      int
	isEncrypted bool
	result     []byte
	err        error
}

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

// Optimized stream decrypt with multithreading
func decryptFileStream(inputFile, outputFile string, aesKey []byte) error {
	// Open with buffered I/O
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()
	
	reader := bufio.NewReaderSize(inFile, 8*1024*1024) // 8MB buffer

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()
	
	writer := bufio.NewWriterSize(outFile, 8*1024*1024) // 8MB buffer
	defer writer.Flush()

	// Read metadata header
	header := make([]byte, 17)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("error reading header: %v", err)
	}
	
	totalSize := binary.BigEndian.Uint64(header[0:8])
	encryptedSize := binary.BigEndian.Uint64(header[8:16])
	encryptionPercentage := float64(header[16])
	
	fmt.Printf("📊 Original file size: %d bytes\n", totalSize)
	fmt.Printf("🔒 Encrypted portion: %.1f%% (%d bytes)\n", encryptionPercentage, encryptedSize)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Setup worker pool for decryption
	numWorkers := runtime.NumCPU()
	workChan := make(chan *DecryptWork, numWorkers*2)
	resultChan := make(chan *DecryptWork, numWorkers*2)
	
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				if work.isEncrypted {
					// Decrypt chunk
					work.result, work.err = aesGCM.Open(nil, work.nonce, work.data, nil)
				} else {
					// Just copy plaintext
					work.result = make([]byte, len(work.data))
					copy(work.result, work.data)
				}
				resultChan <- work
			}
		}()
	}

	// Start result writer goroutine
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	resultMap := make(map[int]*DecryptWork)
	nextIndex := 0
	
	go func() {
		defer writerWg.Done()
		for work := range resultChan {
			if work.err != nil {
				fmt.Printf("Error decrypting chunk %d: %v\n", work.index, work.err)
				continue
			}
			
			resultMap[work.index] = work
			
			// Write results in order
			for {
				if result, exists := resultMap[nextIndex]; exists {
					writer.Write(result.result)
					delete(resultMap, nextIndex)
					nextIndex++
				} else {
					break
				}
			}
		}
	}()

	// Read and decrypt file chunk by chunk
	chunkIndex := 0
	for {
		// Read chunk type marker
		chunkType := make([]byte, 1)
		_, err := io.ReadFull(reader, chunkType)
		if err != nil {
			if err == io.EOF {
				break
			}
			close(workChan)
			return err
		}

		work := &DecryptWork{
			index:       chunkIndex,
			isEncrypted: chunkType[0] == 1,
		}

		if work.isEncrypted {
			// Read nonce
			work.nonce = make([]byte, 12)
			if _, err := io.ReadFull(reader, work.nonce); err != nil {
				close(workChan)
				return err
			}

			// Read encrypted chunk length
			lenBytes := make([]byte, 4)
			if _, err := io.ReadFull(reader, lenBytes); err != nil {
				close(workChan)
				return err
			}
			ciphertextLen := binary.BigEndian.Uint32(lenBytes)

			// Read encrypted chunk
			work.data = make([]byte, ciphertextLen)
			if _, err := io.ReadFull(reader, work.data); err != nil {
				close(workChan)
				return err
			}
		} else {
			// Read plaintext length
			lenBytes := make([]byte, 4)
			if _, err := io.ReadFull(reader, lenBytes); err != nil {
				close(workChan)
				return err
			}
			plaintextLen := binary.BigEndian.Uint32(lenBytes)

			// Read plaintext chunk
			work.data = make([]byte, plaintextLen)
			if _, err := io.ReadFull(reader, work.data); err != nil {
				close(workChan)
				return err
			}
		}

		workChan <- work
		chunkIndex++
	}

	// Close work channel and wait for workers
	close(workChan)
	wg.Wait()
	
	// Close result channel and wait for writer
	close(resultChan)
	writerWg.Wait()

	fmt.Printf("✅ File successfully decrypted: %s\n", outputFile)
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
