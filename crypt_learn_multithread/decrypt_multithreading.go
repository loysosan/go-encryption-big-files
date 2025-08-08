package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// DecryptWork represents decryption work for a goroutine
type DecryptWork struct {
	data        []byte
	nonce       []byte
	index       int
	isEncrypted bool
	result      []byte
	err         error
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
	defer func() {
		if err := writer.Flush(); err != nil {
			fmt.Printf("flush error: %v\n", err)
		}
	}()

	// Read metadata header (supports v2 with magic "ENC2" and legacy v1)
	var (
		totalSize            uint64
		encryptedSize        uint64
		encryptionPercentage float64
		chunkSize            uint32
		period               uint16
		encryptBlocks        uint16
	)

	// Peek first 5 bytes to detect v2 header
	prefix := make([]byte, 5)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return fmt.Errorf("error reading header prefix: %v", err)
	}

	if string(prefix[0:4]) == "ENC2" && prefix[4] == 0x01 {
		// v2 header, read remaining 18 bytes (total 23)
		rest := make([]byte, 18)
		if _, err := io.ReadFull(reader, rest); err != nil {
			return fmt.Errorf("error reading v2 header: %v", err)
		}
		// parse
		totalSize = binary.BigEndian.Uint64(rest[0:8])
		pctScaled := binary.BigEndian.Uint16(rest[8:10])
		encryptionPercentage = float64(pctScaled) / 100.0
		chunkSize = binary.BigEndian.Uint32(rest[10:14])
		period = binary.BigEndian.Uint16(rest[14:16])
		encryptBlocks = binary.BigEndian.Uint16(rest[16:18])
		// encryptedSize is approximate for v2; compute from pct
		encryptedSize = uint64(float64(totalSize) * (encryptionPercentage / 100.0))
		fmt.Printf("📊 Original file size: %d bytes\n", totalSize)
		fmt.Printf("🔒 Intermittent encryption: %.2f%% (~%d bytes), block=%dB, pattern=%d/%d enc/plain\n",
			encryptionPercentage, encryptedSize, chunkSize, encryptBlocks, period-encryptBlocks)
	} else {
		// legacy v1 header: we already consumed 5 bytes; we need remaining 12
		rest := make([]byte, 12)
		if _, err := io.ReadFull(reader, rest); err != nil {
			return fmt.Errorf("error reading legacy header: %v", err)
		}
		header := append(prefix, rest...)
		// parse legacy layout (17 bytes total)
		totalSize = binary.BigEndian.Uint64(header[0:8])
		encryptedSize = binary.BigEndian.Uint64(header[8:16])
		encryptionPercentage = float64(header[16])
		fmt.Printf("📊 Original file size: %d bytes\n", totalSize)
		fmt.Printf("🔒 Encrypted portion: %.1f%% (%d bytes)\n", encryptionPercentage, encryptedSize)
	}

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

	var totalWritten uint64

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
					if n, err := writer.Write(result.result); err != nil {
						fmt.Printf("write error: %v\n", err)
						return
					} else {
						totalWritten += uint64(n)
					}
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

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush error: %v", err)
	}
	if err := outFile.Sync(); err != nil {
		return fmt.Errorf("fsync error: %v", err)
	}

	if totalWritten != totalSize {
		return fmt.Errorf("size mismatch after decryption: wrote %d bytes, expected %d", totalWritten, totalSize)
	}

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
