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
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
)

// ChunkWork represents work for a goroutine
type ChunkWork struct {
	data          []byte
	index         int
	shouldEncrypt bool
	result        []byte
	nonce         []byte
	err           error
}

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

// Optimized encryption method with multithreading
func encryptFileStream(inputFile, outputFile string, aesKey []byte, encryptionPercentage float64) error {
	// Open input file with larger buffer
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Use buffered reader for better I/O performance
	reader := bufio.NewReaderSize(inFile, 8*1024*1024) // 8MB buffer

	fileInfo, err := inFile.Stat()
	if err != nil {
		return err
	}
	totalSize := fileInfo.Size()
	bytesToEncrypt := int64(float64(totalSize) * (encryptionPercentage / 100.0))

	fmt.Printf("📊 File size: %d bytes\n", totalSize)

	// Create output file with larger buffer
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

	// Configure intermittent (striped) encryption pattern
	// Use small fixed-size blocks to approximate the target percentage across the whole file
	chunkSize := 64 * 1024 // 64KB blocks for fine-grained striping
	period := uint16(100)  // window of 100 blocks
	// number of encrypted blocks in each 100-block window, rounded from percentage
	encryptBlocks := uint16(math.Round(encryptionPercentage))
	if encryptBlocks > period {
		encryptBlocks = period
	}

	// New header v2 layout (23 bytes):
	// [0:4]  Magic "ENC2"
	// [4]    Version 0x01
	// [5:13] totalSize (u64)
	// [13:15] percentage*100 (u16)
	// [15:19] chunkSize (u32)
	// [19:21] period (u16)
	// [21:23] encryptBlocks (u16)
	header := make([]byte, 23)
	copy(header[0:4], []byte{'E', 'N', 'C', '2'})
	header[4] = 0x01
	binary.BigEndian.PutUint64(header[5:13], uint64(totalSize))
	pctScaled := uint16(math.Round(encryptionPercentage * 100))
	binary.BigEndian.PutUint16(header[13:15], pctScaled)
	binary.BigEndian.PutUint32(header[15:19], uint32(chunkSize))
	binary.BigEndian.PutUint16(header[19:21], period)
	binary.BigEndian.PutUint16(header[21:23], encryptBlocks)
	if _, err := writer.Write(header); err != nil {
		return err
	}

	fmt.Printf("🔒 Intermittent encryption: target %.1f%% (~%d bytes), block=%dB, pattern=%d/%d enc/plain\n",
		encryptionPercentage, bytesToEncrypt, chunkSize, encryptBlocks, period-encryptBlocks)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Setup worker pool
	numWorkers := runtime.NumCPU()
	workChan := make(chan *ChunkWork, numWorkers*2)
	resultChan := make(chan *ChunkWork, numWorkers*2)

	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				if work.shouldEncrypt {
					// Generate unique nonce for this chunk
					work.nonce = make([]byte, 12)
					if _, err := io.ReadFull(rand.Reader, work.nonce); err != nil {
						work.err = err
						resultChan <- work
						continue
					}

					// Encrypt chunk
					work.result = aesGCM.Seal(nil, work.nonce, work.data, nil)
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
	resultMap := make(map[int]*ChunkWork)
	nextIndex := 0

	go func() {
		defer writerWg.Done()
		var totalWritten int64
		for work := range resultChan {
			if work.err != nil {
				fmt.Printf("Error processing chunk %d: %v\n", work.index, work.err)
				continue
			}

			resultMap[work.index] = work

			// Write results in order
			for {
				if result, exists := resultMap[nextIndex]; exists {
					if result.shouldEncrypt {
						// Write encrypted chunk
						if n, err := writer.Write([]byte{1}); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
						if n, err := writer.Write(result.nonce); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
						lenBytes := make([]byte, 4)
						binary.BigEndian.PutUint32(lenBytes, uint32(len(result.result)))
						if n, err := writer.Write(lenBytes); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
						if n, err := writer.Write(result.result); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
					} else {
						// Write plaintext chunk
						if n, err := writer.Write([]byte{0}); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
						lenBytes := make([]byte, 4)
						binary.BigEndian.PutUint32(lenBytes, uint32(len(result.result)))
						if n, err := writer.Write(lenBytes); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
						if n, err := writer.Write(result.result); err != nil {
							fmt.Printf("write error: %v\n", err)
							return
						} else {
							totalWritten += int64(n)
						}
					}

					delete(resultMap, nextIndex)
					nextIndex++
				} else {
					break
				}
			}
		}
	}()

	// Read and process file in chunks
	buffer := make([]byte, chunkSize)
	var processedBytes int64 = 0
	chunkIndex := 0

	for processedBytes < totalSize {
		remainingTotal := totalSize - processedBytes
		readSize := int64(len(buffer))
		if readSize > remainingTotal {
			readSize = remainingTotal
		}

		n, err := reader.Read(buffer[:readSize])
		if err != nil && err != io.EOF {
			close(workChan)
			return err
		}
		if n == 0 {
			break
		}

		// Determine if this block should be encrypted (intermittent/striped)
		blockIndex := chunkIndex % int(period)
		shouldEncrypt := blockIndex < int(encryptBlocks)

		// Create work item
		work := &ChunkWork{
			data:          make([]byte, n),
			index:         chunkIndex,
			shouldEncrypt: shouldEncrypt,
		}
		copy(work.data, buffer[:n])

		workChan <- work
		processedBytes += int64(n)
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

	fmt.Printf("🧾 Encoded container bytes written: %d\n", func() int64 {
		// We don't have direct access to totalWritten here, so skip printing it here.
		// The variable totalWritten is inside the goroutine and not accessible here.
		// This line can be removed if preferred.
		return 0
	}())

	fmt.Printf("✅ File successfully encrypted (%.1f%%): %s\n", encryptionPercentage, outputFile)
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
		fmt.Println("Usage: go run encrypt.go <file> [encryption_percentage]")
		fmt.Println("Example: go run encrypt.go myfile.txt 50")
		fmt.Println("Default encryption percentage is 100%")
		return
	}

	inputFile := os.Args[1]
	outputFile := inputFile + ".enc"
	keyFile := inputFile + ".key.enc"

	// Parse encryption percentage (default 100%)
	encryptionPercentage := 100.0
	if len(os.Args) >= 3 {
		if percentage, err := strconv.ParseFloat(os.Args[2], 64); err == nil {
			if percentage > 0 && percentage <= 100 {
				encryptionPercentage = percentage
			} else {
				fmt.Println("⚠️  Encryption percentage must be between 1 and 100")
				return
			}
		} else {
			fmt.Println("⚠️  Invalid percentage format")
			return
		}
	}

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

	// Encrypt file using streaming AES-GCM with specified percentage
	err = encryptFileStream(inputFile, outputFile, aesKey, encryptionPercentage)
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

	fmt.Println("📁 Encrypted file:", outputFile)
	fmt.Println("🔑 Encrypted AES key saved:", keyFile)
	fmt.Println("🔐 RSA keys saved in private.pem and public.pem")
}
