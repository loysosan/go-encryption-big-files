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
)

// Генерация RSA-ключей
func generateRSAKeys(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Шифрование AES-ключа с помощью RSA
func encryptAESKey(aesKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
}

// Потоковое шифрование файла с использованием AES-256-GCM
func encryptFileStream(inputFile, outputFile string, aesKey []byte) error {
	// Открываем входной файл
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Создаем выходной файл
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Генерируем случайный nonce (12 байт для AES-GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Записываем nonce в начало выходного файла
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	// Создаем AES-GCM шифр
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Читаем файл и шифруем его частями
	buffer := make([]byte, 1024*1024) // 1 МБ блоки
	for {
		n, err := inFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		// Шифруем блок
		ciphertext := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		// Записываем зашифрованный блок в выходной файл
		if _, err := outFile.Write(ciphertext); err != nil {
			return err
		}
	}

	fmt.Println("Файл успешно зашифрован:", outputFile)
	return nil
}

// Сохранение RSA-ключей в файлы
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
		fmt.Println("Использование: go run encrypt.go <файл>")
		return
	}
	inputFile := os.Args[1]
	outputFile := inputFile + ".enc"
	keyFile := inputFile + ".key.enc"

	// 1️⃣ Генерация RSA-ключей (2048 бит)
	privateKey, err := generateRSAKeys(2048)
	if err != nil {
		fmt.Println("Ошибка генерации RSA-ключей:", err)
		return
	}

	// Сохранение RSA-ключей
	err = saveRSAKeys(privateKey)
	if err != nil {
		fmt.Println("Ошибка сохранения RSA-ключей:", err)
		return
	}

	// 2️⃣ Генерация AES-256 ключа (32 байта)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Ошибка генерации AES-ключа:", err)
		return
	}

	// 3️⃣ Шифрование файла потоковым методом
	err = encryptFileStream(inputFile, outputFile, aesKey)
	if err != nil {
		fmt.Println("Ошибка шифрования файла:", err)
		return
	}

	// 4️⃣ Шифрование AES-ключа RSA-ключом
	encryptedAESKey, err := encryptAESKey(aesKey, &privateKey.PublicKey)
	if err != nil {
		fmt.Println("Ошибка шифрования AES-ключа:", err)
		return
	}

	// 5️⃣ Сохранение зашифрованного AES-ключа
	err = os.WriteFile(keyFile, encryptedAESKey, 0644)
	if err != nil {
		fmt.Println("Ошибка сохранения зашифрованного AES-ключа:", err)
		return
	}

	fmt.Println("Файл зашифрован:", outputFile)
	fmt.Println("Зашифрованный AES-ключ сохранен:", keyFile)
	fmt.Println("RSA-ключи сохранены в private.pem и public.pem")
}