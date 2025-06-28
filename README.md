# GoSecureFileEncryptor

GoSecureFileEncryptor is a high-performance file encryption tool written in Go, designed to encrypt large files efficiently using AES-256-GCM for encryption and RSA-2048 for key protection. This project supports **streaming encryption** and **partial encryption**, allowing you to encrypt only a specified percentage of the file while maintaining security.

## 🚀 Features
- **AES-256-GCM Encryption** – Secure encryption with authentication tag protection.
- **RSA-2048 Key Protection** – Encrypts the AES key using RSA.
- **Streaming Encryption** – Encrypts large files **without memory overload**.
- **Partial Encryption** – Option to encrypt only a specified percentage of the file.
- **Multi-platform** – Works on Linux, macOS, and Windows.
- **Fast & Secure** – Uses strong cryptographic libraries.

---

## 🔧 Installation

Make sure you have Go installed on your system. If not, install it from [Go's official website](https://golang.org/dl/).

```sh
git clone https://github.com/yourusername/GoSecureFileEncryptor.git
cd GoSecureFileEncryptor
go mod init GoSecureFileEncryptor
go mod tidy
```

---

## 📌 Usage

### 🔐 Encrypt a file (Full encryption)
```sh
go run crypt_multithreading.go <filename>
```
Example:
```sh
go run crypt_multithreading.go large_file.bin
```

### 🔐 Encrypt a file (Partial encryption)
```sh
go run crypt_multithreading.go <filename> <percentage>
```
Example:
```sh
go run crypt_multithreading.go large_file.bin 30
```
This will encrypt only 30% of the file content.

### 🔓 Decrypt a file
```sh
go run decrypt_multithreading.go <encrypted_filename> <encrypted_key_file>
```
Example:
```sh
go run decrypt_multithreading.go large_file.bin.enc large_file.bin.key.enc
```
This will generate:
- `decrypted_large_file.bin` – The original decrypted file.

---

## 🛠 How It Works

### **Encryption Process:**
1. **Generates a random AES-256 key (32 bytes).**
2. **Reads the file and determines which chunks to encrypt** (based on percentage if specified).
3. **Uses AES-GCM to encrypt selected chunks**, leaving others as plaintext.
4. **Writes metadata header** with file size info and encryption percentage.
5. **Encrypts the AES key using RSA-2048.**
6. **Saves the encrypted file and encrypted AES key separately.**

### **Decryption Process:**
1. **Reads metadata header** to understand file structure and encryption percentage.
2. **Decrypts the AES key using the RSA private key.**
3. **Processes each chunk** - decrypts encrypted chunks and copies plaintext chunks.
4. **Restores the original file.**

### **File Format:**
- **Header (17 bytes):** Original size (8) + Encrypted size (8) + Encryption percentage (1)
- **Chunks:** Each chunk has a type marker (1=encrypted, 0=plaintext) followed by the data

---

## ⚡ Performance Notes

**Why partial encryption doesn't significantly improve performance:**
- The program still **reads the entire file** during processing
- Main bottleneck is **I/O operations** (disk read/write), not encryption
- Encryption speed is much faster than disk I/O for modern CPUs
- Partial encryption is useful for **reducing encrypted data size**, not processing time

**Performance example (3.5GB file):**
- Full encryption (100%): ~6.8 seconds
- Partial encryption (30%): ~8.7 seconds
- The slight difference is due to additional metadata processing

---

## 📜 License
This project is licensed under the MIT License.

---

## 🤝 Contributing
Contributions are welcome! Feel free to submit issues or pull requests.

---

## 🔒 Security Warning
**This tool is for educational purposes only.** Do not use it for illegal activities. Always ensure that encryption methods comply with your local laws.

