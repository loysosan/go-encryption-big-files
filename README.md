# GoSecureFileEncryptor

GoSecureFileEncryptor is a high-performance file encryption tool written in Go, designed to encrypt large files efficiently using AES-256-GCM for encryption and RSA-2048 for key protection. This project supports **streaming encryption**, allowing encryption of files **without loading them entirely into memory**, making it suitable for large files (10GB, 100GB+).

## 🚀 Features
- **AES-256-GCM Encryption** – Secure encryption with authentication tag protection.
- **RSA-2048 Key Protection** – Encrypts the AES key using RSA.
- **Streaming Encryption** – Encrypts large files **without memory overload**.
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

### 🔐 Encrypt a file
```sh
go run encrypt.go <filename>
```
Example:
```sh
go run encrypt.go large_file.bin
```
This will generate:
- `large_file.bin.enc` – Encrypted file.
- `large_file.bin.key.enc` – Encrypted AES key.
- `private.pem` – RSA private key.
- `public.pem` – RSA public key.

### 🔓 Decrypt a file
```sh
go run decrypt.go <encrypted_filename>
```
Example:
```sh
go run decrypt.go large_file.bin.enc
```
This will generate:
- `decrypted_large_file.bin` – The original decrypted file.

---

## 🛠 How It Works

### **Encryption Process:**
1. **Generates a random AES-256 key (32 bytes).**
2. **Uses AES-GCM to encrypt the file in chunks** (1MB each).
3. **Writes a nonce (IV) at the start of the file** (needed for decryption).
4. **Encrypts the AES key using RSA-2048.**
5. **Saves the encrypted file and encrypted AES key separately.**

### **Decryption Process:**
1. **Reads the nonce (IV) from the encrypted file.**
2. **Decrypts the AES key using the RSA private key.**
3. **Decrypts the file in chunks using AES-GCM.**
4. **Restores the original file.**

---

## 📜 License
This project is licensed under the MIT License.

---

## 🤝 Contributing
Contributions are welcome! Feel free to submit issues or pull requests.

---

## 🔒 Security Warning
**This tool is for educational purposes only.** Do not use it for illegal activities. Always ensure that encryption methods comply with your local laws.

