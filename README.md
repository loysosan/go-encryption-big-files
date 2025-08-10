# GoSecureFileEncryptor

GoSecureFileEncryptor is a high-performance file encryption tool written in Go, designed to encrypt large files efficiently using AES-256-GCM for encryption and RSA-2048 for key protection. This project supports **streaming encryption** and **partial encryption**, allowing you to encrypt only a specified percentage of the file while maintaining security.

## 🚀 Features
- **AES-256-GCM (ENC2)** – Secure streaming encryption with authentication tag for each chunk.
- **AES-256-CTR (ENC2I, in-place)** – Very fast striped encryption *in-place* without increasing file size (IV for each encrypted block).
- **RSA-2048 Key Protection** – AES key is encrypted with RSA and stored alongside (`*.key.enc`).
- **Streaming Encryption** – Works with large files without memory overflow (`*.enc` container).
- **Partial / Striped Encryption** – Encrypts `round(P)` blocks out of every 100 (block=64KB) throughout the file.
- **Multi-platform** – Linux, macOS, Windows.
- **Fast & Secure** – Fast AES with hardware acceleration; GCM provides authenticity, CTR does not (see warning below).

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

### 🔐 Encrypt a file — streaming container (ENC2, AES-GCM)
```sh
go run crypt_multithreading.go <filename> [percentage]
```
Examples:
```sh
# Full encryption (100%)
go run crypt_multithreading.go large_file.bin

# Partial striped encryption (30% of blocks)
go run crypt_multithreading.go large_file.bin 30
```
Outputs:
- `large_file.bin.enc` — container with data (encrypted/plaintext chunks + metadata)
- `large_file.bin.key.enc` — encrypted AES key (RSA)
- `private.pem`, `public.pem`

### 🔐 Encrypt a file — **in-place** (ENC2I, AES-CTR)
```sh
go run crypt_multithreading.go <filename> <percentage> --inplace
```
Example:
```sh
go run crypt_multithreading.go large_file.bin 10 --inplace
```
What happens:
- Only selected blocks are encrypted **inside** the file itself (block=64KB, period=100).
- A map `large_file.bin.encmap` with IVs is created (16 bytes per each encrypted block).
- Generates `large_file.bin.key.enc` + RSA keys.

### 🔓 Decrypt a file
**Streaming container (ENC2):**
```sh
go run decrypt_multithreading.go large_file.bin.enc large_file.bin.key.enc
```
**In-place (ENC2I):**
```sh
go run decrypt_multithreading.go large_file.bin large_file.bin.key.enc
```
(The decryptor automatically detects `large_file.bin.encmap` and rolls back blocks in place.)

---

## 🛠 How It Works

### **ENC2 (Streaming, AES-GCM)**
1. Generates a random AES-256 key.
2. File is read as a stream; a striped pattern is determined (100-block window, block=64KB).
3. Selected blocks are encrypted with AES-GCM (unique 12-byte nonce per chunk); others are written as plaintext chunks.
4. Writes `ENC2` header with parameters (totalSize, pct*100, chunkSize, period, encryptBlocks).
5. AES key is encrypted with RSA-2048 and stored separately (`*.key.enc`).

### **ENC2I (In-place, AES-CTR)**
1. Generates AES-256 key; file is opened with `O_RDWR`.
2. According to the striped pattern, only selected blocks are encrypted **in-place** using AES-CTR (file size does not change).
3. Writes `ENC2I` header and **sequence of IVs** (one per each encrypted block) into `*.encmap`.
4. During decryption, the same pattern and IV list are applied to restore bytes in place.

---

### **File Formats**
- **ENC2 (streaming container, AES-GCM):**
  - Header (23 bytes): `"ENC2" | ver | totalSize | pct*100 (u16) | chunkSize (u32) | period (u16) | encryptBlocks (u16)`
  - Stream of chunks: each chunk has a marker (1=enc, 0=plain), for enc also `nonce(12)` + `len(u32)` + `ciphertext`.
- **ENC2I (in-place map, AES-CTR):**
  - Header (30 bytes): `"ENC2I" | ver | totalSize | chunkSize | period | encryptBlocks | countEncrypted`
  - Then — sequence of `IV`s sized 16 bytes **only** for encrypted blocks in file order.

---

## ⚡ Performance Notes

- In streaming mode (ENC2) the program still **reads and writes the entire file**, so the bottleneck is **I/O**, not AES. Because of this, 10% vs 100% gives a small difference.
- In **in-place** mode (ENC2I) only encrypted blocks are written — at 10% the write volume ≈10% of file size → time difference is noticeable.
- Tip for accurate measurements: measure time **after** `Flush()+fsync()`, run tests on a "cold" cache, use `hyperfine`.

---

## 📜 License
This project is licensed under the MIT License.

---

## 🤝 Contributing
Contributions are welcome! Feel free to submit issues or pull requests.

---

## 🔒 Security Warning
**This tool is for educational purposes only.**
- ENC2 mode (AES-GCM) provides authenticity for encrypted chunks but does not cover plaintext ones — add an external MAC for the entire container if needed.
- ENC2I mode (AES-CTR) **does not provide authenticity/integrity**. Use with caution, make backups before in-place operations.
- Follow legal regulations and security policies.

