# 🖼️ Inkryptor — A CLI Steganography + Encryption Project

**Inkryptor** is a command-line tool that securely embeds encrypted passwords into image files using steganography.  
Built as a personal learning project, it demonstrates how cryptography and steganography can be combined to protect sensitive data in a simple, hands-on way.

---

## 🔍 Features

- 🔐 Encrypts passwords using a master key
- 🖼️ Hides encrypted passwords in PNG images using LSB steganography
- 🔓 Allows secure retrieval and decryption from stego images
- 📦 Lightweight, no external database or backend required

---

## 🎯 Project Purpose

This project was created purely for **learning and exploration** during a cybersecurity-focused development sprint.  
It’s not a commercial tool, but something that helped me understand:

- How encryption and key derivation work
- The logic of steganography using pixel manipulation
- CLI tool design in Python
- Safe password handling
  
---

## 🛠️ How It Works

1. **Encrypt**
   - Takes a password + master key
   - Encrypts the password using AES encryption

2. **Embed**
   - Encodes the encrypted bytes into the least significant bits (LSB) of image pixels
   - Saves a new PNG with the hidden data

3. **Extract**
   - Reads the modified image
   - Extracts and decrypts the original password using the master key

---
