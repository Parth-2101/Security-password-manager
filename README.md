# 🔐 Secure Password Manager (Tkinter, AES, PBKDF2, Fernet)

A desktop password manager with a clean Tkinter UI, **AES-encrypted JSON storage**, and **PBKDF2 key derivation**.  
No external files needed — an encrypted vault (`passwords.json.enc`) is created on first run.  
(Optional logo: `file.png.jpeg` in the same folder.)

---

## 📦 Project Structure

| File | Description |
|:-----|:------------|
| `password_manager.py` | Main Tkinter app (UI + crypto + storage). |
| `passwords.json.enc`  | Encrypted vault (auto-created after first login). |
| `file.png.jpeg`       | Optional logo shown on the login screen. |

> Your script already bundles everything; no extra data files are required.

---

## ✨ Features

- **Master password** lock with **PBKDF2 (SHA-256, 100k rounds)** → derives a 32-byte key.
- **AES encryption via Fernet** (symmetric, authenticated) for the entire JSON vault.
- **Add / View / Copy / Delete** credentials from a scrollable list.
- **Search** by website or username (live filter).
- **Show/Hide** password toggles.
- **Password generator** with live **strength meter** (weak → very strong).
- **Consistent theming** and button hover states.

---

## 🔐 Security Design

- **Vault file:** `passwords.json.enc`  
  - First **16 bytes**: randomly generated **salt**.  
  - Remaining bytes: **Fernet ciphertext** of the JSON payload.
- **Key derivation:** `PBKDF2(master_password, salt, dkLen=32, count=100_000, HMAC=SHA256)` → base64-url key for Fernet.
- **Decryption path:** reads salt → derives key → decrypts JSON → loads credentials.

> If the master password is wrong or the file is corrupted, the app shows an error and **refuses to decrypt**.

---

## 🧰 Requirements

```bash
pip install pillow cryptography pycryptodome pyperclip
