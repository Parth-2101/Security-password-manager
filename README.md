
# Secure Password Manager (Tkinter, AES, PBKDF2, Fernet)

## What This Implements
A desktop password manager built in Python with a Tkinter UI that:
- Locks the vault with a master password using PBKDF2 (SHA-256, 100k iterations).
- Encrypts all credential data with Fernet (AES + HMAC) into a single file (`passwords.json.enc`).
- Provides add/view/copy/delete, search, and show/hide actions for credentials.
- Includes a password generator with a live strength meter.

## Project Highlights
- Self-contained application; the encrypted vault file is created on first run.
- Key derivation via PBKDF2; distinct random salt stored at the start of the vault file.
- Full-vault encryption using Fernet; decryption fails safely on wrong password or corruption.
- Consistent theming and hover states; responsive search and scrollable list view.
- Live password strength scoring (length, classes) with a six-segment visual bar.

## Architecture and Workflow

### Security Path
1. User enters master password.
2. On first run, a random 16-byte salt is generated; otherwise read salt from the vault.
3. Derive a 32-byte key with PBKDF2 (SHA-256, 100,000 iterations) and base64-encode for Fernet.
4. Encrypt/decrypt the JSON payload with Fernet; the vault is `salt || ciphertext`.

### Data Model
- In-memory structure: `{ website: { "username": "...", "password": "..." }, ... }`.
- On save, the entire structure is serialized to JSON and re-encrypted atomically.

### UI Flow
1. Login screen (master password, show/hide toggle, optional logo).
2. Vault screen with search bar, scrollable credential list, and actions:
   - Show/Hide password, Copy to clipboard, Delete entry.
   - Generate Password window with strength label; save directly into vault.
3. Add Password form with live strength meter; save triggers full-vault re-encryption.

### Password Strength Heuristics
- Score from 0 to 6: length thresholds (8, 12) and presence of lowercase, uppercase, digits, symbols.
- Labels: Weak, Medium, Strong, Very Strong; mapped to six visual segments.

## Results
- The application maintains an encrypted, single-file vault that can only be opened with the correct master password.
- Typical user actions (add, search, show/hide, copy, delete) are persisted immediately via authenticated encryption.
- Generated passwords are assessed in real time; stronger suggestions are encouraged through the UI.
- The system fails closed on incorrect credentials or tampering, avoiding partial or insecure reads of sensitive data.
