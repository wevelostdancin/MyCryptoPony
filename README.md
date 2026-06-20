# 🦄 MyCryptoPony

<p align="center">
  <img src="logo/logo.PNG" alt="Логотип MyCryptoPony" width="200">
</p>

A friendly terminal UI (TUI) that wraps five powerful cryptography and privacy CLI tools — [`age`](https://github.com/FiloSottile/age), [`minisign`](https://jedisct1.github.io/minisign/), [`mat2`](https://0xacab.org/jvoisin/mat2), [`rhash`](https://github.com/rhash/RHash), and [`croc`](https://github.com/schollz/croc) — into a single, easy-to-use menu.

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

- **🔏 Age Encryption & Decryption**: Secure file encryption via passphrase or public key (non-blocking UI via `pexpect`).
- **✍️ Minisign Signing & Verification**: Cryptographic file signatures with default key path support (`~/.minisign/`).
- **🪄 Metadata Cleaning (mat2)**: Strips hidden metadata (GPS, author, EXIF) from PDFs and images, creating a safe `.cleaned` copy.
- **🔎 Hash Generation & Verification (rhash)**: Generates and verifies SHA-512 or BLAKE3 checksums, automatically saving them to standard `.algo` files.
- **📤 Secure File Transfer (croc)**: Send files/folders and instantly get a human-readable code phrase for the recipient.
- **📂 Built-in File Browser**: Modal directory tree picker starting from the root (`/`), allowing easy navigation to external drives (`/Volumes/`).

## 📦 Requirements

### System dependencies (install via Homebrew on macOS)

```bash
brew install age minisign mat2 rhash croc
```

### Python dependencies

```bash
pip install textual pexpect
```

Python **3.10+** is required.

## 🚀 Installation

```bash
git clone https://github.com/wevelostdancin/MyCryptoPony.git
cd MyCryptoPony
pip install -r requirements.txt
chmod +x mycryptopony.py
```

## 💻 Usage

```bash
./mycryptopony.py
```

You will see the main menu:

```
🦄 MyCryptoPony
[📁 Encrypt file (age)]
[🔓 Decrypt file (age)]
[✍️ Sign file (minisign)]
[✅ Verify signature (minisign)]
[🪄 Clean metadata (mat2)]
[🔎 Generate hash (rhash)]
[🔍 Verify hash (rhash)]
[📤 Send via croc]
[📥 Receive via croc]
[❌ Exit]
```

### Keyboard shortcuts

- `Tab` / `Shift+Tab` — navigate between widgets
- `Enter` — activate focused button or submit a form
- `Esc` — go back / close modal

### Generating an age keypair (for key-based encryption)

```bash
age-keygen -o key.txt          # creates a private key file
age-keygen -y key.txt          # prints the matching public key
```

Use the public key as the recipient when encrypting, and the `key.txt` file as the identity when decrypting.

### Generating a minisign keypair (for signing files)

If you plan to use the signing features, generate a keypair once. The app defaults to `~/.minisign/`:

```bash
# Generate a new keypair (you will be prompted for a passphrase)
minisign -G

# This creates:
# ~/.minisign/minisign.key  (Keep this secret!)
# ~/.minisign/minisign.pub   (Share this to verify your signatures)
```

## 🏗️ Project structure

```
MyCryptoPony/
├── mycryptopony.py       # Main application
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules (excludes .age, .minisig, etc.)
└── README.md           # This file
```

## ⚙️ How it works

- Non-blocking Passwords: `age` and `minisign` require interactive password prompts. MyCryptoPony uses `pexpect` in a background thread (`asyncio.to_thread`) to handle this securely without freezing the TUI or leaking passwords to process lists (`ps aux`).
- Safe Metadata Cleaning: `mat2` is invoked to create a `.cleaned` copy of the file, leaving the original untouched to prevent accidental data loss.
- Standardized Hashing: `rhash` is used with the `-o` flag to automatically generate standard checksum files (e.g., document.pdf.sha512), which can be immediately used by the "Verify hash" screen or standard CLI tools.
- External Drive Support: The file picker roots at `/`, ensuring you can navigate to `/Volumes/YourUSBDrive` on macOS without workarounds.

## 🤝 Contributing

Issues and pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [age](https://github.com/FiloSottile/age) by Filippo Valsorda
- [minisign](https://jedisct1.github.io/minisign/) by Frank Denis
- [mat2](https://github.com/tpet/mat2) by Julien Voisin
- [RHash](https://github.com/rhash/RHash) by Aleksey Kravchenko
- [croc](https://github.com/schollz/croc) by Zack Scholl
- [Textual](https://github.com/Textualize/textual) by Textualize
