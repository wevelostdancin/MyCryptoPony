# 🦄 MyCryptoPony

A friendly terminal UI (TUI) that wraps three powerful cryptography CLI tools — [`age`](https://github.com/FiloSottile/age), [`GnuPG`](https://gnupg.org/), and [`croc`](https://github.com/schollz/croc) — into a single, easy-to-use menu. No more memorizing flags.

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

- **age encryption & decryption** — via passphrase or public key
- **GPG signing & verification** — detached ASCII-armored signatures
- **croc file transfer** — send files/folders and get a human-readable code phrase
- **Built-in file browser** — modal directory tree picker, no need to type paths manually
- **Non-blocking UI** — all heavy operations run in background threads, keeping the interface responsive

## 📦 Requirements

### System dependencies (install via Homebrew on macOS)

```bash
brew install age gnupg croc
```

### Python dependencies

```bash
pip install textual pexpect
```

Python **3.10+** is required.

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/MyCryptoPony.git
cd MyCryptoPony
pip install -r requirements.txt
chmod +x crypto_tui.py
```

## 💻 Usage

```bash
./crypto_tui.py
```

You will see the main menu:

```
🔐 Crypto Helper
[📁 Encrypt file (age)]
[🔓 Decrypt file (age)]
[✍️ Sign file (GPG)]
[✅ Verify signature (GPG)]
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

## 🏗️ Project structure

```
MyCryptoPony/
├── crypto_tui.py       # Main application
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## ⚙️ How it works

- **Passphrase-based age encryption** uses `pexpect` to drive the interactive `age -p` prompt in a background thread. The passphrase never touches the command line (no `ps aux` leaks).
- **Key-based age encryption** calls `age` directly with `--recipient` / `--identity`.
- **GPG operations** rely on your existing `gpg-agent` setup. On macOS with Homebrew's `gnupg`, the default `pinentry-mac` GUI dialog is used for key passphrases.
- **croc integration** parses the `Code is: <phrase>` line from `croc send` output and shows only the phrase to the user.

## 🤝 Contributing

Issues and pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [age](https://github.com/FiloSottile/age) by Filippo Valsorda
- [GnuPG](https://gnupg.org/)
- [croc](https://github.com/schollz/croc) by Zack Scholl
- [Textual](https://github.com/Textualize/textual) by Textualize
