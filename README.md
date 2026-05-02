# CredX Vault v1.9.2

A **Zero-Knowledge CLI Credential Manager** with industry-standard security following Bitwarden/1Password architecture patterns.

## 🔐 Security Features

- **Zero-Knowledge**: Database never sees your master password or encryption keys.
- **AES-256-GCM**: Authenticated encryption with tamper detection.
- **Argon2id KDF**: OWASP 2024 recommended key derivation (GPU-resistant).
- **Memory Hardening**: Active memory wiping (`secure_wipe`) to prevent RAM scraping.
- **Lazy Decryption**: Resource-efficient UI that only decrypts data on demand.
- **Portable**: Login from any device with just Email + Master Password.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         YOUR DEVICE                              │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │  Email   │───>│ Fetch Salt   │───>│     Argon2id KDF      │  │
│  └──────────┘    │ (Public DB)  │    │  (64MB, 3 iterations) │  │
│                  └──────────────┘    └───────────┬───────────┘  │
│  ┌──────────┐                                    │              │
│  │ Master   │────────────────────────────────────┘              │
│  │ Password │                                                   │
│  └──────────┘                        ┌───────────┴───────────┐  │
│                                      │     Master Key (Km)   │  │
│                                      └───────────┬───────────┘  │
│                                 ┌────────────────┼────────────┐ │
│                                 │                │            │ │
│                         ┌───────▼───────┐ ┌──────▼──────┐     │ │
│                         │  Auth Key     │ │ Encryption  │     │ │
│                         │  (Ka) - HKDF  │ │ Key (Ke)    │     │ │
│                         └───────┬───────┘ └──────┬──────┘     │ │
│                                 │                │            │ │
│                                 ▼                ▼            │ │
│                         ┌─────────────┐  ┌─────────────┐      │ │
│                         │ Database    │  │ Decrypt PSK │      │ │
│                         │ Auth Login  │  │ -> Vault Key│      │ │
│                         └─────────────┘  └─────────────┘      │ │
└─────────────────────────────────────────────────────────────────┘
                                │                │
                                ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                          DATABASE                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  auth.users     │  │ user_metadata   │  │     vault       │  │
│  │  (Auth only)    │  │ (Salt + PSK)    │  │ (Encrypted)     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                  │
│  Database sees: hex(Ka), Salt, PSK, Encrypted blobs             │
│  Database NEVER sees: Master Password, Km, Ke, Vault Key, Data  │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your Database URL and anon key
```

### 2. Setup Database

- Go to your Database Dashboard → SQL Editor.
- Run the consolidated `schema.sql` to initialize/update your tables and RPC functions.

### 3. Installation

#### **Desktop (Windows/macOS/Linux)**

```bash
# Install in editable mode (Professional method)
pip install -e .

# Run the application
python -m credx

# List available command
python run.py --help
```

or

```bash
# From root directory
python run.py
```

#### **Android (Termux)**

Bypass heavy compilation errors by using pre-compiled binaries:

```bash
# Run the automated setup script
bash requirements_termux.sh

# Run the application
python -m credx
```

## 🧪 Automated Testing

To ensure your installation is clean and error-free:

```bash
# Run unit tests (Local logic)
python tests/test_credx.py

# Run full integration test (Live Database check)
python tests/integration_full_flow.py
```

## 🔒 Key Concepts

| Term                              | Description                                              |
| --------------------------------- | -------------------------------------------------------- |
| **Master Key (Km)**               | Derived from password + salt via Argon2id. Never stored. |
| **Auth Key (Ka)**                 | HKDF(Km, "auth"). Used as Database password (hex).       |
| **Encryption Key (Ke)**           | HKDF(Km, "encryption"). Decrypts PSK.                    |
| **Symmetric Key (Ks)**            | Random 256-bit key. Encrypts vault data.                 |
| **Protected Symmetric Key (PSK)** | AES-GCM(Ks, Ke). Stored in database.                     |

## 📜 License

MIT
