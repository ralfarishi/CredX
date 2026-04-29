#!/bin/bash

# =====================================================
# CredX Vault - Termux Installation Script
# This solves the common Android compilation errors.
# =====================================================

echo "🚀 Starting CredX Setup..."

# 1. Update Termux environment
echo "🔄 Updating packages..."
pkg update && pkg upgrade -y

# 2. Install binary dependencies (The "Heavy" stuff)
# This prevents pip from trying to compile them from source
echo "📦 Installing binary dependencies via pkg..."
pkg install python rust clang make libffi openssl binutils -y

# Install pre-compiled cryptography for Termux
pkg install python-cryptography -y

# 3. Install dependencies from pyproject.toml
echo "🐍 Installing Python dependencies..."
# We install the package itself in editable mode, which pulls all dependencies
# from pyproject.toml automatically.
pip install -e .

echo ""
echo "✅ Setup Complete!"
echo "👉 To run the app: credx"
echo "   (or: python run.py)"
echo ""
