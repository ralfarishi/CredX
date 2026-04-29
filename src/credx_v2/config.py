"""
CredX Vault - Configuration and Constants (v3.0)
"""

from rich.theme import Theme

# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

APP_NAME = "CredX"
APP_VERSION = "1.9.2"
APP_SUBTITLE = "Zero-Knowledge Vault"

# Canary value for master password verification
CANARY_SERVICE = "__SYSTEM_CANARY__"
CANARY_VALUE = "CREDX_VAULT_CANARY_CHECK"

# ═══════════════════════════════════════════════════════════════════════════════
# KDF CONFIGURATION (v3.0)
# ═══════════════════════════════════════════════════════════════════════════════

# Default KDF algorithm ('argon2id' or 'pbkdf2')
DEFAULT_KDF_ALGORITHM = "argon2id"

# Argon2id parameters
DEFAULT_ARGON2_TIME_COST = 3       # iterations
DEFAULT_ARGON2_MEMORY_COST = 65536  # 64 MiB in KiB
DEFAULT_ARGON2_PARALLELISM = 4

# PBKDF2 fallback parameters
DEFAULT_PBKDF2_ITERATIONS = 600_000

# ═══════════════════════════════════════════════════════════════════════════════
# THEME CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

CUSTOM_THEME = Theme({
    "primary": "bold cyan",
    "secondary": "bold magenta",
    "success": "bold green",
    "warning": "bold yellow",
    "danger": "bold red",
    "info": "dim cyan",
    "muted": "dim white",
})
