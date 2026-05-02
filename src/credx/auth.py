"""
CredX Vault - Authentication Module (v3.1 Zero-Knowledge)
Handles Supabase authentication with Zero-Knowledge key derivation.
"""

import getpass
import os
import re
import sys
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from pyfiglet import Figlet
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from supabase import Client, create_client

from .config import (
    CANARY_SERVICE,
    CANARY_VALUE,
    DEFAULT_ARGON2_MEMORY_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_KDF_ALGORITHM,
)
from .crypto import (
    base64_to_bytes,
    bytes_to_base64,
    decrypt_aead,
    derive_auth_key,
    derive_blind_index_key,
    derive_encryption_key,
    derive_master_key,
    encrypt_aead,
    generate_salt,
    generate_symmetric_key,
    key_to_hex,
    secure_wipe,
)
from .ui import (
    console,
    interactive_select,
    interactive_text,
    show_error,
    show_info,
    show_spinner,
)


# DATA CLASSES

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
MIN_PASSWORD_LENGTH = 8

@dataclass(slots=True)
class UserMetadata:
    """User's cryptographic metadata from database."""
    user_id: str
    email: str
    encryption_salt: bytes
    protected_symmetric_key: str
    kdf_algorithm: str
    kdf_time_cost: int
    kdf_memory_cost: int
    kdf_parallelism: int


@dataclass(slots=True)
class AuthContext:
    """Authentication context containing all derived keys."""
    user_id: str
    email: str
    display_name: str
    symmetric_key: bytearray  # The vault encryption key (Ks)
    blind_index_key: bytearray # Key for deterministic searching

    def wipe(self):
        """Securely wipe all keys from memory."""
        secure_wipe(self.symmetric_key)
        secure_wipe(self.blind_index_key)


# SUPABASE CLIENT

def get_supabase_client() -> Client:
    """
    Create and return a Supabase client using environment variables.
    """
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    if not supabase_url or not supabase_key:
        show_error(
            "Missing SUPABASE_URL or SUPABASE_KEY in .env file!\n"
            "[muted]Please copy .env.example to .env and fill in your credentials.[/muted]"
        )
        sys.exit(1)

    return create_client(supabase_url, supabase_key)


# USER METADATA OPERATIONS

def get_user_metadata(supabase: Client, email: str) -> Optional[UserMetadata]:
    """
    Fetch user metadata (salt, PSK, KDF params) by email via RPC.
    """
    response = supabase.rpc("get_user_metadata_by_email", {
        "p_email": email.lower().strip()
    }).execute()
    
    if not response.data:
        return None
    
    row = response.data[0]
    return UserMetadata(
        user_id=row["user_id"],
        email=email.lower().strip(),
        encryption_salt=base64_to_bytes(row["encryption_salt"]),
        protected_symmetric_key=row["protected_symmetric_key"],
        kdf_algorithm=row.get("kdf_algorithm", DEFAULT_KDF_ALGORITHM),
        kdf_time_cost=row.get("kdf_time_cost", DEFAULT_ARGON2_TIME_COST),
        kdf_memory_cost=row.get("kdf_memory_cost", DEFAULT_ARGON2_MEMORY_COST),
        kdf_parallelism=row.get("kdf_parallelism", DEFAULT_ARGON2_PARALLELISM),
    )


def create_user_metadata(
    supabase: Client,
    user_id: str,
    email: str,
    encryption_salt: bytes,
    protected_symmetric_key: str,
    kdf_algorithm: str = DEFAULT_KDF_ALGORITHM,
    kdf_time_cost: int = DEFAULT_ARGON2_TIME_COST,
    kdf_memory_cost: int = DEFAULT_ARGON2_MEMORY_COST,
    kdf_parallelism: int = DEFAULT_ARGON2_PARALLELISM,
) -> None:
    """
    Create user metadata entry after successful registration.
    """
    # Use RPC call to SECURITY DEFINER function
    supabase.rpc("create_user_metadata_for_new_user", {
        "p_user_id": user_id,
        "p_email": email.lower().strip(),
        "p_encryption_salt": bytes_to_base64(encryption_salt),
        "p_protected_symmetric_key": protected_symmetric_key,
        "p_kdf_algorithm": kdf_algorithm,
        "p_kdf_time_cost": kdf_time_cost,
        "p_kdf_memory_cost": kdf_memory_cost,
        "p_kdf_parallelism": kdf_parallelism,
    }).execute()


# KEY DERIVATION

def derive_keys_from_password(
    password: bytearray | bytes,
    metadata: UserMetadata,
) -> tuple[bytearray, bytearray, bytearray]:
    """
    Derive auth key, encryption key, and blind index key from master password.
    """
    master_key = derive_master_key(
        password=password,
        salt=metadata.encryption_salt,
        kdf_algorithm=metadata.kdf_algorithm,
        time_cost=metadata.kdf_time_cost,
        memory_cost=metadata.kdf_memory_cost,
        parallelism=metadata.kdf_parallelism,
    )
    
    auth_key = derive_auth_key(master_key)
    encryption_key = derive_encryption_key(master_key)
    blind_index_key = derive_blind_index_key(master_key)
    
    secure_wipe(master_key)
    
    return auth_key, encryption_key, blind_index_key


def _build_auth_context(
    user_id: str,
    email: str,
    user_metadata: dict,
    symmetric_key: bytes | bytearray,
    blind_index_key: bytearray,
) -> AuthContext:
    """Consolidated helper to build AuthContext from user data."""
    display_name = user_metadata.get("display_name") or user_metadata.get("full_name") or email
    
    return AuthContext(
        user_id=user_id,
        email=email,
        display_name=display_name,
        symmetric_key=bytearray(symmetric_key),
        blind_index_key=blind_index_key,
    )


# REGISTRATION

def register_user(supabase: Client) -> Optional[AuthContext]:
    """
    Handle user registration and key initialization.
    """
    console.print()
    console.print(Panel(
        "[bold cyan]🔐 Initialize New Identity[/bold cyan]\n\n"
        "[muted]Local KDF Processing: Master phrase remains on-device.[/muted]",
        border_style="cyan",
    ))
    
    email = interactive_text("📧 Email Address: ", validate=True).lower()
    if not email or not EMAIL_REGEX.match(email):
        show_error("Error: Invalid mail format")
        return None

    display_name = interactive_text("👤 Display Name (Operator Name): ", validate=True)

    existing = get_user_metadata(supabase, email)
    if existing:
        show_error("Error: Identity conflict - Account exists")
        return None
    
    password_str = getpass.getpass("🔑 Passphrase: ")
    if not password_str or len(password_str) < MIN_PASSWORD_LENGTH:
        show_error(f"Error: Insufficient entropy (Min {MIN_PASSWORD_LENGTH} chars)")
        return None
    
    password_confirm_str = getpass.getpass("🔑 Confirm Passphrase: ")
    if password_str != password_confirm_str:
        show_error("Error: Phrase mismatch")
        return None
    
    # Convert to bytearray immediately and clear strings
    password = bytearray(password_str.encode("utf-8"))
    password_str = ""
    password_confirm_str = ""
    
    with show_spinner("Computing entropy pool...") as progress:
        progress.add_task("Generating vectors...", total=None)
        
        salt = generate_salt()
        symmetric_key = generate_symmetric_key()
        
        temp_metadata = UserMetadata(
            user_id="", email=email, encryption_salt=salt,
            protected_symmetric_key="", kdf_algorithm=DEFAULT_KDF_ALGORITHM,
            kdf_time_cost=DEFAULT_ARGON2_TIME_COST,
            kdf_memory_cost=DEFAULT_ARGON2_MEMORY_COST,
            kdf_parallelism=DEFAULT_ARGON2_PARALLELISM
        )
        
        auth_key, encryption_key, blind_index_key = derive_keys_from_password(password, temp_metadata)
        secure_wipe(password)
        
        protected_symmetric_key = encrypt_aead(bytes_to_base64(symmetric_key), encryption_key)
        secure_wipe(encryption_key)
        
        auth_password = key_to_hex(auth_key)
        secure_wipe(auth_key)
    
    try:
        with show_spinner("Establishing remote identity...") as progress:
            progress.add_task("Transmitting...", total=None)
            
            response = supabase.auth.sign_up({
                "email": email, 
                "password": auth_password,
                "options": {
                    "data": {"display_name": display_name}
                }
            })
            if not response.user:
                raise Exception("Failed to create account")
            
            user_id = response.user.id
            create_user_metadata(
                supabase=supabase, user_id=user_id, email=email,
                encryption_salt=salt, protected_symmetric_key=protected_symmetric_key
            )
            
            try:
                supabase.auth.sign_in_with_password({"email": email, "password": auth_password})
            except Exception as sign_in_err:
                if "email not confirmed" in str(sign_in_err).lower():
                    console.print("\n[warning]⚠ Email Confirmation Required[/warning]")
                    interactive_text("Check your inbox, confirm, and press Enter to continue...", validate=False)
                    supabase.auth.sign_in_with_password({"email": email, "password": auth_password})
                else:
                    raise sign_in_err
        
        return _build_auth_context(
            user_id=response.user.id,
            email=email,
            user_metadata=response.user.user_metadata or {},
            symmetric_key=symmetric_key,
            blind_index_key=blind_index_key,
        )
        
    except Exception as e:
        show_error(f"Error: Network or identity failure. Details: {e}")
        return None


# LOGIN

def login_user(supabase: Client) -> Optional[AuthContext]:
    """
    Handle user login and key recovery.
    """
    console.print()
    email = interactive_text("📧 Email Address: ", validate=True).lower()
    if not email or not EMAIL_REGEX.match(email):
        show_error("Error: Invalid mail format")
        return None

    with show_spinner("Fetching metadata packet...") as progress:
        progress.add_task("Scanning...", total=None)
        metadata = get_user_metadata(supabase, email)
    
    if not metadata:
        show_error("Error: Identity not found - Register required")
        return None
    
    password_str = getpass.getpass("🔑 Passphrase: ")
    if not password_str:
        show_error("Error: Null phrase")
        return None
    
    password = bytearray(password_str.encode("utf-8"))
    password_str = ""
    
    with show_spinner("Executing Argon2 KDF...") as progress:
        progress.add_task("Deriving keys...", total=None)
        auth_key, encryption_key, blind_index_key = derive_keys_from_password(password, metadata)
        secure_wipe(password)
        auth_password = key_to_hex(auth_key)
        secure_wipe(auth_key)
    
    try:
        with show_spinner("Requesting remote access...") as progress:
            progress.add_task("Authenticating...", total=None)
            response = supabase.auth.sign_in_with_password({"email": email, "password": auth_password})
            if not response.user:
                raise Exception("Authentication failed")
            
    except Exception:
        show_error("✗ Error: Authentication failed - Invalid phrase")
        return None
    
    try:
        with show_spinner("Decrypting vault seed...") as progress:
            progress.add_task("Unlocking...", total=None)
            symmetric_key = base64_to_bytes(decrypt_aead(metadata.protected_symmetric_key, encryption_key))
            secure_wipe(encryption_key)
    except Exception:
        show_error("✗ Error: Vault access failure")
        return None
    
    return _build_auth_context(
        user_id=response.user.id,
        email=email,
        user_metadata=response.user.user_metadata or {},
        symmetric_key=symmetric_key,
        blind_index_key=blind_index_key,
    )



# MAIN AUTHENTICATION FLOW

fig = Figlet(font="slant")

def authenticate(supabase: Client) -> AuthContext:
    """
    Main authentication entry point.
    """
    auth_choices = [
        ("login", "🔓 Login", "Access existing identity"),
        ("register", "🆕 Register", "Initialize new identity"),
        ("quit", "🚪 Quit", "Exit application"),
    ]
    
    while True:
        console.print()
        choice = interactive_select(message="Identity Status", choices=auth_choices, default="login")
        if choice == "login":
            ctx = login_user(supabase)
            if ctx: return ctx
        elif choice == "register":
            ctx = register_user(supabase)
            if ctx: return ctx
        elif choice == "quit":
            sys.exit(0)


# CANARY OPERATIONS

def verify_or_create_canary(supabase: Client, symmetric_key: bytearray, user_id: str) -> bool:
    """
    Verify the symmetric key using a canary record.
    If no canary exists (first time), create one.
    """
    canary_marker = CANARY_SERVICE
    
    response = supabase.table("vault") \
        .select("encrypted_password") \
        .eq("user_id", user_id) \
        .eq("service_type", canary_marker) \
        .execute()
    
    if response.data:
        try:
            stored_canary = response.data[0]["encrypted_password"]
            decrypted = decrypt_aead(stored_canary, symmetric_key)
            return decrypted == CANARY_VALUE
        except (InvalidTag, Exception):
            return False
    else:
        canary_data = {
            "user_id": user_id,
            "service_type": canary_marker,
            "username_email": CANARY_SERVICE,
            "encrypted_password": encrypt_aead(CANARY_VALUE, symmetric_key),
        }
        supabase.table("vault").insert(canary_data).execute()
        
        show_info("✓ Vault initialized successfully!")
        return True
