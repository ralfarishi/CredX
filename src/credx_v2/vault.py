"""
CredX Vault - Vault Manager (v3.0 Zero-Knowledge)
Manages encrypted credentials in Supabase with AES-256-GCM encryption.
"""

from typing import Optional

from cryptography.exceptions import InvalidTag
from rich.align import Align
from rich.table import Table
from supabase import Client

from .config import CANARY_SERVICE
from .crypto import decrypt_aead, derive_blind_index, encrypt_aead, secure_wipe
from .ui import console, show_spinner, show_success, show_warning


class VaultManager:
    """Manages encrypted credentials in Supabase with client-side AES-256-GCM encryption."""

    def __init__(self, supabase: Client, symmetric_key: bytes | bytearray, blind_index_key: bytes | bytearray, user_id: str):
        """
        Initialize the VaultManager.
        
        Args:
            supabase: Supabase client instance
            symmetric_key: 32-byte symmetric key for AES-256-GCM
            blind_index_key: 32-byte key for blind indexing
            user_id: The authenticated user's ID
        """
        self.supabase = supabase
        self.symmetric_key = bytearray(symmetric_key)
        self.blind_index_key = bytearray(blind_index_key)
        self.user_id = user_id
        self._cache: list[dict] = []
        self._cache_valid: bool = False
        self._summaries_cache: list[dict] = []

    def wipe(self):
        """Securely wipe all keys from memory."""
        secure_wipe(self.symmetric_key)
        secure_wipe(self.blind_index_key)
        # Clear caches
        self._cache = []
        self._summaries_cache = []

    def invalidate_cache(self):
        """Invalidate the local cache so the next fetch reaches the database."""
        self._cache_valid = False
        self._cache = []
        self._summaries_cache = []

    def _fetch_all(self) -> list[dict]:
        """
        Fetch all vault entries for the current user (excluding canary).
        """
        if self._cache_valid:
            return self._cache
            
        response = self.supabase.table("vault") \
            .select("*") \
            .eq("user_id", self.user_id) \
            .neq("service_type", CANARY_SERVICE) \
            .order("created_at", desc=True) \
            .execute()
        
        result: list[dict] = response.data if response.data else []
        
        # Backward Compatibility: Auto-Heal missing blind indices
        self._heal_blind_indices(result)
        
        self._cache = result
        self._cache_valid = True
        return result

    def _heal_blind_indices(self, entries: list[dict]):
        """
        Background process to populate missing blind indices for old records.
        This happens locally and securely using the user's keys.
        """
        to_heal = [e for e in entries if e.get("service_blind_index") is None]
        if not to_heal:
            return

        healed_count = 0
        for entry in to_heal:
            try:
                # Decrypt service name locally
                service = decrypt_aead(entry["service_type"], self.symmetric_key)
                # Derive new blind index
                blind_index = derive_blind_index(service, self.blind_index_key)
                
                # Update database silently
                self.supabase.table("vault") \
                    .update({"service_blind_index": blind_index}) \
                    .eq("id", entry["id"]) \
                    .execute()
                
                # Update local object so it's ready for immediate use
                entry["service_blind_index"] = blind_index
                healed_count += 1
            except Exception:
                # If decryption fails (e.g. corrupt record), skip it
                continue
        
        if healed_count > 0:
            console.print(f"[muted]💡 Optimized {healed_count} legacy records for faster searching.[/muted]")

    def get_entry_summaries(self) -> list[dict]:
        """
        Get a list of decrypted service names and usernames for display in menus.
        Utilizes local cache to avoid repeated decryption overhead.
        """
        if self._summaries_cache:
            return self._summaries_cache

        entries = self._fetch_all()
        summaries = []
        for entry in entries:
            try:
                summaries.append({
                    "id": entry["id"],
                    "service": decrypt_aead(entry["service_type"], self.symmetric_key),
                    "username": decrypt_aead(entry["username_email"], self.symmetric_key),
                    "original_index": entries.index(entry)
                })
            except (InvalidTag, ValueError):
                summaries.append({
                    "id": entry["id"],
                    "service": "[danger]⚠ Decryption Error[/danger]",
                    "username": "—",
                    "original_index": entries.index(entry)
                })
        
        self._summaries_cache = summaries
        return summaries

    def list_credentials(self) -> bool:
        """
        Display all stored credentials in a table.
        """
        with show_spinner("Fetching credentials...") as progress:
            progress.add_task("Fetching credentials...", total=None)
            entries = self._fetch_all()

        if not entries:
            from rich.panel import Panel
            console.print(Panel(
                Align.center(
                    "[warning]No credentials stored yet.[/warning]\n"
                    "[muted]Use 'Add New' to store your first credential.[/muted]"
                ),
                border_style="yellow",
                padding=(1, 2),
            ))
            return False

        table = Table(
            title="[bold cyan]\nStored Credentials[/bold cyan]",
            border_style="cyan",
            header_style="bold white on dark_cyan",
            row_styles=["", "dim"],
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Service", style="bold white")
        table.add_column("Added", style="muted", width=12)

        for idx, entry in enumerate(entries, 1):
            try:
                service = decrypt_aead(entry["service_type"], self.symmetric_key)
                created = entry["created_at"][:10] if entry.get("created_at") else "N/A"
                table.add_row(str(idx), service, created)
            except (InvalidTag, ValueError):
                table.add_row(str(idx), "[danger]⚠ Decryption Error[/danger]", "—")

        console.print(Align.center(table))
        return True

    def add_credential(self, service: str | bytearray, username: str | bytearray, password: str | bytearray):
        """
        Add a new encrypted credential to the vault.
        """
        service_str = service if isinstance(service, str) else service.decode("utf-8")
        
        encrypted_data = {
            "user_id": self.user_id,
            "service_type": encrypt_aead(service, self.symmetric_key),
            "service_blind_index": derive_blind_index(service_str, self.blind_index_key),
            "username_email": encrypt_aead(username, self.symmetric_key),
            "encrypted_password": encrypt_aead(password, self.symmetric_key),
        }

        with show_spinner("Encrypting and saving...") as progress:
            progress.add_task("Encrypting and saving...", total=None)
            self.supabase.table("vault").insert(encrypted_data).execute()
            self.invalidate_cache()

        show_success(f"✓ Credential for '{service_str}' saved successfully!")

    def get_password(self, index: int) -> Optional[str]:
        """
        Retrieve and return the decrypted password for a given index.
        """
        entries = self._fetch_all()
        if 0 <= index < len(entries):
            try:
                return decrypt_aead(entries[index]["encrypted_password"], self.symmetric_key)
            except (InvalidTag, ValueError):
                return None
        return None

    def get_full_entry_by_id(self, entry_id: str) -> Optional[dict]:
        """
        Get and fully decrypt an entry by its ID.
        """
        entries = self._fetch_all()
        for entry in entries:
            if entry["id"] == entry_id:
                try:
                    return {
                        "id": entry["id"],
                        "service": decrypt_aead(entry["service_type"], self.symmetric_key),
                        "username": decrypt_aead(entry["username_email"], self.symmetric_key),
                        "password": decrypt_aead(entry["encrypted_password"], self.symmetric_key),
                    }
                except (InvalidTag, ValueError):
                    return None
        return None

    def get_entry(self, index: int) -> Optional[dict]:
        """
        Get a decrypted entry by index.
        """
        entries = self._fetch_all()
        if 0 <= index < len(entries):
            try:
                return {
                    "id": entries[index]["id"],
                    "service": decrypt_aead(entries[index]["service_type"], self.symmetric_key),
                    "username": decrypt_aead(entries[index]["username_email"], self.symmetric_key),
                    "password": decrypt_aead(entries[index]["encrypted_password"], self.symmetric_key),
                }
            except (InvalidTag, ValueError):
                return None
        return None

    def update_credential(self, entry_id: str, service: str | bytearray, username: str | bytearray, password: str | bytearray):
        """
        Update an existing credential.
        """
        service_str = service if isinstance(service, str) else service.decode("utf-8")
        
        update_data = {
            "service_type": encrypt_aead(service, self.symmetric_key),
            "service_blind_index": derive_blind_index(service_str, self.blind_index_key),
            "username_email": encrypt_aead(username, self.symmetric_key),
            "encrypted_password": encrypt_aead(password, self.symmetric_key),
        }

        with show_spinner("Updating credential...") as progress:
            progress.add_task("Updating credential...", total=None)
            self.supabase.table("vault") \
                .update(update_data) \
                .eq("id", entry_id) \
                .execute()
            self.invalidate_cache()

        show_success("✓ Credential updated successfully!")

    def delete_credential(self, entry_id: str, service_name: str):
        """
        Delete a credential from the vault.
        """
        with show_spinner("Deleting credential...") as progress:
            progress.add_task("Deleting credential...", total=None)
            self.supabase.table("vault") \
                .delete() \
                .eq("id", entry_id) \
                .execute()
            self.invalidate_cache()

        show_warning(f"Credential '{service_name}' has been deleted.")

    def count_entries(self) -> int:
        """
        Get the count of stored credentials.
        """
        return len(self._fetch_all())

    def _decrypt_entry(self, entry: dict) -> Optional[dict]:
        """Decrypt a single entry safely."""
        try:
            return {
                "id": entry["id"],
                "service": decrypt_aead(entry["service_type"], self.symmetric_key),
                "username": decrypt_aead(entry["username_email"], self.symmetric_key),
                "password": decrypt_aead(entry["encrypted_password"], self.symmetric_key),
            }
        except (InvalidTag, ValueError):
            return None

    def get_all_entries(self) -> list[dict]:
        """
        Get all decrypted entries for interactive selection.
        """
        entries = self._fetch_all()
        
        def _iter_decrypted():
            for entry in entries:
                decrypted = self._decrypt_entry(entry)
                if decrypted is not None:
                    yield decrypted
                    
        return list(_iter_decrypted())
