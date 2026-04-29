"""
CredX Vault - Main Entry Point (v3.1 Zero-Knowledge)
Secure CLI password manager using Supabase backend.
"""

import signal
import sys
import time
from typing import Optional

from dotenv import load_dotenv
from rich.align import Align
from rich.panel import Panel

from .auth import (
    AuthContext,
    authenticate,
    get_supabase_client,
    verify_or_create_canary,
)
from .handlers import (
    handle_add_credential,
    handle_delete_credential,
    handle_get_password,
    handle_update_credential,
)
from .ui import (
    clear_screen,
    console,
    interactive_select,
    render_header,
    render_status_bar,
    show_error,
    show_spinner,
    show_success,
)
from .vault import VaultManager

load_dotenv()

# Global references for signal wiping
_CURRENT_AUTH_CONTEXT: Optional[AuthContext] = None
_CURRENT_VAULT_MANAGER: Optional[VaultManager] = None

def signal_handler(sig, frame):
    """Ensure keys are wiped on any exit signal (Ctrl+C, SIGTERM)."""
    if _CURRENT_VAULT_MANAGER:
        _CURRENT_VAULT_MANAGER.wipe()
    if _CURRENT_AUTH_CONTEXT:
        _CURRENT_AUTH_CONTEXT.wipe()
    console.print("\n[warning]⚠ Emergency Shutdown: Security Wipe Executed.[/warning]")
    sys.exit(0)

# Register signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main_menu(vault: VaultManager, auth_context: AuthContext):
    """
    Main application loop with interactive arrow-key navigation.
    """
    display_name = auth_context.display_name
    
    menu_choices = [
        ("list", "List Entries", "Scan all encrypted modules"),
        ("add", "Create Node", "Initialize new credential node"),
        ("get", "Decrypt By Id", "Extract specific payload data"),
        ("update", "Patch Node", "Update existing credential node"),
        ("delete", "Purge Node", "Remove credential node"),
        ("quit", "Disconnect", "Terminate session and lock vault"),
    ]
    
    while True:
        console.print()
        render_status_bar(display_name)
        
        choice = interactive_select(
            message="Execute Command",
            choices=menu_choices,
            default="get",
        )

        if choice == "list":
            vault.list_credentials()
        elif choice == "add":
            handle_add_credential(vault)
        elif choice == "get":
            handle_get_password(vault)
        elif choice == "update":
            handle_update_credential(vault)
        elif choice == "delete":
            handle_delete_credential(vault)
        elif choice == "quit":
            vault.wipe()
            auth_context.wipe()
            console.print(Panel(
                Align.center("[success]✓ Session Terminated. Bye.[/success]"),
                border_style="green",
                padding=(1, 2),
            ))
            break


def main():
    """Application entry point."""
    global _CURRENT_AUTH_CONTEXT, _CURRENT_VAULT_MANAGER
    auth_context = None
    vault = None
    try:
        clear_screen()
        render_header()

        supabase = get_supabase_client()
        
        auth_context = authenticate(supabase)
        if not auth_context:
            return

        _CURRENT_AUTH_CONTEXT = auth_context

        with show_spinner("Verifying vault integrity...") as progress:
            progress.add_task("Auditing...", total=None)
            if not verify_or_create_canary(
                supabase, 
                auth_context.symmetric_key, 
                auth_context.user_id
            ):
                show_error("✗ Error: Integrity check failed")
                sys.exit(1)

        show_success("✓ Vault Decrypted")

        vault = VaultManager(
            supabase, 
            auth_context.symmetric_key, 
            auth_context.blind_index_key,
            auth_context.user_id
        )
        _CURRENT_VAULT_MANAGER = vault
        
        main_menu(vault, auth_context)

    except Exception:
        import traceback
        if vault:
            vault.wipe()
        if auth_context:
            auth_context.wipe()
        console.print("\n")
        show_error("An unexpected error occurred.")
        console.print(Panel(
            traceback.format_exc(), 
            title="[bold red]Debug Traceback[/bold red]", 
            border_style="red"
        ))
        sys.exit(1)


if __name__ == "__main__":
    main()
