"""
CredX Vault - Menu Handlers
Handles user interactions for each menu option with interactive selection.
"""

import getpass

from pyfiglet import Figlet
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .crypto import secure_wipe
from .ui import (
    console,
    interactive_confirm,
    interactive_credential_select,
    interactive_text,
    show_info,
    show_warning,
    clear_screen,
)
from .vault import VaultManager

fig = Figlet(font="slant")


def _show_empty_vault_message():
    """Display a message when vault is empty."""
    console.print(Panel(
        Align.center(
            "[warning]No credentials stored yet.[/warning]\n"
            "[muted]Use 'Create Node' to store your first credential.[/muted]"
        ),
        border_style="yellow",
        padding=(1, 2),
    ))


def handle_add_credential(vault: VaultManager):
    """Handle adding a new credential with interactive input."""
    console.print(Panel(
        "[bold cyan]➕ Initializing New Node[/bold cyan]",
        border_style="cyan",
    ))

    service = interactive_text("Identifier (service name)")
    if not service:
        console.print("[danger]Error: Null identifier[/danger]")
        return
    if len(service) > 100:
        console.print("[danger]Error: Identifier exceeds maximum length (100)[/danger]")
        return

    username = interactive_text("Uid / Email")
    if not username:
        console.print("[danger]Error: Null uid[/danger]")
        return
    if len(username) > 255:
        console.print("[danger]Error: Uid exceeds maximum length (255)[/danger]")
        return

    password_raw = getpass.getpass("🔑 Passphrase: ").strip()
    if not password_raw:
        console.print("[danger]Error: Null phrase[/danger]")
        return
    if len(password_raw) > 1024:
        console.print("[danger]Error: Passphrase exceeds maximum length (1024)[/danger]")
        return

    password = bytearray(password_raw.encode("utf-8"))
    password_raw = "" # Attempt to clear string reference
    
    try:
        vault.add_credential(service, username, password)
    finally:
        secure_wipe(password)


def handle_get_password(vault: VaultManager):
    """Handle retrieving and displaying a password with interactive selection."""
    summaries = vault.get_entry_summaries()
    
    if not summaries:
        _show_empty_vault_message()
        return

    selected_summary = interactive_credential_select(
        message="Select credential to decrypt",
        credentials=summaries,
    )
    
    if not selected_summary:
        show_info("Selection cancelled.")
        return

    # Fetch full entry now (Lazy Decryption)
    entry = vault.get_full_entry_by_id(selected_summary["id"])
    if not entry:
        show_warning("Error: Could not decrypt entry payload.")
        return

    # Display the credential details with ASCII art
    fig.width = min(console.width - 10, 60)
    service_art = fig.renderText(entry["service"]).rstrip()

    info_table = Table(show_header=False, box=None, padding=(0, 3))
    info_table.add_column("System Parameter", style="muted")
    info_table.add_column("Value String", style="bold white")
    info_table.add_row("Uid:", entry["username"])
    info_table.add_row("Pwd:", entry["password"])

    detail_content = Group(
        Align.center(Text(service_art, style="secondary")),
        Text(),
        Align.center(info_table),
    )

    console.print(Panel(
        detail_content,
        title="[bold magenta]═══ DECODED PAYLOAD ═══[/bold magenta]",
        border_style="magenta",
        padding=(1, 2),
    ))


def handle_update_credential(vault: VaultManager):
    """Handle updating an existing credential with interactive selection."""
    summaries = vault.get_entry_summaries()
    
    if not summaries:
        _show_empty_vault_message()
        return

    selected_summary = interactive_credential_select(
        message="Select credential to update",
        credentials=summaries,
    )
    
    if not selected_summary:
        show_info("Selection cancelled.")
        return

    # Fetch full entry for current values
    entry = vault.get_full_entry_by_id(selected_summary["id"])
    if not entry:
        show_warning("Error: Could not decrypt entry payload.")
        return

    show_info("Leave empty to keep current value")

    new_service = interactive_text(
        f"Identifier [{entry['service']}]",
        default=entry["service"],
        validate=False,
    ) or entry["service"]
    
    if len(new_service) > 100:
        console.print("[danger]Error: Identifier exceeds maximum length (100)[/danger]")
        return

    new_username = interactive_text(
        f"Uid [{entry['username']}]",
        default=entry["username"],
        validate=False,
    ) or entry["username"]
    if len(new_username) > 255:
        console.print("[danger]Error: Uid exceeds maximum length (255)[/danger]")
        return

    new_password_raw = getpass.getpass(
        "🔑 Passphrase [Keep current]: "
    ).strip()
    
    if new_password_raw:
        if len(new_password_raw) > 1024:
            console.print("[danger]Error: Passphrase exceeds maximum length (1024)[/danger]")
            return
        new_password = bytearray(new_password_raw.encode("utf-8"))
    else:
        new_password = bytearray(entry["password"].encode("utf-8"))
    
    new_password_raw = "" # Attempt to clear string reference

    try:
        # Check if anything actually changed
        if (new_service == entry["service"] and 
            new_username == entry["username"] and 
            new_password.decode("utf-8") == entry["password"]):
            console.print("[muted]No changes detected. Skipping update.[/muted]")
            return

        vault.update_credential(entry["id"], new_service, new_username, new_password)
    finally:
        secure_wipe(new_password)


def handle_delete_credential(vault: VaultManager):
    """Handle deleting a credential with interactive selection and confirmation."""
    summaries = vault.get_entry_summaries()
    
    if not summaries:
        _show_empty_vault_message()
        return

    selected_summary = interactive_credential_select(
        message="Select credential to delete",
        credentials=summaries,
    )
    
    if not selected_summary:
        show_info("Selection cancelled.")
        return

    # Interactive confirmation
    if interactive_confirm(f"Confirm purge '{selected_summary['service']}'?", default=False):
        vault.delete_credential(selected_summary['id'], selected_summary['service'])
    else:
        show_info("Deletion cancelled.")
