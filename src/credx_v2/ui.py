"""
CredX Vault - UI Components
Rich-based CLI interface components for a beautiful user experience.
"""

from datetime import datetime
from typing import Any

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator
from pyfiglet import Figlet
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from .config import APP_NAME, APP_SUBTITLE, APP_VERSION, CUSTOM_THEME

console = Console(theme=CUSTOM_THEME)
fig = Figlet(font="slant")

# InquirerPy theme matching Rich cyan/green theme
# Using get_style with custom dict to create proper InquirerStyle object
from InquirerPy.utils import get_style

INQUIRER_STYLE = get_style({
    "questionmark": "#00d7ff bold",  # Cyan
    "answermark": "#00ff00",         # Green
    "answer": "#00ff00 bold",        # Green
    "input": "#ffffff",              # White
    "question": "#00d7ff",           # Cyan
    "answered_question": "#888888",  # Muted
    "instruction": "#888888",        # Muted
    "long_instruction": "#888888",   # Muted
    "pointer": "#00d7ff bold",       # Cyan arrow
    "checkbox": "#00d7ff",           # Cyan
    "separator": "#888888",          # Muted
    "skipped": "#888888",            # Muted
    "validator": "#ff5555",          # Red for errors
    "marker": "#00ff00",             # Green checkmark
    "fuzzy_prompt": "#00d7ff",       # Cyan
    "fuzzy_info": "#888888",         # Muted
    "fuzzy_border": "#00d7ff",       # Cyan
    "fuzzy_match": "#00ff00",        # Green for matches
}, style_override=False)


def clear_screen():
    """Clear the terminal screen."""
    console.clear()


def render_header(title: str = APP_NAME, subtitle: str = APP_SUBTITLE, version: str = APP_VERSION):
    """
    Render the application header with ASCII art.
    
    Args:
        title: Main title text for ASCII art
        subtitle: Subtitle displayed below the ASCII art
    """
    fig.width = min(console.width - 10, 80)
    ascii_art = fig.renderText(title).rstrip()

    header_content = Group(
        Align.center(Text(ascii_art, style="primary")),
        Align.center(Text(f"\n─── {subtitle} ───", style="muted")),
        Align.center(Text(f"v{version}", style="muted")),
    )

    console.print(Panel(
        header_content,
        border_style="cyan",
        padding=(1, 2),
    ))


def render_status_bar(user_email: str):
    """
    Render a status bar showing the logged-in user.
    
    Args:
        user_email: The authenticated user's email
    """
    status = Table.grid(expand=True)
    status.add_column(justify="left")
    status.add_column(justify="right")
    status.add_row(
        Text(f"🤖 Operator: {user_email}", style="success"),
        Text(datetime.now().strftime("%Y-%m-%d %H:%M"), style="muted"),
    )
    console.print(Panel(status, border_style="dim cyan", padding=(0, 1)))


def render_menu():
    """Render the main menu with styled options."""
    menu_items = [
        ("1", "List Entries", "Scan all encrypted modules"),
        ("2", "Create Node", "Initialize new credential node"),
        ("3", "Decrypt By Id", "Extract specific payload data"),
        ("4", "Patch Node", "Update existing credential node"),
        ("5", "Purge Node", "Remove credential node"),
        ("6", "Disconnect", "Terminate session and lock vault"),
    ]

    menu_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        expand=True,
    )
    menu_table.add_column("Key", style="primary", width=4)
    menu_table.add_column("Action", style="bold white")
    menu_table.add_column("Description", style="muted")

    for key, action, desc in menu_items:
        menu_table.add_row(f"[{key}]", action, desc)

    console.print(Panel(
        Align.center(menu_table),
        title="[bold cyan]═══ SELECT COMMAND ═══[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))


def show_spinner(message: str) -> Progress:
    """
    Create a styled spinner context manager.
    
    Args:
        message: Message to display with the spinner
    
    Returns:
        Progress instance for use as context manager
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[primary]{task.description}"),
        console=console,
        transient=True,
    )


def show_success(message: str):
    """Display a success message in a green panel."""
    console.print(Panel(
        Align.center(f"[success]{message}[/success]"),
        border_style="green",
        padding=(0, 2),
    ))


def show_error(message: str):
    """Display an error message in a red panel."""
    console.print(Panel(
        Align.center(f"[danger]{message}[/danger]"),
        border_style="red",
        padding=(0, 2),
    ))


def show_warning(message: str):
    """Display a warning message in a yellow panel."""
    console.print(Panel(
        Align.center(f"[warning]{message}[/warning]"),
        border_style="yellow",
        padding=(0, 2),
    ))


def show_info(message: str):
    """Display an info message."""
    console.print(f"[muted]{message}[/muted]")


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE SELECTION FUNCTIONS (Arrow-key navigation)
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_select(
    message: str,
    choices: list[tuple[str, str, str]],
    default: str | None = None,
) -> str:
    """
    Display an interactive menu with arrow-key navigation.
    
    Args:
        message: Prompt message to display
        choices: List of (value, label, description) tuples
        default: Default selected value
    
    Returns:
        Selected value
    """
    inquirer_choices = [
        Choice(value=value, name=f"{label:<18} {description}")
        for value, label, description in choices
    ]
    
    result = inquirer.select(
        message=message,
        choices=inquirer_choices,
        default=default,
        style=INQUIRER_STYLE,
        pointer="❯",
        qmark="⚡",
        amark="✓",
        instruction="(↑↓ navigate, Enter select)",
    ).execute()
    
    return result


def interactive_confirm(
    message: str,
    default: bool = False,
) -> bool:
    """
    Display an interactive Yes/No confirmation with arrow-key navigation.
    
    Args:
        message: Confirmation message
        default: Default selection (True=Yes, False=No)
    
    Returns:
        True if confirmed, False otherwise
    """
    result = inquirer.confirm(
        message=message,
        default=default,
        style=INQUIRER_STYLE,
        qmark="⚠",
        amark="✓",
        instruction="(y/n)",
    ).execute()
    
    return result


def interactive_credential_select(
    message: str,
    credentials: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Display an interactive credential selector with arrow-key navigation.
    
    Args:
        message: Prompt message
        credentials: List of credential dicts with 'id', 'service', 'username' keys
    
    Returns:
        Selected credential dict, or None if cancelled
    """
    if not credentials:
        return None
    
    inquirer_choices = [
        Choice(
            value=cred,
            name=f"[{i+1}] {cred['service']:<20} ({cred['username']})"
        )
        for i, cred in enumerate(credentials)
    ]
    
    # Add cancel option
    inquirer_choices.append(Separator())
    inquirer_choices.append(Choice(value=None, name="✗ Cancel"))
    
    result = inquirer.select(
        message=message,
        choices=inquirer_choices,
        style=INQUIRER_STYLE,
        pointer="❯",
        qmark="🔐",
        amark="✓",
        instruction="(↑↓ navigate, Enter select)",
    ).execute()
    
    return result


def interactive_text(
    message: str,
    default: str = "",
    validate: bool = True,
) -> str:
    """
    Display an interactive text input.
    
    Args:
        message: Prompt message
        default: Default value
        validate: Whether to validate non-empty input
    
    Returns:
        User input string
    """
    result = inquirer.text(
        message=message,
        default=default,
        style=INQUIRER_STYLE,
        qmark="📝",
        amark="✓",
        validate=lambda x: len(x.strip()) > 0 if validate else True,
        invalid_message="Input cannot be empty",
    ).execute()
    
    return result.strip() if result else ""
