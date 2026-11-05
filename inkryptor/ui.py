"""Interactive terminal interface for Inkryptor."""

import random
from datetime import datetime, timezone
from pathlib import Path

import click
from PIL import Image, UnidentifiedImageError

from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from inkryptor import auth
from inkryptor.crypto import (
    encrypt_data,
    decrypt_data,
    DecryptionError,
)
from inkryptor.embed import (
    embed_payload,
    calculate_capacity,
    EmbeddingError,
)
from inkryptor.extract import (
    extract_payload,
    ExtractionError,
)


console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = PROJECT_ROOT / "assets" / "sample_images"
OUTPUT_DIR = PROJECT_ROOT / "output"

SCHEMA_NAME = "inkryptor.credentials"
SCHEMA_VERSION = 1

SUPPORTED_IMAGE_FORMATS = {
    ".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tiff", ".tif"
}


# --------------------------------------------------
# Interface
# --------------------------------------------------

def show_banner():
    """Display the Inkryptor welcome banner."""

    console.print()
    console.print(
        "  [bold bright_cyan]INKRYPTOR[/bold bright_cyan] "
        "[dim]// SECURE CREDENTIAL STORAGE[/dim]"
    )
    console.print("  [dim]Hide it in plain sight.[/dim]")
    console.rule(style="bright_cyan")
    console.print()


def show_main_menu():
    """Display the main menu and return the selection."""

    console.print("[bold]MAIN MENU[/bold]\n")

    console.print("  [bright_cyan]1[/bright_cyan]  Encrypt credentials")
    console.print("  [bright_cyan]2[/bright_cyan]  Decrypt credentials")
    console.print("  [bright_cyan]3[/bright_cyan]  Image information")
    console.print("  [bright_cyan]4[/bright_cyan]  Exit")

    console.print()

    return Prompt.ask(
        "[bold bright_cyan]inkryptor[/bold bright_cyan] [dim]›[/dim]",
        choices=["1", "2", "3", "4"],
        default="4",
    )


def show_section(title, description=None):
    """Display a lightweight workflow heading."""

    console.print()
    console.print(f"[bold bright_cyan]{title.upper()}[/bold bright_cyan]")

    if description:
        console.print(f"[dim]{description}[/dim]")

    console.print()


def show_success(message):
    console.print(f"\n[bold green]✓ {message}[/bold green]")


def show_error(message):
    console.print(f"\n[bold red]✗ {message}[/bold red]")


def ask_path(message):
    """Prompt for a filesystem path with Tab autocomplete."""

    return prompt(
        f"{message}: ",
        completer=PathCompleter(expanduser=True),
        complete_while_typing=False,
    ).strip()


# --------------------------------------------------
# Master password
# --------------------------------------------------

def setup_master_password():
    """Handle first-time master password configuration."""

    show_section(
        "First-time setup",
        "No master password configured. Let's create one.",
    )

    while True:
        password = Prompt.ask(
            "Create master password",
            password=True,
        )

        if not auth.enforce_password_strength(password):
            show_error(
                "Use at least 12 characters with uppercase, "
                "lowercase, digits and symbols."
            )
            continue

        confirmation = Prompt.ask(
            "Confirm master password",
            password=True,
        )

        if password != confirmation:
            show_error("Passwords do not match. Try again.")
            continue

        break

    try:
        auth.set_master_password(password)

    except auth.AuthError as exc:
        raise click.ClickException(str(exc)) from exc

    show_success("Master password created successfully!")

    Prompt.ask(
        "\nPress Enter to continue",
        default="",
        show_default=False,
    )


def authenticate():
    """Verify the master password for a protected operation."""

    if not auth.is_master_password_set():
        setup_master_password()

    console.print("\n[bold]MASTER PASSWORD AUTHENTICATION[/bold]")

    for attempt in range(3):
        password = Prompt.ask(
            "Enter master password",
            password=True,
        )

        try:
            if auth.verify_master_password(password):
                show_success("Authentication successful!")
                return password

        except auth.AuthError as exc:
            raise click.ClickException(str(exc)) from exc

        remaining = 2 - attempt

        if remaining:
            show_error(
                f"Incorrect password. {remaining} attempts remaining."
            )

    raise click.ClickException(
        "Too many incorrect attempts. Restart Inkryptor to try again."
    )


# --------------------------------------------------
# Image selection
# --------------------------------------------------

def select_cover_image():
    """Ask for a cover image or select a random sample."""

    while True:
        image_input = ask_path(
            "Cover image path (blank for a random sample)"
        )

        if image_input:
            image_path = Path(image_input).expanduser()

            if not image_path.is_file():
                show_error("File not found. Try again.")
                continue

            if image_path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
                show_error("Unsupported image format.")
                continue

            try:
                with Image.open(image_path) as img:
                    img.verify()

            except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError,
            ):
                show_error("Unable to read this image. Try another.")
                continue

            console.print(
                f"[green]✓ Selected cover image: {image_path}[/green]"
            )
            return image_path.resolve()

        if not SAMPLE_DIR.is_dir():
            raise click.ClickException(
                f"Sample image directory not found: {SAMPLE_DIR}"
            )

        candidates = [
            path for path in SAMPLE_DIR.iterdir()
            if path.is_file()
            and path.suffix.lower() in SUPPORTED_IMAGE_FORMATS
        ]

        random.shuffle(candidates)

        for candidate in candidates:
            try:
                with Image.open(candidate) as img:
                    img.verify()

                console.print(
                    f"[green]✓ Random sample selected: {candidate.name}[/green]"
                )
                return candidate.resolve()

            except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError,
            ):
                continue

        raise click.ClickException(
            "No usable sample images found. Add valid images to "
            "assets/sample_images or provide your own image path."
        )


def select_output_path(input_path):
    """Ask for an output path or generate one automatically."""

    while True:
        output_input = ask_path(
            "Output image path (blank for default)"
        )

        if not output_input:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            output_path = OUTPUT_DIR / f"inkryptor_{timestamp}.png"

        else:
            output_path = Path(output_input).expanduser()

            if output_path.suffix.lower() != ".png":
                show_error("Output must have a .png extension.")
                continue

            if not output_path.parent.is_dir():
                show_error("Output directory does not exist.")
                continue

        if output_path.resolve() == input_path.resolve():
            show_error("Input and output images must be different.")
            continue

        if output_path.exists():
            show_error("Output file already exists. Choose another path.")
            continue

        return output_path.resolve()


def select_stego_image():
    """Ask for a steganographic image or find one in output/."""

    while True:
        image_input = ask_path(
            "Steganographic image path (blank for automatic selection)"
        )

        if image_input:
            image_path = Path(image_input).expanduser()

            if not image_path.is_file():
                show_error("File not found. Try again.")
                continue

            if image_path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
                show_error("Unsupported image format.")
                continue

            try:
                with Image.open(image_path) as img:
                    img.verify()

            except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError,
            ):
                show_error("Unable to read this image.")
                continue

            return image_path.resolve()

        if not OUTPUT_DIR.is_dir():
            raise click.ClickException(
                "No output directory found. Provide an image path."
            )

        candidates = [
            path for path in OUTPUT_DIR.iterdir()
            if path.is_file()
            and path.suffix.lower() in SUPPORTED_IMAGE_FORMATS
        ]

        random.shuffle(candidates)

        for candidate in candidates:
            try:
                extract_payload(candidate)

                console.print(
                    f"[green]✓ Inkryptor image found: {candidate.name}[/green]"
                )
                return candidate.resolve()

            except ExtractionError:
                continue

        raise click.ClickException(
            "No valid Inkryptor images found in output/. "
            "Provide an image path or encrypt some credentials first."
        )


def select_info_image():
    """Select an image for inspection."""

    while True:
        image_input = ask_path(
            "Image path (blank for a random image)"
        )

        if image_input:
            image_path = Path(image_input).expanduser()

            if not image_path.is_file():
                show_error("File not found. Try again.")
                continue

            if image_path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
                show_error("Unsupported image format.")
                continue

            try:
                with Image.open(image_path) as img:
                    img.verify()

                return image_path.resolve()

            except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError,
            ):
                show_error("Unable to read this image.")
                continue

        candidates = []

        for directory in (OUTPUT_DIR, SAMPLE_DIR):
            if directory.is_dir():
                candidates.extend(
                    path for path in directory.iterdir()
                    if path.is_file()
                    and path.suffix.lower() in SUPPORTED_IMAGE_FORMATS
                )

        random.shuffle(candidates)

        for candidate in candidates:
            try:
                with Image.open(candidate) as img:
                    img.verify()

                console.print(
                    f"[green]✓ Selected image: {candidate.name}[/green]"
                )
                return candidate.resolve()

            except (
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError,
            ):
                continue

        raise click.ClickException(
            "No usable images found. Provide an image path or add "
            "images to assets/sample_images."
        )


# --------------------------------------------------
# Credential collection
# --------------------------------------------------

def collect_credentials():
    """Collect multiple credentials from the user."""

    count = IntPrompt.ask(
        "\nHow many credentials would you like to store?",
        default=1,
    )

    while not 1 <= count <= 100:
        show_error("Enter a number between 1 and 100.")
        count = IntPrompt.ask("Number of credentials")

    credentials = []

    for index in range(1, count + 1):
        console.print(
            f"\n[bold bright_cyan]CREDENTIAL {index}/{count}[/bold bright_cyan]"
        )

        service = Prompt.ask("Service name").strip()

        while not service:
            show_error("Service name cannot be empty.")
            service = Prompt.ask("Service name").strip()

        username = Prompt.ask(
            "Username / Email",
            default="",
            show_default=False,
        ).strip()

        password = click.prompt(
            "Credential password",
            hide_input=True,
            confirmation_prompt=True,
        )

        credentials.append({
            "service": service,
            "username": username,
            "password": password,
        })

    return credentials


# --------------------------------------------------
# Encryption
# --------------------------------------------------

def encrypt_workflow(master_password):
    """Collect credentials, encrypt them and embed them into an image."""

    show_section(
        "Encrypt credentials",
        "Encrypt your credentials and hide them inside an image.",
    )

    image_path = select_cover_image()
    output_path = select_output_path(image_path)
    credentials = collect_credentials()

    payload_data = {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "credentials": credentials,
    }

    try:
        with console.status("[cyan]Encrypting credentials..."):
            encrypted_payload = encrypt_data(
                payload_data,
                master_password,
            )

        with console.status("[cyan]Embedding payload into image..."):
            embed_payload(
                encrypted_payload,
                image_path,
                output_path,
            )

    except (ValueError, EmbeddingError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    show_success("Encryption completed successfully!")

    console.print(f"  Credentials stored : {len(credentials)}")
    console.print(f"  Cover image        : {image_path.name}")
    console.print(f"  Output image       : {output_path}")


# --------------------------------------------------
# Decryption
# --------------------------------------------------

def decrypt_workflow(master_password):
    """Extract and decrypt credentials from a steganographic image."""

    show_section(
        "Decrypt credentials",
        "Recover credentials hidden inside an image.",
    )

    image_path = select_stego_image()

    try:
        with console.status("[cyan]Extracting hidden payload..."):
            encrypted_payload = extract_payload(image_path)

        with console.status("[cyan]Decrypting credentials..."):
            data = decrypt_data(encrypted_payload, master_password)

    except (ExtractionError, DecryptionError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if (
        not isinstance(data, dict)
        or data.get("schema") != SCHEMA_NAME
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("credentials"), list)
    ):
        raise click.ClickException(
            "Unsupported or invalid credential data."
        )

    credentials = data["credentials"]

    if not credentials:
        raise click.ClickException("No credentials found.")

    for credential in credentials:
        if not isinstance(credential, dict):
            raise click.ClickException("Invalid credential entry.")

        if not all(
            isinstance(credential.get(field), str)
            for field in ("service", "username", "password")
        ):
            raise click.ClickException("Malformed credential entry.")

    show_success("Credentials recovered successfully!")

    console.print(f"  Image       : {image_path.name}")
    console.print(f"  Created     : {data.get('created_at', 'Unknown')}")
    console.print(f"  Credentials : {len(credentials)}\n")

    reveal = Confirm.ask(
        "Reveal recovered passwords?",
        default=False,
    )

    table = Table(
        title="Recovered Credentials",
        border_style="bright_cyan",
        show_lines=False,
    )

    table.add_column("Service", style="cyan")
    table.add_column("Username")
    table.add_column("Password", style="green")

    for credential in credentials:
        password = (
            credential["password"]
            if reveal
            else "*" * min(len(credential["password"]), 20)
        )

        table.add_row(
            credential["service"],
            credential["username"],
            password,
        )

    console.print()
    console.print(table)


# --------------------------------------------------
# Image information
# --------------------------------------------------

def image_info_workflow():
    """Display image properties and Inkryptor payload information."""

    show_section(
        "Image information",
        "Inspect image properties and embedded Inkryptor payloads.",
    )

    image_path = select_info_image()

    try:
        with Image.open(image_path) as img:
            width, height = img.size
            image_format = img.format or "Unknown"
            color_mode = img.mode

        file_size = image_path.stat().st_size
        capacity = calculate_capacity(width, height)

    except (
        OSError,
        ValueError,
        Image.DecompressionBombError,
    ) as exc:
        raise click.ClickException(
            f"Unable to inspect image: {exc}"
        ) from exc

    console.print("[bold]IMAGE PROPERTIES[/bold]")

    console.print(f"  Filename       {image_path.name}")
    console.print(f"  Format         {image_format}")
    console.print(f"  Dimensions     {width} × {height}")
    console.print(f"  Color mode     {color_mode}")
    console.print(f"  File size      {file_size / 1024:.2f} KB")
    console.print(f"  Payload limit  {capacity:,} bytes")

    try:
        payload = extract_payload(image_path)

        used = len(payload)
        remaining = max(0, capacity - used)

        console.print()
        show_success("Valid Inkryptor payload detected!")

        console.print(f"  Payload size       : {used:,} bytes")
        console.print(f"  Remaining capacity : {remaining:,} bytes")

    except ExtractionError:
        console.print()
        console.print(
            "[yellow]○ No valid Inkryptor payload detected.[/yellow]"
        )
        console.print(
            "[dim]This image can potentially be used as a cover image.[/dim]"
        )


# --------------------------------------------------
# Application entry point
# --------------------------------------------------

def run():
    """Start the Inkryptor interactive interface."""

    show_banner()

    if not auth.is_master_password_set():
        setup_master_password()
    else:
        console.print(
            "[green]✓ Master password found.[/green] "
            "[dim]Welcome back![/dim]\n"
        )

    while True:
        choice = show_main_menu()

        if choice == "1":
            try:
                master_password = authenticate()
                encrypt_workflow(master_password)

            except click.ClickException as exc:
                show_error(str(exc))

        elif choice == "2":
            try:
                master_password = authenticate()
                decrypt_workflow(master_password)

            except click.ClickException as exc:
                show_error(str(exc))

        elif choice == "3":
            try:
                image_info_workflow()

            except click.ClickException as exc:
                show_error(str(exc))

        elif choice == "4":
            console.print()
            console.rule(style="bright_cyan")
            console.print(
                "[bold bright_cyan]Thank you for using Inkryptor![/bold bright_cyan]"
            )
            console.print()
            break
