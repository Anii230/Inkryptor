"""Inkryptor command-line interface."""

import json
from datetime import datetime, timezone
from pathlib import Path

import click
from PIL import Image

from inkryptor import auth
from inkryptor.crypto import encrypt_data, decrypt_data, DecryptionError
from inkryptor.embed import (
    embed_payload,
    calculate_capacity,
    EmbeddingError,
)
from inkryptor.extract import extract_payload, ExtractionError


SCHEMA_NAME = "inkryptor.credentials"
SCHEMA_VERSION = 1


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Inkryptor - Securely hide encrypted credentials inside images."""
    pass


@cli.command()
@click.option(
    "--image",
    "-i",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Cover image (PNG, JPEG, or another Pillow-supported format).",
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output steganographic PNG image.",
)
def encrypt(image: Path, output: Path):
    """Encrypt credentials and hide them inside an image."""

    if image.resolve() == output.resolve():
        raise click.ClickException(
            "Input and output images must be different."
        )

    if not output.parent.is_dir():
        raise click.ClickException(
            "Output directory does not exist."
        )

    click.echo("\n--- Inkryptor: Credential Encryption ---\n")

    credentials = []

    while True:
        click.echo(f"\nCredential #{len(credentials) + 1}")

        service = click.prompt("Service name").strip()

        if not service:
            raise click.ClickException("Service name cannot be empty.")

        username = click.prompt(
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

        click.echo(click.style("Credential added.", fg="green"))

        if not click.confirm("Add another credential?", default=False):
            break

    click.echo("\n--- Master Password ---")

    master_password = click.prompt(
        "Create master password",
        hide_input=True,
        confirmation_prompt=True,
    )

    if not auth.enforce_password_strength(master_password):
        raise click.ClickException(
            "Master password is too weak. Use at least 12 characters "
            "with uppercase, lowercase, digits and symbols."
        )

    payload_data = {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "credentials": credentials,
    }

    try:
        encrypted_payload = encrypt_data(
            payload_data,
            master_password,
        )

        embed_payload(
            encrypted_payload,
            image,
            output,
        )

    except (ValueError, EmbeddingError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo()
    click.echo(click.style("Encryption successful!", fg="green", bold=True))
    click.echo(f"Credentials stored: {len(credentials)}")
    click.echo(f"Output image: {output}")


@cli.command()
@click.option(
    "--image",
    "-i",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Inkryptor steganographic image.",
)
def decrypt(image: Path):
    """Extract and decrypt credentials from an image."""

    click.echo("\n--- Inkryptor: Credential Recovery ---\n")

    try:
        encrypted_payload = extract_payload(image)

    except ExtractionError as exc:
        raise click.ClickException(str(exc)) from exc

    master_password = click.prompt(
        "Enter master password",
        hide_input=True,
    )

    try:
        data = decrypt_data(
            encrypted_payload,
            master_password,
        )

    except (DecryptionError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if (
        data.get("schema") != SCHEMA_NAME
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("credentials"), list)
    ):
        raise click.ClickException(
            "Unsupported or invalid credential data."
        )

    credentials = data["credentials"]

    if not credentials:
        raise click.ClickException("No credentials found.")

    click.echo()
    click.echo(click.style("Credentials recovered!", fg="green", bold=True))
    click.echo(f"Created: {data.get('created_at', 'Unknown')}")
    click.echo(f"Total credentials: {len(credentials)}")

    for index, credential in enumerate(credentials, start=1):
        if not isinstance(credential, dict):
            raise click.ClickException("Invalid credential entry.")

        if not all(
            isinstance(credential.get(field), str)
            for field in ("service", "username", "password")
        ):
            raise click.ClickException("Malformed credential entry.")

        click.echo(f"\n--- Credential {index} ---")
        click.echo(f"Service:  {credential['service']}")
        click.echo(f"Username: {credential['username']}")
        click.echo(f"Password: {credential['password']}")


@cli.command()
@click.option(
    "--image",
    "-i",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Image to inspect.",
)
def info(image: Path):
    """Inspect image dimensions, capacity and embedded payload."""

    try:
        with Image.open(image) as img:
            width, height = img.size
            image_format = img.format or "Unknown"

    except (OSError, Image.DecompressionBombError) as exc:
        raise click.ClickException(
            f"Unable to inspect image: {exc}"
        ) from exc

    capacity = calculate_capacity(width, height)

    click.echo("\n--- Inkryptor: Image Information ---\n")
    click.echo(f"Image: {image.name}")
    click.echo(f"Format: {image_format}")
    click.echo(f"Dimensions: {width} x {height}")
    click.echo(f"Maximum payload capacity: {capacity:,} bytes")

    try:
        payload = extract_payload(image)

        click.echo(
            click.style(
                "\nInkryptor payload detected.",
                fg="green",
                bold=True,
            )
        )
        click.echo(f"Embedded payload size: {len(payload):,} bytes")

    except ExtractionError:
        click.echo(
            click.style(
                "\nNo valid Inkryptor payload detected.",
                fg="yellow",
            )
        )


if __name__ == "__main__":
    from inkryptor.ui import run
    run()
