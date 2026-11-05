import click
from inkryptor import auth
import getpass

@click.group()
def cli():
    pass

@cli.command(help="Set up the master password for Inkryptor")
def setup():
    if auth.is_master_password_set():
        click.echo("Master Password already set. No need to run setup again")
        return

    while True:
        password = getpass.getpass("Create your Master Password: ")
        confirm = getpass.getpass("Confirm Password: ")

        if password != confirm:
            click.echo("Password does not match! Try again.\n")
            continue

        if not auth.enforce_password_strength(password):
            click.echo("Password too weak! Use atleast 12 characters, with uppercase, lowercase, digits and symbols.\n")
            continue

        auth.set_master_password(password)
        click.echo("Master Password setup successful!")
        break

if __name__ == "__main__":
    cli()
