# ? Project overview for reviewers
# * This file is the CLI entrypoint for an encrypted password manager.
# * A user runs commands like add, get, list, delete, and generate from the terminal.
# * This file intentionally focuses only on argument parsing and command dispatch.
# ! Real password storage, validation, encryption, and clipboard logic live outside this file.
# ? Why this matters: it shows separation of concerns, which makes the project easier to test and explain.

"""Command-line interface for the password manager."""

# * Standard library imports
import argparse
from pathlib import Path
import sys

# * Local manager imports
from manager import DEFAULT_PASSWORD_LENGTH
from manager import DEFAULT_VAULT_PATH
from manager import PasswordManager
from manager import PasswordManagerError


def build_parser():
    """Build the command-line parser."""

    # * These examples appear at the bottom of the help menu for beginners.
    help_examples = """
Examples:
  python main.py add github avina "my-password"
  python main.py list
  python main.py get github --show
  python main.py generate --length 24
  python main.py delete github

Tip:
  In this project, use .\\.venv\\Scripts\\python.exe instead of python.
"""

    # * Create the main parser for the whole program.
    parser = argparse.ArgumentParser(
        description="Encrypted CLI password manager",
        epilog=help_examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # * Add a global option for choosing a custom vault path.
    parser.add_argument(
        "--vault",
        default=str(DEFAULT_VAULT_PATH),
        help="Path to vault JSON file. Default: " + str(DEFAULT_VAULT_PATH),
    )

    # * Create the subcommand area: add, get, list, delete, generate.
    subparsers = parser.add_subparsers(dest="command", required=True)

    # * Build the add command.
    add_parser = subparsers.add_parser("add", help="Add a new password entry")
    add_parser.add_argument("service", help="Service name, for example github")
    add_parser.add_argument("username", help="Username or email for the service")
    add_parser.add_argument("password", help="Password to encrypt and store")
    add_parser.add_argument("--force", action="store_true", help="Replace an existing service entry")

    # * Build the get command.
    get_parser = subparsers.add_parser("get", help="Retrieve a saved password")
    get_parser.add_argument("service", help="Service name to retrieve")
    get_parser.add_argument("--show", action="store_true", help="Print the password after copying it")

    # * Build the list command.
    subparsers.add_parser("list", help="List saved services")

    # * Build the delete command.
    delete_parser = subparsers.add_parser("delete", help="Delete a saved password entry")
    delete_parser.add_argument("service", help="Service name to delete")

    # * Build the generate command.
    generate_parser = subparsers.add_parser("generate", help="Generate a strong random password")
    generate_parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_PASSWORD_LENGTH,
        help="Generated password length. Default: " + str(DEFAULT_PASSWORD_LENGTH),
    )

    # * Return the complete parser.
    return parser


def run_command(manager, args):
    """Call the correct PasswordManager method for the selected command."""

    # * Route the add command to PasswordManager.add_entry.
    if args.command == "add":
        result = manager.add_entry(args.service, args.username, args.password, args.force)
        return result

    # * Route the get command to PasswordManager.get_entry.
    if args.command == "get":
        result = manager.get_entry(args.service, args.show)
        return result

    # * Route the list command to PasswordManager.list_services.
    if args.command == "list":
        result = manager.list_services()
        return result

    # * Route the delete command to PasswordManager.delete_entry.
    if args.command == "delete":
        result = manager.delete_entry(args.service)
        return result

    # * Route the generate command to PasswordManager.generate_password.
    if args.command == "generate":
        result = manager.generate_password(args.length)
        return result

    # ! argparse should stop unknown commands before this point.
    raise PasswordManagerError("Unknown command: " + str(args.command))


def print_result(result):
    """Print the result returned by PasswordManager."""

    # * Print the normal message first.
    print(result.message)

    # ! Only print the secret when PasswordManager intentionally returns one.
    if result.secret is not None:
        print(result.secret)


def main(argv=None):
    """Parse arguments, unlock the vault, run the command, and return an exit code."""

    # * Build and run the argument parser.
    parser = build_parser()

    # * Use real terminal arguments when main() is called normally.
    if argv is None:
        command_line_arguments = sys.argv[1:]
    else:
        command_line_arguments = argv

    # * Show help when the file is run without a command.
    if len(command_line_arguments) == 0:
        print("No command provided. Choose one command from the help menu below.")
        print()
        parser.print_help()
        return 0

    # * Parse the command-line arguments after the no-command check.
    args = parser.parse_args(command_line_arguments)

    # * Convert the vault path text into a Path object.
    vault_path = Path(args.vault)

    # ! Prompt for the master password only after argparse has validated the command.
    try:
        manager = PasswordManager.from_master_password_prompt(vault_path)
        result = run_command(manager, args)
    except PasswordManagerError as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1

    # * Print the command result.
    print_result(result)

    # * Return a success exit code.
    return 0


if __name__ == "__main__":
    # * Start the program when this file is run directly.
    exit_code = main()
    raise SystemExit(exit_code)
