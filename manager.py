# ? Project overview for reviewers
# * This file contains the main application logic for the password manager.
# * PasswordManager controls the vault workflow: unlock, add, retrieve, list, delete, and generate.
# * It also decides when to save data, when to decrypt data, and when to copy passwords.
# ! Plaintext passwords are only kept temporarily during a command and are never written to vault.json.
# ? Why this matters: recruiters can see the project uses clean OOP instead of putting all logic in main.py.

"""Business logic for the CLI password manager."""

# * Standard library imports
from datetime import datetime, timezone
from getpass import getpass
import json
from pathlib import Path
import secrets
import string

# * Local crypto imports
from crypto import CryptoError
from crypto import decode_bytes
from crypto import decrypt_text
from crypto import encode_bytes
from crypto import encrypt_text
from crypto import generate_salt
from crypto import make_fernet

# * Vault settings
DEFAULT_VAULT_PATH = Path(__file__).with_name("vault.json")
VAULT_VERSION = 1
VAULT_CHECK_TEXT = "password-manager-vault-check"

# * Password generator settings
DEFAULT_PASSWORD_LENGTH = 24
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


class PasswordManagerError(Exception):
    """Raised when the password manager cannot complete an operation."""


class CommandResult:
    """Store the message and optional secret returned by a command."""

    def __init__(self, message, secret=None):
        """Create a simple command result object."""

        # * Store the safe message that main.py can print.
        self.message = message

        # ! This is only used when a command is allowed to print a password.
        self.secret = secret


class PasswordManager:
    """Manage encrypted password entries stored in a JSON vault."""

    def __init__(self, master_password, vault_path=DEFAULT_VAULT_PATH):
        """Open an existing vault or create a new one."""

        # * Store the vault path as a Path object so file operations are simple.
        self.vault_path = Path(vault_path)

        # * This will hold the Fernet encryption object after the vault is unlocked.
        self.fernet = None

        # * Try to load vault.json from disk.
        loaded_vault = self._load_vault_file()

        # * Create a new vault when vault.json does not exist yet.
        if loaded_vault is None:
            self.vault_data = self._create_new_vault(master_password)
            self._save_vault()
            return

        # * Use the existing vault data when vault.json already exists.
        self.vault_data = loaded_vault
        self._prepare_existing_vault(master_password)

    @classmethod
    def from_master_password_prompt(cls, vault_path=DEFAULT_VAULT_PATH):
        """Ask for the master password and return a PasswordManager object."""

        # ! getpass hides the password while the user types it.
        master_password = getpass("Master password: ")

        # ! Empty master passwords are not accepted.
        if not master_password:
            raise PasswordManagerError("Master password cannot be empty.")

        # * Create and return the manager after the password is entered.
        manager = cls(master_password, vault_path)
        return manager

    def add_entry(self, service, username, password, force=False):
        """Add a new password entry to the vault."""

        # * Clean and validate the user input.
        service_name = self._require_value(service, "Service")
        username_text = self._require_value(username, "Username")
        password_text = self._require_value(password, "Password")

        # * Convert the service name into a consistent dictionary key.
        service_key = self._make_service_key(service_name)

        # * Read the current vault entries.
        entries = self.vault_data["entries"]

        # ! Do not overwrite an existing service unless --force is used.
        existing_entry = entries.get(service_key)
        if existing_entry is not None and not force:
            message = "Service '" + service_name + "' already exists. Use --force to replace it."
            raise PasswordManagerError(message)

        # * Encrypt the password before it is placed in the vault dictionary.
        encrypted_password = self._encrypt_password(password_text)

        # * Reuse the old created_at value when updating an existing entry.
        current_time = self._utc_now()
        created_at = current_time
        if existing_entry is not None:
            created_at = existing_entry["created_at"]

        # * Build the dictionary that will be saved inside vault.json.
        entry = {
            "service": service_name,
            "username": username_text,
            "password": encrypted_password,
            "created_at": created_at,
            "updated_at": current_time,
        }

        # * Save the entry in memory.
        entries[service_key] = entry

        # * Write the updated encrypted vault to disk.
        self._save_vault()

        # * Return a clear message for the CLI.
        if existing_entry is None:
            action = "Added"
        else:
            action = "Updated"

        # * Build the final response.
        message = action + " '" + service_name + "' for username '" + username_text + "'."
        return CommandResult(message)

    def get_entry(self, service, show_password=False):
        """Get a password from the vault and copy it to the clipboard."""

        # * Clean and normalize the requested service name.
        service_name = self._require_value(service, "Service")
        service_key = self._make_service_key(service_name)

        # * Find the matching vault entry.
        entry = self._get_entry_or_raise(service_key, service_name)

        # * Decrypt the password only after the entry is found.
        password = self._decrypt_password(entry["password"])

        # * Try to copy the password to the clipboard.
        clipboard_message = self._copy_to_clipboard(password)

        # * Build safe output that does not show the password by default.
        message_lines = []
        message_lines.append("Service: " + entry["service"])
        message_lines.append("Username: " + entry["username"])
        message_lines.append(clipboard_message)
        message = "\n".join(message_lines)

        # ! Only show the password when the user passes --show.
        if show_password:
            return CommandResult(message, password)

        # * Return the safe result.
        return CommandResult(message)

    def list_services(self):
        """List all saved services in the vault."""

        # * Read the current vault entries.
        entries = self.vault_data["entries"]

        # * Show a helpful message when the vault is empty.
        if len(entries) == 0:
            return CommandResult("No services saved yet.")

        # * Sort entries so the output is easy to read.
        sorted_entries = sorted(entries.values(), key=self._service_sort_value)

        # * Build the output one line at a time.
        lines = []
        lines.append("Saved services:")

        # * Add each service and username to the output.
        for entry in sorted_entries:
            line = "- " + entry["service"] + " (" + entry["username"] + ")"
            lines.append(line)

        # * Return the complete list.
        message = "\n".join(lines)
        return CommandResult(message)

    def delete_entry(self, service):
        """Delete one saved service from the vault."""

        # * Clean and normalize the requested service name.
        service_name = self._require_value(service, "Service")
        service_key = self._make_service_key(service_name)

        # * Find the entry first so the error message is clear if it does not exist.
        entry = self._get_entry_or_raise(service_key, service_name)

        # * Remove the entry from the vault dictionary.
        entries = self.vault_data["entries"]
        del entries[service_key]

        # * Save the updated vault to disk.
        self._save_vault()

        # * Return a clear success message.
        message = "Deleted '" + entry["service"] + "'."
        return CommandResult(message)

    def generate_password(self, length=DEFAULT_PASSWORD_LENGTH):
        """Generate a strong random password."""

        # * Make sure the requested password length is safe.
        self._validate_password_length(length)

        # ? These groups make sure the password has lowercase, uppercase, digits, and symbols.
        character_groups = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            SYMBOLS,
        ]

        # * Start with one character from each group.
        password_characters = []
        for group in character_groups:
            random_character = secrets.choice(group)
            password_characters.append(random_character)

        # * Combine all allowed characters into one large string.
        all_characters = ""
        for group in character_groups:
            all_characters = all_characters + group

        # * Add more random characters until the requested length is reached.
        remaining_count = length - len(password_characters)
        for unused_number in range(remaining_count):
            random_character = secrets.choice(all_characters)
            password_characters.append(random_character)

        # * Shuffle the characters so the first four are not always predictable groups.
        secure_random = secrets.SystemRandom()
        secure_random.shuffle(password_characters)

        # * Turn the list of characters into one password string.
        password = "".join(password_characters)

        # * Return the generated password so main.py can print it.
        message = "Generated password (" + str(length) + " characters):"
        return CommandResult(message, password)

    def _load_vault_file(self):
        """Load vault.json from disk, or return None when it does not exist."""

        # * A missing vault means this is the first run.
        if not self.vault_path.exists():
            return None

        # * Read the JSON file from disk.
        try:
            with self.vault_path.open("r", encoding="utf-8") as vault_file:
                loaded_data = json.load(vault_file)
        except json.JSONDecodeError as error:
            raise PasswordManagerError("Vault file contains invalid JSON.") from error
        except OSError as error:
            message = "Could not read vault file: " + str(error)
            raise PasswordManagerError(message) from error

        # ! The vault must be a JSON object, not a list or string.
        if not isinstance(loaded_data, dict):
            raise PasswordManagerError("Vault file must contain a JSON object.")

        # * Return the loaded vault dictionary.
        return loaded_data

    def _create_new_vault(self, master_password):
        """Create a new encrypted vault dictionary."""

        # * Generate a random salt for this vault.
        salt = generate_salt()

        # * Build the encryption object and encrypted check token.
        try:
            self.fernet = make_fernet(master_password, salt)
            check_token = encrypt_text(self.fernet, VAULT_CHECK_TEXT)
        except CryptoError as error:
            raise PasswordManagerError(str(error)) from error

        # * Store the salt as text because JSON cannot store raw bytes.
        salt_text = encode_bytes(salt)

        # * Build the full vault structure.
        vault_data = {
            "version": VAULT_VERSION,
            "salt": salt_text,
            "check": check_token,
            "entries": {},
        }

        # * Return the new vault dictionary.
        return vault_data

    def _prepare_existing_vault(self, master_password):
        """Validate and unlock an existing vault."""

        # * Check that the vault has the fields this program expects.
        self._validate_vault_shape()

        # * Decode the saved salt and rebuild the encryption object.
        try:
            salt = decode_bytes(self.vault_data["salt"])
            self.fernet = make_fernet(master_password, salt)
        except CryptoError as error:
            raise PasswordManagerError(str(error)) from error

        # ! Verify the master password before running any command.
        self._verify_master_password()

    def _validate_vault_shape(self):
        """Check the main structure of the loaded vault."""

        # ! Version checks prevent this code from reading an unknown future format.
        if self.vault_data.get("version") != VAULT_VERSION:
            raise PasswordManagerError("Unsupported vault version.")

        # ! The vault needs a salt string for key creation.
        if not isinstance(self.vault_data.get("salt"), str):
            raise PasswordManagerError("Vault field 'salt' is missing or invalid.")

        # ! The vault needs a check token to verify the master password.
        if not isinstance(self.vault_data.get("check"), str):
            raise PasswordManagerError("Vault field 'check' is missing or invalid.")

        # ! Entries must be a dictionary of saved services.
        if not isinstance(self.vault_data.get("entries"), dict):
            raise PasswordManagerError("Vault field 'entries' is missing or invalid.")

    def _verify_master_password(self):
        """Check that the master password can unlock the vault."""

        # * Try to decrypt the saved check token.
        try:
            decrypted_check_text = decrypt_text(self.fernet, self.vault_data["check"])
        except CryptoError as error:
            raise PasswordManagerError("Incorrect master password or damaged vault.") from error

        # ! The decrypted check text must match the expected value.
        if decrypted_check_text != VAULT_CHECK_TEXT:
            raise PasswordManagerError("Vault verification failed.")

    def _save_vault(self):
        """Write the current encrypted vault dictionary to disk."""

        # * Make sure the vault folder exists before writing the file.
        try:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            message = "Could not create vault directory: " + str(error)
            raise PasswordManagerError(message) from error

        # ! Only encrypted password tokens should be written to this JSON file.
        try:
            with self.vault_path.open("w", encoding="utf-8") as vault_file:
                json.dump(self.vault_data, vault_file, indent=2)
                vault_file.write("\n")
        except OSError as error:
            message = "Could not write vault file: " + str(error)
            raise PasswordManagerError(message) from error

    def _make_service_key(self, service_name):
        """Create the dictionary key used for a service name."""

        # ? casefold makes GitHub, github, and GITHUB point to the same entry.
        service_key = service_name.casefold()

        # * Return the normalized service key.
        return service_key

    def _require_value(self, value, label):
        """Validate a required text value and return its stripped version."""

        # ! None is not valid text input.
        if value is None:
            message = label + " cannot be empty."
            raise PasswordManagerError(message)

        # * Remove extra spaces from the beginning and end.
        stripped_value = value.strip()

        # ! Empty text is not allowed for required fields.
        if stripped_value == "":
            message = label + " cannot be empty."
            raise PasswordManagerError(message)

        # * Return the cleaned value.
        return stripped_value

    def _get_entry_or_raise(self, service_key, requested_service):
        """Find an entry or raise an error if it does not exist."""

        # * Read the current vault entries.
        entries = self.vault_data["entries"]

        # * Look for the requested service.
        entry = entries.get(service_key)

        # ! Missing services should fail with a clear message.
        if entry is None:
            message = "Service '" + requested_service + "' was not found."
            raise PasswordManagerError(message)

        # * Check that the entry has the expected fields.
        self._validate_entry_shape(entry, requested_service)

        # * Return the valid entry.
        return entry

    def _validate_entry_shape(self, entry, requested_service):
        """Check that one saved entry has all required fields."""

        # ! Each entry should be a dictionary.
        if not isinstance(entry, dict):
            message = "Vault entry '" + requested_service + "' is invalid."
            raise PasswordManagerError(message)

        # * These fields are required for each saved service.
        required_fields = ["service", "username", "password", "created_at", "updated_at"]

        # ! Every required field must exist and must be text.
        for field_name in required_fields:
            field_value = entry.get(field_name)
            if not isinstance(field_value, str):
                message = "Vault entry '" + requested_service + "' is missing '" + field_name + "'."
                raise PasswordManagerError(message)

    def _encrypt_password(self, password_text):
        """Encrypt a password before saving it."""

        # * Convert crypto errors into password-manager errors.
        try:
            encrypted_password = encrypt_text(self.fernet, password_text)
        except CryptoError as error:
            raise PasswordManagerError("Could not encrypt the password.") from error

        # * Return the encrypted password token.
        return encrypted_password

    def _decrypt_password(self, encrypted_password):
        """Decrypt a saved password token."""

        # * Convert crypto errors into password-manager errors.
        try:
            password = decrypt_text(self.fernet, encrypted_password)
        except CryptoError as error:
            raise PasswordManagerError("Could not decrypt the stored password.") from error

        # * Return the decrypted password for this command only.
        return password

    def _copy_to_clipboard(self, password):
        """Copy a password to the clipboard when pyperclip is available."""

        # * Import pyperclip here so the whole app does not crash when it is missing.
        try:
            import pyperclip
        except ImportError:
            return "Clipboard unavailable because pyperclip is not installed. Use --show to print the password."

        # * Try to copy the password.
        try:
            pyperclip.copy(password)
        except pyperclip.PyperclipException:
            return "Clipboard unavailable. Use --show to print the password."

        # * Return a safe status message.
        return "Password copied to clipboard."

    def _validate_password_length(self, length):
        """Check that the generated password length is allowed."""

        # ! Very short generated passwords are not allowed.
        if length < MIN_PASSWORD_LENGTH:
            message = "Password length must be at least " + str(MIN_PASSWORD_LENGTH) + "."
            raise PasswordManagerError(message)

        # ! Very long generated passwords are blocked to avoid accidental huge output.
        if length > MAX_PASSWORD_LENGTH:
            message = "Password length must be at most " + str(MAX_PASSWORD_LENGTH) + "."
            raise PasswordManagerError(message)

    def _service_sort_value(self, entry):
        """Return the value used when sorting saved services."""

        # * Sort services by their display name, ignoring case.
        service_name = entry["service"]
        sort_value = service_name.lower()

        # * Return the sort value.
        return sort_value

    def _utc_now(self):
        """Return the current UTC time as text."""

        # * Store times in UTC so the vault is consistent across machines.
        current_time = datetime.now(timezone.utc)

        # * Convert the datetime object into ISO text for JSON.
        time_text = current_time.isoformat()

        # * Return the timestamp text.
        return time_text

    # TODO Add export and import commands after the basic CLI is stable.
