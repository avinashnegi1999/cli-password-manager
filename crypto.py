# ? Project overview for reviewers
# * This file is the security layer for the password manager.
# * It turns the user's master password into an encryption key with PBKDF2HMAC.
# * It encrypts and decrypts password text with Fernet authenticated encryption.
# ! The raw master password is never stored; only encrypted vault data and a random salt are saved.
# ? Why this matters: security-sensitive code is isolated, easier to audit, and easier to improve later.

"""Crypto helpers for the CLI password manager."""

# * Standard library imports
import base64
import os

# * Crypto settings
SALT_SIZE_BYTES = 16
FERNET_KEY_BYTES = 32
KDF_ITERATIONS = 600_000


class CryptoError(Exception):
    """Raised when encryption, decryption, or key creation fails."""


def generate_salt(size=SALT_SIZE_BYTES):
    """Create a random salt for the vault."""

    # ! The salt must be random so each vault gets a different encryption key.
    if size < SALT_SIZE_BYTES:
        message = "Salt size must be at least " + str(SALT_SIZE_BYTES) + " bytes."
        raise CryptoError(message)

    # * os.urandom gives secure random bytes from the operating system.
    salt = os.urandom(size)

    # * Return the salt so manager.py can save it in vault.json.
    return salt


def encode_bytes(raw_bytes):
    """Convert bytes into text so they can be stored in JSON."""

    # * Base64 turns bytes into safe text.
    encoded_bytes = base64.urlsafe_b64encode(raw_bytes)

    # * JSON stores strings, so decode the base64 bytes into normal text.
    encoded_text = encoded_bytes.decode("utf-8")

    # * Return the JSON-safe string.
    return encoded_text


def decode_bytes(encoded_text):
    """Convert base64 text from JSON back into bytes."""

    # * Convert text into bytes because the base64 decoder expects bytes.
    try:
        encoded_bytes = encoded_text.encode("utf-8")
        raw_bytes = base64.urlsafe_b64decode(encoded_bytes)
    except (ValueError, AttributeError, TypeError) as error:
        raise CryptoError("Stored base64 value is invalid.") from error

    # * Return the decoded bytes.
    return raw_bytes


def derive_key(master_password, salt, iterations=KDF_ITERATIONS):
    """Create a Fernet-ready encryption key from the master password."""

    # ! The vault is only as strong as the master password.
    if not master_password:
        raise CryptoError("Master password cannot be empty.")

    # ! Lower iteration counts make password guessing faster for attackers.
    if iterations < KDF_ITERATIONS:
        message = "KDF iterations must be at least " + str(KDF_ITERATIONS) + "."
        raise CryptoError(message)

    # * Import cryptography here so --help can still work before dependencies are installed.
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as error:
        message = "Missing dependency: install cryptography with 'pip install -r requirements.txt'."
        raise CryptoError(message) from error

    # ? PBKDF2HMAC stretches the password into a strong fixed-size key.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=FERNET_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )

    # * Convert the master password into bytes before deriving the key.
    password_bytes = master_password.encode("utf-8")

    # * Derive the raw 32-byte key.
    raw_key = kdf.derive(password_bytes)

    # ? Fernet requires the key to be URL-safe base64 text stored as bytes.
    fernet_key = base64.urlsafe_b64encode(raw_key)

    # * Return the final Fernet key.
    return fernet_key


def make_fernet(master_password, salt):
    """Create the Fernet object used for encryption and decryption."""

    # * Import Fernet here so dependency errors can be shown clearly.
    try:
        from cryptography.fernet import Fernet
    except ImportError as error:
        message = "Missing dependency: install cryptography with 'pip install -r requirements.txt'."
        raise CryptoError(message) from error

    # * First create the encryption key from the password and salt.
    key = derive_key(master_password, salt)

    # * Build the Fernet object that encrypts and decrypts text.
    fernet = Fernet(key)

    # * Return the ready-to-use Fernet object.
    return fernet


def encrypt_text(fernet, plain_text):
    """Encrypt normal text and return encrypted text for JSON storage."""

    # ! None is not valid password text and should not be encrypted silently.
    if plain_text is None:
        raise CryptoError("Cannot encrypt a null value.")

    # * Fernet encrypts bytes, so convert the text into bytes first.
    plain_bytes = plain_text.encode("utf-8")

    # * Encrypt the bytes.
    encrypted_bytes = fernet.encrypt(plain_bytes)

    # * Fernet returns base64 bytes, so convert them into text for vault.json.
    encrypted_text = encrypted_bytes.decode("utf-8")

    # * Return encrypted text.
    return encrypted_text


def decrypt_text(fernet, encrypted_text):
    """Decrypt encrypted text and return the original normal text."""

    # * Import InvalidToken here so this file does not require cryptography at startup.
    try:
        from cryptography.fernet import InvalidToken
    except ImportError as error:
        message = "Missing dependency: install cryptography with 'pip install -r requirements.txt'."
        raise CryptoError(message) from error

    # ! InvalidToken usually means the master password is wrong or the vault is damaged.
    try:
        encrypted_bytes = encrypted_text.encode("utf-8")
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
    except (InvalidToken, AttributeError) as error:
        raise CryptoError("Unable to decrypt value.") from error

    # * Convert decrypted bytes back into normal text.
    plain_text = decrypted_bytes.decode("utf-8")

    # * Return the original text.
    return plain_text
