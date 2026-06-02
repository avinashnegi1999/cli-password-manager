# CLI Password Manager

This is a beginner-friendly Python command-line password manager.

It is built as a resume project to show Python CLI development, object-oriented programming, encrypted storage, and clean project structure.

It can:

- Add a password for a service
- Get a saved password
- List saved services
- Delete a saved password
- Generate a strong random password
- Encrypt saved passwords inside `vault.json`

The project uses a master password. You must type the same master password every time you run a command.

## Features

- Command-line interface built with `argparse`
- Master password prompt with hidden input using `getpass`
- Encrypted password storage using `cryptography`
- Key derivation from the master password using PBKDF2HMAC
- Clipboard copy support using `pyperclip`
- Strong password generation using `secrets`
- Clean separation between CLI, business logic, and encryption logic

## Tech Stack

- Python
- argparse
- getpass
- secrets
- cryptography
- pyperclip
- JSON file storage

## Beginner Quick Start

Open PowerShell or the VS Code terminal and copy these commands:

```powershell
cd G:\python\password-manager
.\.venv\Scripts\python.exe main.py
```

If you see the help menu, the project is running correctly.

To add your first password:

```powershell
.\.venv\Scripts\python.exe main.py add github avina "my-password"
```

After you press Enter, the program asks for:

```text
Master password:
```

Type a master password you can remember.

The master password will not appear while typing. That is normal.

Use the same master password every time you run this project.

## How To Read A Command

This command:

```powershell
.\.venv\Scripts\python.exe main.py add github avina "my-password"
```

means:

- `.\.venv\Scripts\python.exe` runs Python from this project's virtual environment
- `main.py` starts the password manager
- `add` tells the program to save a new password
- `github` is the service name
- `avina` is the username
- `"my-password"` is the password that will be encrypted and saved

## Project Files

```text
password-manager/
  main.py          # CLI commands and argument parsing
  manager.py       # Main password manager logic
  crypto.py        # Encryption and decryption helpers
  vault.json       # Created automatically, stores encrypted data
  requirements.txt # Required Python packages
  README.md        # Beginner instructions
```

## Important

Do not manually edit `vault.json`.

Do not commit `vault.json` to GitHub because it stores your encrypted password vault.

If you forget your master password, the saved passwords cannot be recovered.

## How To Open The Project In VS Code

1. Open VS Code.
2. Click `File`.
3. Click `Open Folder`.
4. Select this folder:

```powershell
G:\python\password-manager
```

5. Open the VS Code terminal:

```text
Ctrl + `
```

## How To Run

First, make sure you are inside the project folder:

```powershell
cd G:\python\password-manager
```

Then run:

```powershell
.\.venv\Scripts\python.exe main.py
```

This shows the help menu.

If you are currently at this prompt:

```powershell
PS G:\python>
```

You are one folder too high.

Run this first:

```powershell
cd G:\python\password-manager
```

## If The Virtual Environment Does Not Exist

If this command does not work:

```powershell
.\.venv\Scripts\python.exe main.py
```

Create the virtual environment:

```powershell
python -m venv .venv
```

Install the required packages:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Now run the app again:

```powershell
.\.venv\Scripts\python.exe main.py
```

## Commands

### Add A Password

```powershell
.\.venv\Scripts\python.exe main.py add github avina "my-password"
```

You will see:

```text
Master password:
```

Type your master password and press Enter.

The password text will not show while typing. That is normal.

### List Saved Services

```powershell
.\.venv\Scripts\python.exe main.py list
```

This shows the services saved in your vault.

It does not show the passwords.

### Get A Password

```powershell
.\.venv\Scripts\python.exe main.py get github
```

This copies the password to your clipboard.

If clipboard copy is not available, use `--show`.

### Get A Password And Show It In Terminal

```powershell
.\.venv\Scripts\python.exe main.py get github --show
```

Use this only when you are okay with the password being visible on screen.

### Generate A Strong Password

```powershell
.\.venv\Scripts\python.exe main.py generate --length 24
```

This prints a random password.

It does not save the generated password automatically.

To save a generated password, copy it and then use the `add` command.

### Delete A Saved Password

```powershell
.\.venv\Scripts\python.exe main.py delete github
```

## Example Full Run

```powershell
cd G:\python\password-manager

.\.venv\Scripts\python.exe main.py add github avina "my-password"
.\.venv\Scripts\python.exe main.py list
.\.venv\Scripts\python.exe main.py get github --show
.\.venv\Scripts\python.exe main.py generate --length 24
.\.venv\Scripts\python.exe main.py delete github
```

## Running From VS Code

Use the VS Code terminal for commands.

Do not rely on the VS Code Run button for commands like `add`, `get`, or `delete`.

The Run button usually runs only this:

```powershell
python main.py
```

That only shows the help menu because no command was provided.

## Common Errors

### Error: `.venv\Scripts\python.exe` is not recognized

This usually means you are in the wrong folder.

Go to the project folder:

```powershell
cd G:\python\password-manager
```

Then run the command again.

### Error: `ModuleNotFoundError: No module named 'pyperclip'`

This usually means you are using the wrong Python interpreter.

Use the virtual environment Python:

```powershell
.\.venv\Scripts\python.exe main.py
```

Or install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Error: Incorrect master password

You must use the same master password you used when the vault was first created.

If you want to restart from zero, delete `vault.json`.

Only delete `vault.json` if you are okay losing all saved passwords.

## Beginner Explanation

`main.py` reads the command you type in the terminal.

`manager.py` handles the main work, like adding, finding, deleting, and saving entries.

`crypto.py` handles encryption so passwords are not stored as plain text.

`vault.json` is created automatically and stores encrypted password data.

The project is split into three files so it is easier to understand:

- Start reading `main.py` first
- Then read `manager.py`
- Then read `crypto.py`

You do not need to understand every encryption detail immediately.

For interviews, explain the project like this:

```text
main.py handles the terminal commands.
manager.py handles the password manager features.
crypto.py handles encryption and decryption.
vault.json stores encrypted data.
```

## Notes For Recruiters

This project demonstrates:

- Python CLI development with `argparse`
- Object-oriented programming with a `PasswordManager` class
- Secure password input with `getpass`
- Encrypted storage with `cryptography`
- Key derivation from a master password using PBKDF2HMAC
- Clipboard support with `pyperclip`
- Clean separation between CLI, business logic, and crypto logic

## GitHub Upload Notes

These files should be uploaded to GitHub:

```text
main.py
manager.py
crypto.py
requirements.txt
README.md
.gitignore
```

These files and folders should not be uploaded:

```text
.venv/
vault.json
__pycache__/
```

They are already listed in `.gitignore`.
