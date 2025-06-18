import sys
import os
import json
import base64
import getpass
from inputimeout import inputimeout, TimeoutOccurred

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration ---
KDF_ITERATIONS = 480000
SALT_SIZE = 16
TIMEOUT_SECONDS = 300  # 5 minutes


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_store(filepath: str) -> (dict, str):
    """Loads and decrypts an existing password store."""
    master_password = getpass.getpass("Enter master password: ")

    with open(filepath, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    encrypted_data = base64.b64decode(data["encrypted_data"])

    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        passwords = json.loads(decrypted_data)
        print("Vault unlocked successfully.")
        return passwords, master_password
    except InvalidToken:
        print("Error: Invalid master password or corrupted file.")
        sys.exit(1)


def print_help(): #print nice disply of help commands

    print("\nAvailable commands:")
    print("  get <service>              - Get password for a service")
    print("  set <service> <user> <pass>- Add/update a password")
    print("  del <service>              - Delete a password")
    print("  list                       - List all services")
    print("  help                       - Show this help message")
    print("  exit                       - Save and exit the vault\n")



def create_new_store() -> tuple[dict, str]: #create master password, return dict with master password
    print("NO current vault, creating new one....")
    master_password = getpass.getpass("Enter NEW(!) password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if master_password != confirm_password:
        print("You entered a different confirmation password/phrase")
        sys.exit(1)

    print("New vault created :)")
    return {}, master_password


def save_store(filepath: str, passwords: dict, master_password: str): #encrypt and save pw to file
    
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    passwords_bytes = json.dumps(passwords).encode()
    encrypted_data = fernet.encrypt(passwords_bytes)

    file_content = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
    }

    temp_filepath = filepath + ".tmp"
    with open(temp_filepath, "w") as f:
        json.dump(file_content, f, indent=2)

    os.rename(temp_filepath, filepath)
    print(f"Vault saved and locked at '{filepath}'.")

def handle_get(passwords: dict, parts: list):
    """Handles the 'get' command."""
    if len(parts) != 2:
        print("Usage: get <service>")
        return
    service = parts[1]
    entry = passwords.get(service)
    if not entry:
        print(f"Service '{service}' not found.")
        return
    print(f"Service:  {service}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")


def handle_set(passwords: dict, parts: list):
    """Handles the 'set' command."""
    if len(parts) != 4:
        print("Usage: set <service> <username> <password>")
        return
    service, username, password = parts[1], parts[2], parts[3]
    passwords[service] = {"username": username, "password": password}
    print(f"Password for '{service}' has been set.")


def handle_list(passwords: dict):
    """Handles the 'list' command."""
    if not passwords:
        print("No passwords stored yet.")
        return
    print("Services stored:")
    for service in sorted(passwords.keys()):
        print(f"  - {service}")

def handle_del(passwords: dict, parts: list):
    """Handles the 'del' command."""
    if len(parts) != 2:
        print("Usage: del <service>")
        return
    service = parts[1]
    if service in passwords:
        del passwords[service]
        print(f"Password for '{service}' deleted.")
    else:
        print(f"Service '{service}' not found.")


def interactive_session(passwords: dict) -> dict:
    """Runs the main interactive command loop."""
    print_help()
    while True:
        try:
            raw_input = inputimeout(
                prompt="> ", timeout=TIMEOUT_SECONDS
            )
            parts = raw_input.strip().split()

            if not parts:
                continue

            command = parts[0].lower()

            if command == "exit":
                return passwords
            elif command == "help":
                print_help()
            elif command == "list":
                handle_list(passwords)
            elif command == "get":
                handle_get(passwords, parts)
            elif command == "set":
                handle_set(passwords, parts)
            elif command == "del":
                handle_del(passwords, parts)
            else:
                print(
                    f"Unknown command: '{command}'. Type 'help' for a list."
                )

        except TimeoutOccurred:
            print("\nInactivity timeout reached. Locking vault.")
            return passwords

def main():
    """Main entry point for the script."""
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <filepath>")
        sys.exit(1)

    filepath = sys.argv[1]

    if os.path.exists(filepath):
        passwords, master_password = load_store(filepath)
    else:
        passwords, master_password = create_new_store()

    updated_passwords = None
    try:
        updated_passwords = interactive_session(passwords)
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Saving and exiting.")
        updated_passwords = passwords
    finally:
        if updated_passwords is not None:
            save_store(filepath, updated_passwords, master_password)
        else:
            print("Exiting without saving due to an unexpected error.")


if __name__ == "__main__":
    main()
