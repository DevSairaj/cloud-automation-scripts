import os
import sys
import argparse
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken

# --- Directory to store keys ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(SCRIPT_DIR, "Secret Keys")
os.makedirs(KEY_DIR, exist_ok=True)


def generate_key():
    """
    Generates a new Fernet key and saves it with a timestamped filename.

    Returns:
        str: Path to the generated key file.
    """
    key = Fernet.generate_key()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    key_filename = f"secret_{timestamp}.key"
    key_path = os.path.join(KEY_DIR, key_filename)

    with open(key_path, "wb") as key_file:
        key_file.write(key)

    print(f"[+] New key generated: {key_path}")
    return key_path


def load_key(key_path):
    """
    Loads a Fernet key from a file.

    Args:
        key_path (str): Path to the key file.

    Returns:
        bytes: The loaded key.
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")

    with open(key_path, "rb") as key_file:
        return key_file.read()


def encrypt_credentials(username, password, key_path=None):
    """
    Encrypts username and password using Fernet encryption.

    Args:
        username (str): Plain username.
        password (str): Plain password.
        key_path (str, optional): Existing key file path.

    Returns:
        tuple: (encrypted_username, encrypted_password, key_path)
    """
    if key_path:
        key = load_key(key_path)
    else:
        key_path = generate_key()
        key = load_key(key_path)

    cipher = Fernet(key)

    encrypted_username = cipher.encrypt(username.encode()).decode()
    encrypted_password = cipher.encrypt(password.encode()).decode()

    return encrypted_username, encrypted_password, key_path


def decrypt_credentials(encrypted_username, encrypted_password, key_path):
    """
    Decrypts username and password using Fernet encryption.

    Args:
        encrypted_username (str): Encrypted username.
        encrypted_password (str): Encrypted password.
        key_path (str): Path to key file.

    Returns:
        tuple: (decrypted_username, decrypted_password)
    """
    try:
        key = load_key(key_path)
        cipher = Fernet(key)

        decrypted_username = cipher.decrypt(encrypted_username.encode()).decode()
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()

        return decrypted_username, decrypted_password

    except InvalidToken:
        raise ValueError("Invalid key or corrupted encrypted data.")


def mask_value(value):
    """
    Masks sensitive values except last 2 characters.

    Args:
        value (str): Input string.

    Returns:
        str: Masked string.
    """
    if len(value) <= 2:
        return "**"
    return "*" * (len(value) - 2) + value[-2:]


def print_help_with_examples(parser):
    """
    Prints help message along with examples and explanation.
    """
    parser.print_help()

    print("\n📌 Why CLI arguments?")
    print("This tool is designed for automation and secure handling of credentials.")
    print("Arguments allow usage in scripts, schedulers, and CI/CD pipelines.\n")

    print("📌 Examples:\n")

    print("🔐 Encrypt credentials (generate new key):")
    print("  python encrypt_credentials.py --encrypt --username your-username --password your-password\n")

    print("🔐 Encrypt using existing key:")
    print("  python encrypt_credentials.py --encrypt --username your-username --password your-password --key path/to/key.key\n")

    print("🔓 Decrypt credentials:")
    print("  python encrypt_credentials.py --decrypt --enc_username <encrypted_value> --enc_password <encrypted_value> --key path/to/key.key\n")

    print("🔓 Decrypt and show full values:")
    print("  python encrypt_credentials.py --decrypt --enc_username <encrypted_value> --enc_password <encrypted_value> --key path/to/key.key --show\n")


def main():
    parser = argparse.ArgumentParser(
        description="Credential Encryption Utility using Fernet (symmetric encryption)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--encrypt", action="store_true", help="Encrypt credentials")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt credentials")

    parser.add_argument("--username", help="Plain username")
    parser.add_argument("--password", help="Plain password")

    parser.add_argument("--enc_username", help="Encrypted username")
    parser.add_argument("--enc_password", help="Encrypted password")

    parser.add_argument("--key", help="Path to key file")
    parser.add_argument("--show", action="store_true", help="Show full decrypted output")

    args = parser.parse_args()

    # --- No arguments provided ---
    if len(sys.argv) == 1:
        print_help_with_examples(parser)
        return

    # --- Encrypt ---
    if args.encrypt:
        if not args.username or not args.password:
            print("[-] Username and password are required for encryption.")
            return

        enc_user, enc_pass, key_path = encrypt_credentials(
            args.username, args.password, args.key
        )

        print("\n🔐 Encrypted Credentials:")
        print(f'"username": "{enc_user}",')
        print(f'"password": "{enc_pass}"')
        print(f"\n🔑 Key file: {key_path}")

    # --- Decrypt ---
    elif args.decrypt:
        if not args.enc_username or not args.enc_password or not args.key:
            print("[-] Encrypted values and key path are required for decryption.")
            return

        try:
            dec_user, dec_pass = decrypt_credentials(
                args.enc_username, args.enc_password, args.key
            )

            print("\n🔓 Decrypted Credentials:")

            if args.show:
                print(f"Username: {dec_user}")
                print(f"Password: {dec_pass}")
            else:
                print(f"Username: {mask_value(dec_user)}")
                print(f"Password: {mask_value(dec_pass)}")

        except ValueError as e:
            print(f"[-] {str(e)}")


if __name__ == "__main__":
    main()