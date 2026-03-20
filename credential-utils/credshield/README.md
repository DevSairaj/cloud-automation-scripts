# CredShield

A lightweight CLI utility to securely encrypt and decrypt credentials using **Fernet symmetric encryption (AES-based)**.

## Usage

Encrypt credentials:

```bash
python credshield.py --encrypt --username your-username --password your-password
```

Decrypt credentials:

```bash
python credshield.py --decrypt --enc_username <value> --enc_password <value> --key path/to/key.key
```

## Arguments

* `--encrypt` : Encrypt username and password
* `--decrypt` : Decrypt credentials
* `--username` : Plain username
* `--password` : Plain password
* `--enc_username` : Encrypted username
* `--enc_password` : Encrypted password
* `--key` : Path to encryption key
* `--show` : Display full decrypted values (otherwise masked)

## Notes

* Uses secure Fernet encryption from the `cryptography` library
* Generates and stores keys locally
* Supports key reuse for consistent encryption/decryption
* Designed for automation and secure configuration handling
