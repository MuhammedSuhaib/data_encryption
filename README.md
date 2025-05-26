# Secure Data Encryption System

This project is a simple web application for securely storing and retrieving encrypted data using passkeys. It uses [Streamlit](https://streamlit.io/) for the user interface and [cryptography](https://cryptography.io/) for encryption.

## Features

- **Encrypt and store data** with a user-defined passkey.
- **Retrieve and decrypt data** using the correct passkey.
- **Hashing** is used for passkey verification.
- **Brute-force protection**: After 3 failed attempts, reauthorization is required.

## How it works

- Data is encrypted using a symmetric key (Fernet).
- The passkey is hashed and stored alongside the encrypted data.
- To retrieve data, the correct passkey must be provided.


