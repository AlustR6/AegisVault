# Aegis Vault

A command-line password vault I built in C++20 to practice cryptography, secure memory handling, and systems programming. Credentials are stored locally in an encrypted `.avlt` file.

## Features

- Create and unlock vaults with a master password
- Add, view, update, list, and delete credentials
- Derive encryption keys with **Argon2id**
- Encrypt each credential independently with **XChaCha20-Poly1305**
- Keep account names in an encrypted catalog; use **BLAKE2b** hashes to check record integrity
- Handle sensitive data with custom `SecureBuffer` and `SecureText` classes
- Validate a versioned binary file format and save changes through temporary-file replacement

## Tech Stack

C++20 · libsodium · CMake · vcpkg · GoogleTest · Windows API

## Build

Requires Windows, Visual Studio with C++/CMake support, and vcpkg. Open the project folder in Visual Studio, configure the CMake project, and build the `aegis_vault` target. Dependencies are declared in `vcpkg.json`.

## Usage

From the directory containing `aegis_vault.exe`:

```powershell
.\aegis_vault.exe init passwords.avlt
.\aegis_vault.exe unlock passwords.avlt
```

Once unlocked, use `help` to see the available commands: `add`, `get`, `list`, `update`, `rm`, `lock`, and `exit`.

## Tests

Unit and integration tests use GoogleTest. Run `aegis_tests.exe` or use CTest from your configured build directory.

## Security Notes

This is a portfolio project, not an independently audited password manager. It does not protect against malware on an unlocked machine, rollback to an older valid vault file, or concurrent writers. Use test credentials rather than relying on it for important accounts.