# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in vault-sync, please report it privately through GitHub's security advisory feature:

1. Go to the [Security Advisories](https://github.com/alexjbarnes/vault-sync/security/advisories) page
2. Click "Report a vulnerability"
3. Fill in the details

Do not open a public issue for security vulnerabilities.

## What to Report

- Authentication or authorization bypasses
- Credential exposure (tokens, passwords, encryption keys)
- Path traversal or file access outside the vault directory
- Cryptographic weaknesses in the sync protocol implementation
- Denial of service vectors

## Response

Fixes for confirmed vulnerabilities will be released as patch versions.

## Scope

This project is an unofficial third-party client for Obsidian Sync. Vulnerabilities in the Obsidian Sync service itself should be reported to Obsidian directly, not here.
