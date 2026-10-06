# Contributing to Round-Robin

Thanks for taking the time to improve **Round-Robin**.

## Before you start

- Search existing issues before opening a new one.
- Keep changes focused; avoid mixing unrelated refactors and feature work.
- Never commit credentials, API keys, private keys, tokens, production hostnames, internal IP ranges, exported vaults, logs, or environment-specific secrets.
- Preserve documented platform support and fail clearly when a feature is unavailable on the current platform.

## Development workflow

1. Fork the repository and create a focused branch.
2. Install the documented requirements.
3. Make the smallest change that solves the problem.
4. Run the repository's build/tests locally when possible.
5. Update documentation when behavior or configuration changes.
6. Open a pull request using the repository template.

## Commit style

Use short, descriptive commits such as:

```text
fix: handle empty hostname safely
feat: add configurable retry interval
docs: clarify Linux support
test: cover secret redaction
```

## Security-related changes

Do **not** open a public issue containing an undisclosed vulnerability, credentials, private infrastructure details, or sensitive logs. Follow `SECURITY.md` instead.

## Pull requests

A good pull request explains:

- what changed;
- why the change is needed;
- how it was tested;
- platform impact;
- security or compatibility impact, if any.

By contributing, you agree that your contribution is licensed under the repository's MIT License.
