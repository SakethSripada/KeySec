# Security

## What keysec protects against

- **Secrets in transcripts.** Agents never receive values. Output from `run_command`, `http_request` and `push_secret` is redacted, including base64, hex and URL-encoded forms of each value.
- **Secrets in files.** `keysec import` moves `.env` values into the keychain so they are not left in plaintext in the repository.
- **Accidental reads.** The Claude Code hook blocks common ways of reading secrets directly: `cat .env`, `source .env`, `printenv`, `security find-generic-password` and similar.
- **Sending a key to the wrong place.** `http_request` only sends a secret to its allowed hosts, over HTTPS, and does not follow redirects. This limits what a prompt injection can do with an HTTP-only secret.
- **An agent widening its own access.** Policies are stored in the keychain, not in the editable index file. Changing a policy, replacing a value or deleting a secret requires confirmation on the controlling terminal, which an agent's shell does not have.

## What it does not protect against

- **A secret allowed in `run`.** A command that has a value in its environment can do anything with it, including sending it somewhere. Redaction covers common encodings, not arbitrary transformations. Turn `run` off (`keysec policy NAME --no-run`) for secrets that only need to reach one API, and consider Claude Code's sandbox to restrict network access for shell commands.
- **A determined agent with shell access.** The hook matches commands with simple patterns. It stops accidents and casual attempts, not an agent working to get around it. On macOS, keychain entries are written through `/usr/bin/security`, so any process running as your user can read them with that tool without a prompt.
- **Malware running as your user.** keysec relies on your OS account and keychain for protection, like every other local secret store.
- **What the remote API does.** If an allowed host echoes a request back or logs it, the value goes wherever that goes.

## Reporting a vulnerability

Please report security issues privately through [GitHub security advisories](https://github.com/sakethsripada/keysec/security/advisories/new) rather than in a public issue. You should get a response within a few days.
