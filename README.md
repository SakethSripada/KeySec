# keysec

keysec lets Claude Code, Codex and Cursor use your API keys without seeing them.

Agents see each secret's name, description, provider and where it may be sent. When an agent calls an API, runs your tests or deploys, keysec adds the value itself and replaces it with `[keysec:NAME]` in anything that comes back. Values stay in your OS keychain and never leave your machine except in the requests you allow.

## Install

```sh
go install github.com/sakethsripada/keysec/cmd/keysec@latest
```

Or download a binary from [Releases](https://github.com/sakethsripada/keysec/releases):

```sh
curl -fsSL https://raw.githubusercontent.com/sakethsripada/keysec/main/install.sh | sh
```

Then register it with your agents:

```sh
keysec init
```

This adds keysec as an MCP server to Claude Code, Codex and Cursor (whichever are installed) and adds a Claude Code hook that stops the agent from reading `.env` files or the keychain directly. `keysec init --remove` undoes it.

## Add secrets

```sh
keysec add STRIPE_SECRET_KEY          # prompts for the value, input hidden
pbpaste | keysec add OPENAI_API_KEY   # or pipe it in
keysec import .env                    # or bring in an existing file
```

keysec recognizes common key formats and fills in a description, provider and allowed hosts:

```
$ keysec list
NAME               PROVIDER   MODE  HOSTS             DESCRIPTION
OPENAI_API_KEY     openai     -     api.openai.com    OpenAI project API key
STRIPE_SECRET_KEY  stripe     live  api.stripe.com    Stripe secret key
```

Add anything it could not guess:

```sh
keysec edit STRIPE_SECRET_KEY -d "Acme production account" --scope charges:write
```

## What agents can do

Over MCP, agents get five tools:

| Tool | What it does |
| --- | --- |
| `list_secrets`, `describe_secret` | Read names, descriptions, scopes and policies. Never values. |
| `http_request` | Call an API with a secret attached. Only the secret's allowed hosts are reachable. |
| `run_command` | Run a command with secrets as environment variables. Output is redacted. |
| `push_secret` | Copy a secret into GitHub Actions, Vercel, Fly or Cloudflare via their CLIs. |

The same operations are available from the shell:

```sh
keysec run -s STRIPE_SECRET_KEY -- npm test
keysec request STRIPE_SECRET_KEY https://api.stripe.com/v1/balance
keysec push STRIPE_SECRET_KEY vercel --env production
```

## Policy

Each secret has a policy, stored in the keychain next to its value:

- **hosts**: where `http_request` may send it. `*.example.com` matches subdomains. HTTPS only, except for localhost.
- **auth**: how it is attached: `bearer` (default), `basic`, `header:NAME`, `query:PARAM`, or `none` to place it yourself with `{{NAME}}` in the URL, a header or the body.
- **run**: whether it may be put in a command's environment. Turn this off for keys that should only ever go to one API.

```sh
keysec policy STRIPE_SECRET_KEY --host api.stripe.com --no-run
```

Replacing a secret, changing its policy and deleting it ask for confirmation on your terminal. An agent's shell has no terminal, so it cannot make these changes on its own.

## Security

keysec keeps secrets out of agent transcripts, logs, commits and model provider servers, and limits where an agent can send them. It does not make it impossible for an agent with shell access to misuse a secret that is allowed in `run`. Read [SECURITY.md](SECURITY.md) for exactly what is and is not covered.

## Where things live

| What | Where |
| --- | --- |
| Values and policies | OS keychain, service `keysec` |
| Descriptions | `~/.config/keysec/secrets.toml` (override with `KEYSEC_HOME`) |

keysec has no daemon. Agents start `keysec mcp` when they need it.

## Platforms

macOS and Linux (with a Secret Service provider such as GNOME Keyring). Windows builds but is untested, and `run_command` needs `sh`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
