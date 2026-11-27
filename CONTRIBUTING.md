# Contributing

Issues and pull requests are welcome. For anything larger than a small fix, open an issue first so we can agree on the approach.

## Development

You need Go 1.26 or later.

```sh
make test     # run tests with the race detector
make lint     # go vet and golangci-lint
make build    # build ./bin/keysec
```

Tests use an in-memory keychain and never touch your real one.

## Layout

```
cmd/keysec          entry point
internal/cli        command line parsing and output
internal/broker     the operations that use secret values; enforces policy
internal/store      keychain and index file
internal/request    host-checked HTTP requests
internal/runner     running commands with secrets in the environment
internal/redact     replacing values in output
internal/mcpserver  MCP tools
internal/hook       Claude Code PreToolUse hook
internal/setup      registering with agents
internal/detect     recognizing key formats
internal/dotenv     .env parsing
internal/envsync    planning what a .env re-import changes
internal/push       provider CLI commands
```

Anything that reads a secret value should go through `internal/broker`, so policy checks and redaction live in one place.

## Adding a key format

Add a rule to `internal/detect/detect.go` with the provider's documented prefix, API host and auth style, and a case in `detect_test.go`. Only add formats with a documented, distinctive prefix.

## Guidelines

- Keep dependencies to a minimum.
- Never print, log or return a secret value, including in error messages.
- Use obviously fake values in tests. Strings that look like real keys trip secret scanners.
- Run `gofmt` and keep `make lint` clean.
