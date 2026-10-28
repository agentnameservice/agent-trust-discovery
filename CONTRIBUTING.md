# Contributing

Follow the [ANS contribution guide](https://github.com/agentnameservice/governance/blob/main/CONTRIBUTING.md)
and [governance](https://github.com/agentnameservice/governance/blob/main/GOVERNANCE.md).
They define DCO sign-off, pull request review, issue references, and disclosure
of AI assistance.

The [Code of Conduct](CODE_OF_CONDUCT.md) applies to all participation.
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
The repository's [Maintainers](MAINTAINERS.md) handle reviews and releases.

## Development workflow

This is a Go project (see the `go` directive in [`go.mod`](./go.mod) for the
required toolchain version). Common tasks are driven through the
[`Makefile`](./Makefile):

| Command | What it does |
|---------|--------------|
| `make build` | Compile all packages and the four `cmd/` binaries. |
| `make test` | Run the unit tests. |
| `make test-race` | Run the tests with the race detector. |
| `make test-cover` | Run tests and enforce coverage gates (overall ≥ 90%, `internal/domain` = 100%). |
| `make lint` | Run `golangci-lint` (auto-installed, pinned version). |
| `make fmt` / `make vet` | Formatting and `go vet` checks. |
| `make check` | `fmt` + `vet` + `lint` + `test-cover` — run this before opening a PR. |
| `make demo` | Offline, deterministic end-to-end walkthrough. |
| `make demo-live` | Live pipeline against real prod data (real DNS + TLS probes). |

Before submitting a PR, please make sure `make check` passes locally. New code
should include tests, and behavior changes should update the relevant docs
under [`docs/`](./docs).

### Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `ci:`).
Releases and the [CHANGELOG](./CHANGELOG.md) are generated automatically from
these commit types by [release-please](https://github.com/googleapis/release-please),
so a clear, correctly-typed subject line directly shapes the release notes.
