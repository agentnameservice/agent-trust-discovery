# Changelog

## [0.1.3](https://github.com/agentnameservice/agent-trust-discovery/compare/v0.1.2...v0.1.3) (2026-08-13)


### Features

* import RA agent-events feed into trust index pipeline ([#8](https://github.com/agentnameservice/agent-trust-discovery/issues/8)) ([ea5b30f](https://github.com/agentnameservice/agent-trust-discovery/commit/ea5b30f3eca4a721a24f124c1df45204ff7a37da))


### Documentation

* adopt DCO and AI-disclosure contribution policy ([#7](https://github.com/agentnameservice/agent-trust-discovery/issues/7)) ([6ec1034](https://github.com/agentnameservice/agent-trust-discovery/commit/6ec1034d6ce50b44650ef6df0f5c594d7b55fe87))

## [0.1.2](https://github.com/agentnameservice/agent-trust-discovery/compare/v0.1.1...v0.1.2) (2026-07-14)


### Bug Fixes

* **release:** let GoReleaser infer the GitHub owner/name ([#4](https://github.com/agentnameservice/agent-trust-discovery/issues/4)) ([c278968](https://github.com/agentnameservice/agent-trust-discovery/commit/c27896890bba0a4cedb939b07e29d90fb4820367))

## [0.1.1](https://github.com/agentnameservice/agent-trust-discovery/compare/v0.1.0...v0.1.1) (2026-07-13)


### Documentation

* reframe README around Agent Trust Discovery ([#2](https://github.com/agentnameservice/agent-trust-discovery/issues/2)) ([d96bd0e](https://github.com/agentnameservice/agent-trust-discovery/commit/d96bd0e7074dfbf87677948d1418f04db6760868))

## 0.1.0 (2026-07-07)

Initial public release of **agent-trust-discovery**, the Trust Index Reference
Implementation for the [Agent Name Service](https://github.com/agentnameservice/ans).

### Features

* **Read API** — `search` and `detail` endpoints returning the spec-shaped
  Trust Evaluation (trust vector, `recommendedProfile`, risk factors).
* **Admin import API** — atomic, idempotent import of registered agents and
  signal observations.
* **Trust model** — eight built-in signals across two families
  (raw-observation and drift-verdict), two scoring profiles, and the
  `recommendedProfile` cascade.
* **Offline demo** (`make demo`) — deterministic end-to-end walkthrough backed
  by the stub hydrator, with no external dependencies.
* **Live pipeline** (`make demo-live`) — `agent-snapshot` captures a
  Transparency-Log-sourced sealed baseline from prod; `agent-prober` emits real
  DNS + TLS drift observations against it.
* **Storage & transport** — SQLite (FTS5 + WAL) adapter, RFC 7807 problem
  responses, structured `slog` logging, and a bearer-key–gated admin surface.
* **Extension contracts** — pluggable trust signals and evidence sources,
  documented under [`docs/`](docs/).

See the [README](README.md) for the full v1 scope and the items deferred to v2.
