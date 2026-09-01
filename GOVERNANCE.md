# Governance

## Levels of Involvement

### Contributor
Anyone who contributes — pull requests, issue triage, docs, review, or
discussion — is a contributor. All contributions follow
[CONTRIBUTING.md](./CONTRIBUTING.md), including the DCO sign-off and
AI-assistance disclosure.

### Maintainer
Maintainers have commit (merge) access, exercised from within the project's
merge gates — they hold no ruleset bypass. They review, approve, and merge PRs
through the merge queue; triage and close issues that are duplicates, not
reproducible, or out of scope; and shepherd releases by approving the automated
release-please PR. Maintainers uphold DCO sign-off, verified commit signatures,
and AI-assistance disclosure on every change.

Maintainers may be internal or external contributors — this is a
multi-stakeholder project and external maintainers are welcome.

**Becoming a maintainer.** The path is a sustained record of high-quality
contributions and sound review judgment: land PRs, triage issues, and review
others' changes over time. An existing maintainer then nominates you in the
open (an issue or [Discussion]); you are added by lazy consensus of the current
maintainers over a **2-week** window (silence is assent). New maintainers
typically start with triage and review before merge rights. The current roster
is the [agent-trust-discovery maintainers team][maintainers].

**Stepping down / inactivity.** Maintainers may move to emeritus at any time;
prolonged inactivity or a Code of Conduct breach may lead to removal by
consensus of the remaining maintainers.

### Code Owner
A code owner is a maintainer who stewards the project's core: the scoring engine
(`internal/scoring/**`), the signal contract (`internal/port/`), and the spec
(`spec/**`). Code owners are expected to review PRs in these areas and hold veto
power over breaking changes or major refactors to them. Changes to core paths
require a code owner's approval even when another maintainer has reviewed. Code
owners are a small group by design and are listed in
[.github/CODEOWNERS](./.github/CODEOWNERS).

## Consensus-seeking
Different changes need different levels of consensus. Small PRs merge on the
required approval (one, squash-only; a change not attributed to its submitter
requires an extra approval). For a major design addition or refactor, open a
[Discussion] first and allow a few days for feedback and buy-in before investing
in a PR. For a change to a core area, tag at least one code owner. Silence over
the review window is treated as approval; in rare irresolvable disagreement,
maintainers may hold a majority vote.

[maintainers]: https://github.com/orgs/agentnameservice/teams/agent-trust-discovery-maintainers
[Discussion]: https://github.com/agentnameservice/agent-trust-discovery/discussions
