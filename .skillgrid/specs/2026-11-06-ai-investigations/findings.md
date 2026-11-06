# Findings — ai-investigations

## Research: How should KubeDash offer AI investigations (an agent diagnosing the cluster through the dashboard), given ADR-0020 air-gap, in-cluster deployment, and multi-cluster?

> **Decision this serves:** Scoping the "AI investigations" feature — where
> the agent runs, how it authenticates to the dashboard, how runs are
> isolated, how results and fix-approvals are presented. Input to a future
> ADR + briefing. Depends on the `2026-11-06-mcp-server` spec (an
> investigation consumes the read-only MCP surface).
>
> **Type:** technical + competitive
> **Mode:** research (single pass)
> **Date:** 2026-11-06 · **Status:** complete

## Executive Summary

Radar runs the user's **own agent CLI** (Claude Code, Codex, Cursor,
OpenCode) on the machine that runs Radar, against a **read-only internal
MCP endpoint**, with the user's own agent account — "Radar needs no API key
of its own" [1]. Every investigation ends on one Findings page "with the
evidence behind each claim"; a fix is applied only when the user approves
it, and only from the investigation of the resource it changes [1]. Radar's
stated constraints — "a supported agent CLI on the machine running Radar,
MCP on, and authentication off. In-cluster installs don't run them" [1] —
mark exactly the composition problem KubeDash must solve (OIDC always on,
in-cluster always, air-gap). The air-gap-compatible shape: agent on the
user's laptop (egress there), dashboard in-cluster serving MCP (no egress)
[3].

Findings that drive the decision:

1. **The agent is the user's, the account is the user's** — no product
   API key, no model cost to the vendor; the vendor provides evidence +
   orchestration + approval UX [1].
2. **Isolation is profiled, and the weak profile is labeled** — "Radar
   safeguards" (agent's other MCP servers + writes shut off) vs "Your agent
   setup" (unconstrained; Cursor/OpenCode auto-approve tool requests
   without asking) [1][2].
3. **The output contract is mechanical** — a "story contract" JSON block
   separates the agent's evidence ledger from the human-facing story, so a
   quoted patch is never mistaken for the verdict [2].

Biggest caveat: Radar has never run investigations in-cluster; every
in-cluster-specific question for KubeDash (agent host, auth, egress) is
unproven at the vendor [1].

## Findings

### Radar's investigation architecture (verified in [1][2])

- Entry points: **Investigate** action on a resource or issue; the AI
  investigations page (describe what you're seeing: where to start, since
  when, optionally the resource); terminal against a running Radar:
  `radar diagnose deploy/checkout -n shop` (`--json` for machine output)
  [1].
- "Radar's investigation tools can only read the cluster" — investigations
  use an internal read-only MCP endpoint (`/mcp-investigation`) that keeps
  read-only tools + evidence correlation even when `/mcp` is off [2].
- Supported agent CLIs: Claude Code, Codex, Cursor, OpenCode — "on your
  machine and signed in with your own account" [1].
- Constraints: "Investigations need a supported agent CLI on the machine
  running Radar, MCP on, and authentication off. In-cluster installs don't
  run them." [1]

### Isolation model (verified in [1][2])

- **Radar safeguards** (Claude Code and Codex only): "shuts off the agent's
  other MCP servers and its ability to write" [1].
- **Your agent setup** (the only option for Cursor and OpenCode): runs the
  agent "with its normal configuration, tools, and MCP servers, which Radar
  cannot constrain and which may be able to change your cluster. Cursor and
  OpenCode approve tool requests automatically in these runs, without
  asking." [1]
- OpenCode runs with `--auto`: "permission requests are approved
  automatically, including those from built-in tools and configured MCP
  servers; explicit denials still apply. … Radar cannot authenticate write
  results and reports the Apply outcome as uncertain until current-state
  verification." [2]

### Output contract (verified in [1][2])

- "Every investigation ends on the same Findings page, with the evidence
  behind each claim." [1]
- **Story contract** (mechanical, not prompt-only): "The last fenced `json`
  block in the reply that carries a verdict field (`summary`, `root_cause`,
  `healthy`, `inconclusive`, `steps`, `evidence` or `remediation`) is the
  verdict and a divider, so a patch or spec quoted in a `json` fence inside
  the story is never mistaken for it: prose after it is the story
  (`report`), prose before it the agent's evidence ledger (`notes`, kept in
  Activity and never shown in Findings)." [2]
- Incomplete-quote repair: a block that fails to parse only because of
  unescaped quotes inside a string value "is repaired once" [2].

### Apply flow (verified in [1][2])

- "Radar applies a fix only when you approve it, from an investigation of
  the resource it changes." [1]
- Apply is a **separate write-enabled session**, then the original
  read-only session resumes to verify the result [2].
- In `--mcp-read-only` mode, "Built-in investigations and verification
  remain available; their Apply action is unavailable because it requires
  MCP write tools." [2]

### Data-leak framing (verified in [1])

- "An AI agent you connect sends what it reads to its own model provider"
  — stated in the product's privacy section, not a footnote [1].

### Mapping to KubeDash (this repo, [3])

- **Air-gap (ADR-0020):** the dashboard must stay egress-free. The
  laptop-agent + in-cluster-MCP shape satisfies it: egress is the user's
  machine/provider, not the cluster. This inverts Radar's local mode (agent
  on the same host as the dashboard) but keeps its property (no product API
  key, no vendor model traffic).
- **Auth (ADR-0025):** KubeDash sessions are HttpOnly cookies
  (`kd_access` + `kd_refresh`); `Authorization: Bearer` is accepted only for
  the kubectl credential plugin [3]. An agent CLI cannot use browser
  cookies — investigations need a machine-readable credential (short-lived
  scoped token) for the MCP endpoint. This is an auth-flow change →
  ADR-gated.
- **Agent host options:** (a) user's laptop — new `kubedash` CLI subcommand
  (the Go CLI exists as a credential plugin [3]) that runs the agent CLI
  against the in-cluster dashboard's MCP endpoint; (b) leader replica —
  agent CLI inside the container (Radar's container is Go; KubeDash's is
  Python — agent CLIs are Node-based, a substantial container/runtime
  change) and egress to the model provider violates ADR-0020 unless the
  model is local; (c) user-triggered Job. Radar's precedent is (a) in local
  mode only; in-cluster is unhandled [1].
- **Multi-cluster:** an investigation targets one cluster; the UI must
  select it and the run's MCP endpoint must be cluster-scoped (ties to the
  mcp-server spec's open question Q1).
- **Persistence/audit:** radar keeps the evidence ledger in Activity per
  run [2]; KubeDash would likely persist investigations (PG) for team
  visibility — a decision, not a constraint.

## Cross-Dimension Insights

- Radar deliberately keeps the model relationship out of the product (user's
  account, user's provider) — this is what makes the feature shippable
  under an air-gap constraint and worth copying for KubeDash.
- The weakest isolation profile (Cursor/OpenCode auto-approve, unconstrained
  setup) is not hidden; it is documented as a user choice with its
  consequences. KubeDash should define its profiles the same way, per
  supported CLI.
- The story contract (last verdict-field JSON block) is a cheap, robust way
  to get structured findings from any agent CLI without a vendor SDK —
  KubeDash's findings renderer can depend on this one convention.

## Contrary Evidence

- In-cluster agent execution (option b) would give the "one machine, one
  process" simplicity of Radar but collides with ADR-0020 (model egress)
  and the container runtime (Node-based agent CLIs in a Python image) —
  both are real costs, not hypotheticals [1][3].
- Vendor isolation guarantees are per-CLI and change with CLI versions
  (Radar documents Claude Code's server-instruction truncation version
  cutoffs, e.g. "2,048 before v2.1.296" [2]) — isolation is a moving target
  that must be re-verified per release.

## Recommendations

1. **v1 shape: laptop agent + in-cluster read-only MCP** — option (a) above;
   keep the dashboard egress-free (ADR-0020). Confidence: high (only shape
   that satisfies air-gap + vendor precedent [1][3]).
2. **Adopt the story contract** (last verdict-field JSON block; notes vs
   report split) as KubeDash's investigation output convention.
   Confidence: high (mechanical, verifiable [2]).
3. **Ship read-only investigations first; Apply as a separate
   write-enabled session with human approval**, gated on the same SAR
   boundaries as the REST API. Confidence: high [1][2].
4. **Name the isolation profiles explicitly in the UI** (safeguards vs
   user-setup) and document auto-approve behavior per CLI. Confidence: high
   (pattern verified in [1]).
5. **State the data-leak fact in docs** ("what the agent reads goes to your
   model provider") next to the feature, not in a footnote. Confidence:
   medium (good practice, not a hard requirement).

## Open Questions

1. **Agent host** — laptop CLI (a) vs in-cluster (b/c); (b) needs an
   ADR-level look at ADR-0020 + container runtime.
2. **Agent credential** — token shape, lifetime, scope (read-only
   investigation tools only), revocation; extends ADR-0025's Bearer
   allowance (currently kubectl-plugin-only [3]).
3. **Which agent CLIs in v1** — each has different isolation guarantees;
   Cursor/OpenCode auto-approve [1]. A subset (Claude Code + Codex) gives
   the strongest safeguards story.
4. **Multi-cluster targeting** — cluster selection UX + per-cluster MCP
   scoping (shared with the mcp-server spec Q1).
5. **Persistence** — persist investigation runs (PG) for team visibility /
   audit? Radar keeps per-run Activity only [2].
6. **Investigation-only MCP surface** — does v1 need the full `/mcp` or
   only a `/mcp-investigation` equivalent (read-only + evidence
   correlation) [2]?

## Source Appendix

| [n] | Claim/finding it supports | Publisher | Pub date | Accessed | Confidence |
|-----|---------------------------|-----------|----------|----------|------------|
| [1] | Investigation entry points, supported CLIs, isolation profiles, apply-on-approval, constraints (auth off, local only), no-product-API-key, data-leak framing | [skyhook-io/radar README (main)](https://github.com/skyhook-io/radar) | main; releases through v1.18.3 (2026-10-28) | 2026-11-06 | high (primary) |
| [2] | `/mcp-investigation` endpoint, story contract, Apply session semantics, OpenCode `--auto` behavior, server-instruction truncation versions | [radar docs/mcp.md (main)](https://raw.githubusercontent.com/skyhook-io/radar/main/docs/mcp.md) | main | 2026-11-06 | high (primary; investigation-relevant sections read in full) |
| [3] | KubeDash constraints: ADR-0020 (air-gap), ADR-0025 (HttpOnly cookie sessions; Bearer kubectl-plugin-only), ADR-0006 (single container), Go CLI as kubectl credential plugin | [kubedash AGENTS.md + .skillgrid/knowledge/ASSUMPTIONS.md](../../../../AGENTS.md) | this repo | 2026-11-06 | high (repo) |
