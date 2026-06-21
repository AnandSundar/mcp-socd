---
date: 2026-06-20
topic: ai-agent-containment-soc
title: AI-Agent Containment for SOC Teams
---

## Summary

`mcp-socd` is an MCP-aware proxy that mediates AI agent tool calls against a starter SOC-action catalog with CrowdStrike Falcon as the v1 backend. It default-denies destructive verbs, requires out-of-band approval for high-blast-radius actions, and emits OCSF audit records to stdout for SIEM ingestion.

## Problem Frame

Enterprise security teams have AI agents deployed in production that nobody fully trusts. The r/cybersecurity thread "Anyone else losing their mind over this 'AI Cybersecurity' hype?" (976 upvotes) crystallizes the practitioner pain: management bought the marketing hype, threw agents at SOC teams, and those teams are now trying to stop LLMs from accidentally isolating their own domain controllers.

The gap is concrete and at the action-execution layer, not the LLM-output layer. Output guardrails (Guardrails AI, NeMo Guardrails, Lakera) and observability (Langfuse, LangSmith) are saturated. Framework HITL primitives (LangGraph `interrupt()`, Claude Code confirmations) pause but do not enforce policy. OPA, Cedar, and Kyverno enforce generic policy but ship no SOC-action catalog. The ~7 OSS projects in the actual action-guardrail space are all under 500 stars; the largest (Sponsio) is 477.

The harm pattern is consistent across recent incidents: agents taking destructive actions on production because no production-vs-dev boundary was enforced at the action layer. Replit/Lemkin (Jul 2025): agent ignored a code-freeze and deleted a prod DB with 1,200+ executives. Cursor/Claude/PocketOS (Apr 2026): agent deleted a prod DB and volume-level backups in ~9 seconds by chaining an unrelated overprivileged token.

## Key Decisions

**Persona: detection/security engineer running a personal agent against their own SIEM.** Strongest evidence: homelab pattern in `santosomar/AI-agents-for-cybersecurity` (~196 stars), LangGraph+Splunk MCP writeups. CISOs care but do not configure; Tier-1 SOC analysts are downstream beneficiaries once the engineer ships the agent. Building for the operator who feels the pain first.

**Wedge: SOC-action policy catalog plus destructive-action gate.** The gate alone is generic; the catalog with typed parameters, blast-radius scoring, and SIEM-friendly audit shape is where the value compounds. Productizes what practitioners hand-roll today as "LangGraph interrupt + my own policy code."

**Distribution: standalone MCP-aware proxy.** Framework-agnostic; the agent's tool calls route through the proxy with no agent code changes. Matches the egress-proxy pattern already used in the OSS space. Works with LangGraph, Claude Code, OpenAI Agents SDK, and MCP servers.

**MVP backend: CrowdStrike Falcon only.** Faster to first usable artifact than modeling abstract actions. Carbon Black, Sentinel One, and Defender integrations are explicit v1.1 work, not abstractions designed now.

**Posture: default-deny with explicit per-action allowlist.** Matches the failure postmortems; the only posture that catches the rogue-agent failure mode.

**Fail posture: fail-closed for destructive actions, fail-open for read actions.** Defaulted because destructive harm is irreversible and read actions are observable. Flag during planning if different.

**License: Apache-2.0.** De facto standard in this space; all comparable OSS projects (NeMo Guardrails, Guardrails AI, OPA, Kyverno, SPIFFE) are Apache-2.0.

## Actors

- **A1. Detection/security engineer.** Operates the proxy; configures the allowlist; responds to approval requests; ingests audit records into the SIEM.
- **A2. AI agent.** The thing being constrained. Calls tools through the proxy; receives denials or approval-prompt results.
- **A3. MCP-aware proxy (`mcp-socd`).** Mediator. Inspects every tool call against catalog and allowlist; emits audit records; prompts for approval when required.
- **A4. CrowdStrike Falcon backend.** Executes approved actions on the EDR tenant.
- **A5. SIEM destination (Splunk, Elastic, Sentinel).** Ingests OCSF audit records from stdout.
- **A6. Approval channel (Slack DM, terminal prompt).** Human-in-the-loop; records approver identity in audit.
- **A7. EDR tenant.** The protected production environment.

## Key Flows

### F1. Read action through proxy

- **Trigger:** Agent issues `submit_edr_query` with target host and query string.
- **Actors:** A2, A3, A4, A5.
- **Steps:** Agent calls proxy. Proxy matches action to catalog entry. Proxy checks allowlist (engineer has pre-approved this query type). Proxy forwards to CrowdStrike. CrowdStrike returns results. Proxy emits OCSF audit record with `decision=allow`.
- **Covered by:** R1, R2, R4, R5, R9, R11, R14, R15.

### F2. Destructive action blocked by allowlist

- **Trigger:** Agent issues `isolate_endpoint` against a host not on the allowlist.
- **Actors:** A2, A3, A6, A5.
- **Steps:** Agent calls proxy. Proxy matches action to catalog entry. Proxy checks allowlist (no match). Proxy blocks execution. Proxy emits OCSF audit record with `decision=deny` and `reason=allowlist_miss`.
- **Covered by:** R1, R2, R4, R5, R9, R11, R14, R15.

### F3. Destructive action with approval

- **Trigger:** Agent issues `isolate_endpoint` against an allowlisted host.
- **Actors:** A2, A3, A6, A4, A5.
- **Steps:** Agent calls proxy. Proxy matches action to catalog entry. Proxy checks allowlist (match). Proxy identifies destructive-verb pattern. Proxy emits approval prompt to configured channel. Human approves or denies. Proxy forwards approved action to CrowdStrike or returns denial. Proxy emits OCSF audit record with `decision=allow|deny` and approver identity.
- **Covered by:** R1, R2, R4, R5, R7, R8, R9, R11, R12, R13, R14, R15.

### F4. Allowlist configuration

- **Trigger:** Detection engineer updates allowlist configuration.
- **Actors:** A1, A3.
- **Steps:** Engineer writes new allowlist. Proxy hot-reloads. Subsequent tool calls evaluated against new allowlist. No audit emitted (config change, not an action).
- **Covered by:** R2.

### F5. Proxy failure during destructive action

- **Trigger:** Proxy itself errors (network timeout, config corruption, backend unreachable) while evaluating a destructive action.
- **Actors:** A2, A3, A5.
- **Steps:** Proxy errors. Proxy fails closed. Action not executed. Proxy emits OCSF audit record with `decision=error` and `reason=fail_closed`. Agent receives error response.
- **Covered by:** R3, R14, R15.

## Requirements

### Configuration and Posture

- **R1.** The proxy default-denies every tool call whose action type and target are not explicitly allowlisted.
- **R2.** The proxy supports per-action allowlists keyed by action type and target, configurable without recompilation and hot-reloadable.
- **R3.** When the proxy itself errors during tool-call evaluation, it fails closed for destructive actions and fails open for read actions.

### Catalog

- **R4.** The proxy ships with a starter SOC-action catalog covering `isolate_endpoint`, `block_user_account`, `rotate_api_key`, `submit_edr_query`, and `enrich_ioc`.
- **R5.** Each catalog action declares typed parameters, a blast-radius score, and an OCSF-shaped audit record.
- **R6.** The catalog is extensible through configuration; adding or modifying actions does not require recompilation.

### Destructive-Verb Gate

- **R7.** The proxy intercepts destructive verbs (`delete`, `drop`, `truncate`, `revoke`, `disable`) regardless of catalog membership.
- **R8.** A destructive-verb interception requires out-of-band approval through a configured channel before execution.

### MCP Integration

- **R9.** The proxy functions as an MCP-aware proxy mediating tool calls between an agent and MCP servers.
- **R10.** The proxy works with LangGraph, Claude Code, OpenAI Agents SDK, and MCP servers without agent code modification.

### Backend Integration (v1)

- **R11.** The proxy integrates with CrowdStrike Falcon as the v1 backend for `isolate_endpoint`, `block_user_account`, and `submit_edr_query`.

### Approval Workflow

- **R12.** The proxy supports terminal prompt and Slack DM as approval channels for v1.
- **R13.** The approval workflow records the approver's identity and the approval timestamp in the OCSF audit record.

### Audit

- **R14.** The proxy emits audit records as JSON-lines to stdout in OCSF format.
- **R15.** Each audit record includes agent identity, action type, parameters, blast-radius score, decision, approver identity when applicable, and timestamp.

## Acceptance Examples

### AE1. Read action with allowlist match

- **Covers:** R1, R2, R4, R9, R11, R14, R15.
- **Given** the engineer has allowlisted `submit_edr_query` against host `*.example.com`,
- **When** the agent issues `submit_edr_query` with target `server01.example.com`,
- **Then** the proxy forwards the call to CrowdStrike, returns the result, and emits an OCSF audit record with `decision=allow`, `action=submit_edr_query`, and `target=server01.example.com`.

### AE2. Read action with allowlist miss

- **Covers:** R1, R2, R4, R9, R14, R15.
- **Given** the engineer has allowlisted `submit_edr_query` against host `*.example.com`,
- **When** the agent issues `submit_edr_query` with target `server02.other.org`,
- **Then** the proxy returns a denial to the agent and emits an OCSF audit record with `decision=deny` and `reason=allowlist_miss`.

### AE3. Destructive action with allowlist match and approval

- **Covers:** R2, R4, R5, R7, R8, R9, R11, R12, R13, R14, R15.
- **Given** the engineer has allowlisted `isolate_endpoint` against host `server99.example.com` and configured Slack DM as the approval channel,
- **When** the agent issues `isolate_endpoint` with target `server99.example.com`,
- **Then** the proxy emits a Slack approval prompt to the configured operator; on approval, forwards the call to CrowdStrike and emits an audit record with `decision=allow`, `approver=<slack_user_id>`, and `approval_timestamp=<ISO8601>`; on denial, returns the denial and emits an audit record with `decision=deny` and `approver=<slack_user_id>`.

### AE4. Destructive-verb gate triggered outside catalog

- **Covers:** R7, R8.
- **Given** a custom MCP tool emits a tool call with verb `truncate_table` not in the starter catalog,
- **When** the agent issues the call,
- **Then** the proxy's destructive-verb gate intercepts the call regardless of catalog membership, prompts for approval, and on approval forwards to the underlying MCP server or on denial returns a denial.

### AE5. Proxy fails-closed on destructive action

- **Covers:** R3, R14, R15.
- **Given** the proxy's CrowdStrike client times out while evaluating an `isolate_endpoint` call,
- **When** the timeout occurs,
- **Then** the proxy fails closed, the action is not executed, the agent receives an error response, and the proxy emits an OCSF audit record with `decision=error` and `reason=fail_closed`.

### AE6. Proxy fails-open on read action

- **Covers:** R3, R14, R15.
- **Given** the proxy's CrowdStrike client times out while evaluating a `submit_edr_query` call,
- **When** the timeout occurs,
- **Then** the proxy logs the error, attempts to forward the call in degraded mode, the agent receives either a result or a degraded error, and the proxy emits an OCSF audit record with `decision=error` and `reason=fail_open`.

## Success Criteria

- **SC1.** A detection/security engineer can install and configure the proxy against a CrowdStrike Falcon tenant in under 15 minutes following the README.
- **SC2.** The proxy blocks and audits every destructive action whose target is not on the allowlist without exception.
- **SC3.** The proxy emits audit records that Splunk, Elastic, and Sentinel ingest without custom parsing.
- **SC4.** The proxy integrates with LangGraph, Claude Code, and OpenAI Agents SDK without agent code modification, demonstrated by an integration test in each framework.
- **SC5.** The catalog includes at least five typed SOC actions with declared blast-radius scores and OCSF audit shapes at v1.

## Scope Boundaries

### Deferred for later

- **Carbon Black, Sentinel One, Defender integrations.** Explicit v1.1 work once the CrowdStrike integration proves the abstraction.
- **Agent-identity attestation (SPIFFE bridge).** Mints short-lived identities for agents bound to a human principal. Real need but separate surface; would expand scope significantly.
- **K8s-native controller / admission webhook.** Kyverno-style runtime story. Many SOC agents are not K8s-resident; v1 covers the homelab and direct-deployment case.
- **PagerDuty approval channel.** v1.1 once Slack workflow is proven.
- **Multi-agent orchestration.** Single-agent proxy model only.
- **Policy engine adapter mode (OPA, Cedar, OpenFGA packages).** Wires existing policy engines to SOC actions. Lower build cost but lower differentiation.

### Outside this product's identity

- **LLM-output guardrails.** Lakera, Guardrails AI, NeMo Guardrails territory. We do not inspect model output; we mediate tool-call execution.
- **LLM observability.** Langfuse, LangSmith, Helicone territory. We emit audit records but do not trace prompt chains or evaluate outputs.
- **SOAR workflow builder.** Tines, XSOAR, Torq territory. We constrain tool calls; we do not orchestrate multi-step investigations.
- **Agent framework itself.** LangGraph, AutoGen, CrewAI, Claude Code territory. We sit beside the framework as a proxy, not inside it.

## Dependencies / Assumptions

- The MCP protocol continues to be the dominant agent-tool interface through 2026.
- CrowdStrike Falcon APIs remain stable and accessible via OAuth client credentials or API key.
- Detection engineers are comfortable running single-binary proxies from CLI on macOS, Linux, or WSL.
- OCSF v1.x or later is a viable target for SIEM ingestion; the format remains stable.
- Slack workspace tokens are obtainable by individual security engineers for personal-use installations.
- The action catalog's typed parameters and blast-radius scores map cleanly to CrowdStrike API semantics without lossy translation.

## Outstanding Questions

### Resolve Before Planning

- None. The blocking questions are resolved.

### Deferred to Planning

- Language choice (Go, Rust, or Python) — performance vs. ecosystem vs. iteration speed.
- Repo name and namespace (`mcp-socd` is a working placeholder).
- Specific OCSF event class for each catalog action.
- Approval SLA defaults (how long to wait for a human response before timing out).
- Audit retention policy (the proxy emits; downstream SIEM owns retention).
- Configuration file format (YAML, TOML, or JSON).
- Hot-reload mechanism for the allowlist (file watcher vs. signal vs. API endpoint).

## Sources / Research

- r/cybersecurity thread "Anyone else losing their mind over this 'AI Cybersecurity' hype?" — https://reddit.com/r/cybersecurity/comments/1tmwjoj (cited from user prompt; could not fetch directly during this session)
- `santosomar/AI-agents-for-cybersecurity` — practitioner SOC-agent homelab pattern — https://github.com/santosomar/AI-agents-for-cybersecurity
- GitHub topic `agent-guardrails` — OSS landscape survey — https://github.com/topics/agent-guardrails
- LangGraph `interrupt()` docs — confirms state-saver and execution-pauser only, no built-in policy engine — https://docs.langchain.com/oss/python/langgraph/interrupts
- Replit / Jason Lemkin production database deletion (July 2025) — agent ignored code-freeze, deleted 1,200+ executives record
- Cursor / Claude / PocketOS production database deletion (April 2026) — agent deleted prod DB and volume-level backups in ~9 seconds via overprivileged token chain
- Trend Micro, "Unveiling AI Agent Vulnerabilities: Data Exfiltration" — confirms prompt-injection class failures remain open
- Tines Human-led / Deterministic / Agentic workflow classification — referenced for approval-channel design — https://www.tines.com/
- SPIFFE / SPIRE — production identity layer with no documented AI-agent use case — https://spiffe.io/
- OPA / Rego, Cedar, OpenFGA, Kyverno — generic policy engines; none ship a SOC-action catalog
- Lakera, Protect AI (Layer/Guardian/Recon), Cisco AI Defense — output-side guardrails, not action-side
- Verified as of June 2026.