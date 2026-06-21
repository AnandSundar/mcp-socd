---
title: mcp-socd — default-deny for AI agents in production
duration_seconds: 80
aspect_ratios:
  - 9x16   # X / TikTok / Shorts / Reels
  - 16x9   # YouTube / web embed / README hero
format: kinetic-typography + terminal-screenshots
audio: silent — captions carry every beat
font: monospace (JetBrains Mono or system mono)
palette:
  background: "#0a0a0a"
  text:       "#fafafa"
  destructive: "#ff4d4d"   # red — deny, blast, isolate
  safe:        "#4ade80"   # green — allow, pass
  pending:     "#facc15"   # yellow — awaiting approval
  muted:       "#71717a"   # gray — neutral copy
motion:
  default: "typewriter, 60ms per character"
  emphasis: "scale pulse 1.0 → 1.15 → 1.0 over 200ms"
  emphasis_color: matches semantic role (destructive/safe/pending)
captions:
  position: lower-third, large, white on black 70% plate
  safe_area: 8% margin all sides
  max_words_per_beat: 8
target_audience: SOC engineers, detection engineers, security leads
tone: terse, technical, practitioner-to-practitioner; no marketing fluff
---

# Scenes

## Scene 1 — Hook (0:00–0:05)

**Direction:** Hard cut to black. Centered. One sentence types in.
Hold for a beat, then the destructive verb flashes red and stays.

**Caption:**

> Your AI agent just isolated a domain controller.

**Kinetic:**

- "isolated" — typewriter, then `emphasis_color: destructive` pulse,
  holds red for the rest of the scene.

## Scene 2 — The actual failure (0:05–0:15)

**Direction:** Three beats, each a separate line that replaces the
previous. Each beat is one destructive capability an agent has had
in production somewhere. White text on black.

**Captions (in order, hard cuts):**

> 1. Agents in production. Acting on credentials.
>
> 2. No production vs. dev boundary at the action layer.
>
> 3. Output guardrails don't stop the tool call. Observability is post-hoc.

**Kinetic:**

- Beat 1: lines pop in left-aligned, top-down.
- Beat 2: second line replaces first. "production vs. dev" highlighted `muted` then `text`.
- Beat 3: third line replaces second. "Output guardrails" and "Observability" both `muted` and slightly de-saturated — the visual cue is that these solutions don't reach the action.

## Scene 3 — The gap (0:15–0:28)

**Direction:** Centered. Single sentence stacks across two lines.
Underline animates in under the key phrase.

**Captions:**

> The gap is at the action layer.
>
> No SOC-action catalog. No typed policy. No audit shape for SIEM.

**Kinetic:**

- "action layer" — typewriter, then `emphasis_color: destructive` pulse.
- Second line: "SOC-action catalog", "typed policy", "audit shape" each pop in sequentially, 200ms apart, white-on-black, no color (deliberate — they're the things missing).

## Scene 4 — Introducing mcp-socd (0:28–0:45)

**Direction:** Logo / wordmark snap-in. Then a one-line tagline.
Then a 3-bullet list of what it is. Fast.

**Captions:**

> **mcp-socd**
>
> default-deny for AI agents.
>
> - stdio proxy between agent and MCP server
> - action-layer enforcement, not output
> - one static binary, framework-agnostic

**Kinetic:**

- "mcp-socd" — scale-in from 0.5× to 1.0× over 400ms.
- "default-deny" — `emphasis_color: safe` pulse (green — the protective primitive).
- Bullets — pop in top-down, 250ms apart.

## Scene 5 — The four primitives (0:45–1:05)

**Direction:** Two-column grid. Four cards. Each card pops in
sequentially and stays. Each card is one word + one line.

**Captions:**

> | **catalog** | typed actions, blast radius, OCSF audit shape |
> | --- | --- |
> | **policy** | allowlist, default-deny, destructive-verb gate |
> | **audit** | OCSF Detection Finding (UID 2004) to JSON-lines |
> | **approval** | out-of-band; terminal prompt or Slack DM |

**Kinetic:**

- Cards pop in TL → TR → BL → BR. Each card header color matches its role:
  - catalog: `text` (white — descriptive)
  - policy: `destructive` (red — it's the gate)
  - audit: `text`
  - approval: `pending` (yellow — it's the human-in-the-loop)
- Headers use `emphasis` (scale pulse) on arrival.

## Scene 6 — Demo glimpse (1:05–1:15)

**Direction:** Full-screen terminal screenshot. Real shell session.
A single conversation beat: agent makes a bad call, proxy blocks
it and asks for human approval. Monospace. No fake.

**Caption (rendered as a terminal block):**

```text
$ mcp-socd -- falcon-mcp
mcp-socd 0.1.0
  config:    ~/.config/mcp-socd/config.yaml
  upstream:  [falcon-mcp]
  audit:     stderr (use --audit-stdout for SIEM)

> agent → isolate_endpoint host=dc01.corp
policy:    blast_radius=5 → require_approval
approval:  pending Slack @secops
audit:     OCSF 2004 verdict=awaiting_approval actor=agent:v1
```

**Kinetic:**

- Text appears as if typed live (60ms per character).
- The agent line ("agent → isolate_endpoint host=dc01.corp") types first.
- "policy: blast_radius=5" appears in `destructive` red.
- "approval: pending" appears in `pending` yellow.
- Final line ("audit: OCSF 2004 …") in `text` white.
- Hold for 2 seconds with no motion — let the viewer read.

## Scene 7 — Close (1:15–1:20)

**Direction:** Fade to black. Wordmark + repo URL + tagline.

**Caption:**

> **mcp-socd**
> default-deny. in production.
> github.com/AnandSundar/mcp-socd

**Kinetic:**

- "default-deny." and "in production." appear on the same line,
  separated by a typewriter pause. `in production.` ends in
  `emphasis_color: safe` (green) — the resolution.
- URL fades in last, `muted`.
- Hold 1 second, then fade out.

---

# Production notes

- Total runtime: ~80 seconds at the speeds above. Adjust per-scene
  timings if HyperFrames' auto-tempo picks different durations.
- For X/TikTok: lean 9:16, captions lower-third, motion slightly
  faster (×0.85).
- For YouTube/README: lean 16:9, captions can move up to mid-screen,
  motion at the script's natural tempo.
- No voiceover. If you want a voiceover pass later, the captions
  are written to be read aloud verbatim.