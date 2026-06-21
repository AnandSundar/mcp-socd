# mcp-socd launch reel

A HyperFrames script for a 75-80 second launch reel announcing mcp-socd.

## Files

- `script.md` — the source. Drop this into HyperFrames' input.
- `README.md` — this file. Describes the format so future reels
  stay consistent and so a reviewer can tell the HyperFrames
  agent what's expected.

## Format (best guess — correct me after first render)

HyperFrames' "no editor, no timeline" loop means the agent
reads the script and decides everything else: timing, layout,
fonts, motion, audio, transitions. The script's job is to
specify **what must be on screen, in what order, and with what
kinetic energy**, so the agent has unambiguous intent to render.

Each `script.md` has three layers:

1. **Frontmatter** — global config the agent should honor where
   possible (palette, font, aspect ratios, audio posture).
2. **Per-scene sections** (`## Scene N — title`) — the agent's
   primary work unit. Each scene carries:
   - **Direction** — visual/intent notes for the agent
     (hard cut, centered, type-in, terminal screenshot, etc.).
   - **Captions** — every word that must appear on screen, in
     order, with no fluff. The user said "captions carrying every
     beat" — this is the spec.
   - **Kinetic** — micro-instructions for the typography agent
     (which word pops first, which color, which animates in
     last). If the user wants simpler "just render" scenes, drop
     the Kinetic block.
3. **Trailing close** — the final scene carries the repo URL
   and a one-line CTA.

## Reusable conventions for future reels

- **Color semantics** carry across the project. Keep them stable:
  - `#ff4d4d` (red) — deny, destructive, blast
  - `#4ade80` (green) — allow, safe
  - `#facc15` (yellow) — awaiting approval, in-flight
  - `#fafafa` (white) — neutral copy
  - `#0a0a0a` (near-black) — background
- **Aspect ratios** — always specify both 9:16 (X/TikTok/Shorts)
  and 16:9 (YouTube/web/README embed). HyperFrames can render
  both from the same source.
- **No voiceover** — captions are the audio. The reel is silent.
  This keeps the production loop to "render and post" with no
  voice actor or studio step.
- **Mono font** — JetBrains Mono or system mono. Signals
  "practitioner tool, not marketing fluff."

## Adjustments after first render

If HyperFrames ignores the frontmatter, the per-scene direction,
or the kinetic instructions, fix it in this file, not in the
render output. The script is the source of truth; the MP4 is a
build artifact.
