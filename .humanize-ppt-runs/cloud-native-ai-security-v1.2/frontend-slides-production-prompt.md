# Frontend Slides Production Prompt

> Humanize PPT stops here. The next agent must follow
> `~/.agents/skills/frontend-slides/SKILL.md` end to end.
> Do not reimplement the renderer inside Humanize.

## Deck

- Title: Cloud Native Enterprise AI Security Control Plane
- Source: /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/[6]Cloud Native Enterprise AI Security Control Plane -v1.2.md
- Language: en
- Slides: 8

## Hard rules

- Read `frontend-slides/SKILL.md` first. Use its native PPTX→HTML
  conversion, viewport-safe deck, and Vercel deploy path.
- Use the registered layouts / templates that skill ships with. Do not
  invent layout classes.
- Do not post-process the rendered HTML in Humanize. Frontend-slides
  owns its own navigation, presenter shell, and deploy step.

## Inputs already produced by Humanize

- `deck_brief.md`
- `ast_outline.md`
- `slide_plan.json`
- `speaker_intent.md`
- `asset_manifest.md`
- `video_slots.json`
- `style_brief.md`

## Per-page media decisions (Humanize-owned)

- S01 Cloud Native Enterprise AI Security Control Plane — image=gpt-photo
  - image.asset_path: `assets/s01-image.png`
  - image.prompt_hint: Slide title: Cloud Native Enterprise AI Security Control Plane | Slide message: Cloud Native Enterprise AI Security Contro | Page role: Open the deck. Set emotional anchor. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
- S02 企业云原生 AI 安全控制平面完整设计书 V1.2 — diagram=svg-html
  - diagram.asset_path: `assets/s02-diagram.svg`
  - diagram.prompt_hint: Slide title: 企业云原生 AI 安全控制平面完整设计书 V1.2 | Slide message: 企业云原生 AI 安全控制平面完整设计书 V1.2 | Page role: Establish common ground. Show system / scope. | Asset guidance: Diagram: render as inline SVG or HTML table, deterministic, no text overflow.
- S03 MCP / Tool-Calling Runtime Security Hardening — image=svg-html
  - image.asset_path: `assets/s03-image.svg`
  - image.prompt_hint: Slide title: MCP / Tool-Calling Runtime Security Hardening | Slide message: 定位：本文档面向工程团队、平台团队、安全团队、SRE 团队与产品集成团队，定义一套可 | Page role: Highlight the gap or contradiction. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
- S04 Canonical Enums, Contracts and Runtime Semantics — diagram=svg-html, video=remotion-clip (10s)
  - diagram.asset_path: `assets/s04-diagram.svg`
  - diagram.prompt_hint: Slide title: Canonical Enums, Contracts and Runtime Semantics | Slide message: 本章是全文的“硬约束源” | Page role: Walk through the process / decision tree. | Asset guidance: Diagram: render as inline SVG or HTML table, deterministic, no text overflow.
  - video.asset_path: `assets/s04-video.mp4`
  - video.prompt_hint: Slide title: Canonical Enums, Contracts and Runtime Semantics | Slide message: 本章是全文的“硬约束源” | Page role: Walk through the process / decision tree. | Asset guidance: Short loop clip (8-12s), deterministic motion, no narration.
- S05 0.1 Canonical Runtime Stage Enum — image=screenshot, diagram=svg-html, video=remotion-clip (8s)
  - image.asset_path: `assets/s05-image.png`
  - image.prompt_hint: Slide title: 0.1 Canonical Runtime Stage Enum | Slide message: 全系统只允许使用一个字段表达运行时阶段：stage | Page role: Show evidence: real UI, screenshots, before/after. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
  - diagram.asset_path: `assets/s05-diagram.svg`
  - diagram.prompt_hint: Slide title: 0.1 Canonical Runtime Stage Enum | Slide message: 全系统只允许使用一个字段表达运行时阶段：stage | Page role: Show evidence: real UI, screenshots, before/after. | Asset guidance: Diagram: render as inline SVG or HTML table, deterministic, no text overflow.
  - video.asset_path: `assets/s05-video.mp4`
  - video.prompt_hint: Slide title: 0.1 Canonical Runtime Stage Enum | Slide message: 全系统只允许使用一个字段表达运行时阶段：stage | Page role: Show evidence: real UI, screenshots, before/after. | Asset guidance: Short loop clip (8-12s), deterministic motion, no narration.
- S06 0.2 Canonical Action Enum 与分类 — image=svg-html
  - image.asset_path: `assets/s06-image.svg`
  - image.prompt_hint: Slide title: 0.2 Canonical Action Enum 与分类 | Slide message: yaml Action: allow logonly warn redact blo | Page role: Close the deck. Reinforce the judgment. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
- S07 0.3 Canonical Severity / RiskFamily Enum — image=svg-html
  - image.asset_path: `assets/s07-image.svg`
  - image.prompt_hint: Slide title: 0.3 Canonical Severity / RiskFamily Enum | Slide message: yaml Severity: none low medium high critic | Page role: Close the deck. Reinforce the judgment. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
- S08 0.4 Decision Determinism Rules（决策可复现规则） — image=svg-html
  - image.asset_path: `assets/s08-image.svg`
  - image.prompt_hint: Slide title: 0.4 Decision Determinism Rules（决策可复现规则） | Slide message: replay consistency 成立的充要条件是 replay key 完整： | Page role: Close the deck. Reinforce the judgment. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).

## Media production (visual enhancement)

Each media slot above ships `asset_path` (where to write) and `prompt_hint`
(what to generate). Produce the asset, then reference it from the rendered
slide. Recommended generators (hot-pluggable — swap for any equivalent skill):

- **image** (`gpt-photo`): preferred — `baoyu-image-gen` driving the local
  Codex CLI (`--provider codex-cli`, uses the logged-in Codex/ChatGPT
  subscription, no `OPENAI_API_KEY` needed). Alternatives: `imagegen` /
  `imagen` / `nanobanana-ppt` (these need their own API key). Feed
  `prompt_hint`, honor `aspect_ratio` and `max_size_kb`, write to `asset_path`.
  Use synthesized images for atmospheric / conceptual / hero visuals; keep
  precise-text or data figures as deterministic SVG (image models garble
  exact labels and numbers).
- **image** (`screenshot`): capture the real UI / result; do not synthesize.
- **diagram** (`svg-html` / `html-table`): render as deterministic inline SVG
  or HTML from `prompt_hint`. No external call, no text overflow. This is the
  right choice for data, metrics, process steps, and any precise-label figure.
- **video** (`remotion-clip`): default to `remotion-video-production` (it
  orchestrates the pipeline) paired with `remotion-best-practices` (avoids
  unstable Remotion patterns — misused CSS/Tailwind animation, wrong asset
  paths); add `remotion-video-toolkit` only for complex work (captions,
  charts, 3D, batch templates). Build a deterministic loop of `duration_s`
  seconds (no narration), render to `asset_path` (mp4).
- **video** (`hyperframes`): use the HyperFrames pipeline for the clip.

Rule: an asset slot with `asset_path` is an executable task. A slot without
one is a label only — do not invent paths. Humanize decides *what* and
*where* (the per-page media plan); the downstream skill produces the file and
renders the deck. Humanize orchestrates the presentation; it does not own the
template that paints the final slide.

## Hand-off

The next agent writes its output to its own convention
(e.g. `outputs/frontend-slides-rendered/index.html`).
