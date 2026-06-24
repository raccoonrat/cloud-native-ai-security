# Guizang Production Prompt

> Humanize PPT stops here. The next agent must follow
> `~/.agents/skills/guizang-ppt-skill/SKILL.md` end to end.
> Do not reimplement Guizang inside Humanize. Do not import the
> Guizang template into Humanize. Do not post-process the rendered HTML
> with Humanize-owned bridges — Guizang owns its own navigation.

## Deck

- Title: 云原生企业 AI 安全控制平面
- Source: /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/[6]Cloud Native Enterprise AI Security Control Plane -v1.2.md
- Language: en
- Style: A
- Theme preset: ink-classic (Ink Classic (墨水经典) — the verified known-good baseline at examples/03-codex-guizang-native-ink-classic/)

- Slides: 8

## Style files (use the ones for Style A)

- template: `assets/template.html`
- layouts: `references/layouts.md`
- themes: `references/themes.md`
- lock: (none — Style A is the flexible track)
- validator: `guizang's own Style A visual QA checklist (see references/guizang-material-qa.md)`
- Apply theme preset: `ink-classic` from references/themes.md


## Hard rules

- Read `guizang-ppt-skill/SKILL.md` before any rendering. Do not skip it.
- Pick every page's layout from the registered set in
  `references/layouts.md`. Do not invent layout classes.
- Preserve Guizang's animation hooks (`data-anim` / `data-animate`),
  Motion One loading, and the WebGL dual canvas where Style A applies.
- This prompt requires `guizang-ppt-skill` to be installed at
  `~/.agents/skills/guizang-ppt-skill/`. If it is not, the next agent
  must install it before rendering. The brief still ships.
- Run the validator above before reporting complete.
- Do not modify or post-process the rendered HTML in Humanize.
- The HTML that ends up on disk is produced by `guizang-ppt-skill`,
  not by Humanize.

## Inputs already produced by Humanize

- `deck_brief.md`
- `ast_outline.md`
- `slide_plan.json`
- `speaker_intent.md`
- `asset_manifest.md`
- `video_slots.json`
- `style_brief.md`

## Per-page media decisions (Humanize-owned)

- S01 云原生企业 AI 安全控制平面 — image=gpt-photo
  - image.asset_path: `assets/s01-image.png`
  - image.prompt_hint: Slide title: 云原生企业 AI 安全控制平面 | Slide message: Cloud Native Enterprise AI Security Contro | Page role: Open the deck. Set emotional anchor. | Asset guidance: Image: must be visually anchored, no Chinese text in the image (Chinese labels go in the slide layout).
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

## Known-good checkpoint (read-only reference)

- `examples/03-codex-guizang-native-ink-classic/index.html`
  (Style A, Ink Classic, 10 slides, hero WebGL background, 86 `data-anim`
  occurrences). Open it to see the bar for Style A quality.

## Style A QA gates (must all pass)

- no `[必填]` template residue
- no `<!-- SLIDES_HERE -->` marker residue
- `canvas#bg-dark` exists
- `canvas#bg-light` exists
- `body.low-power` is not active by default
- `.slide.hero.light,.slide.hero.dark { background: transparent }` is applied so the WebGL hero canvas is visible
- meaningful `data-anim` / `data-animate` markers are present
- at least 3 `data-anim` occurrences per non-cover page (Ink Classic checkpoint has 86)

## Hand-off

The next agent writes its output to its own convention
(e.g. `outputs/guizang-rendered/index.html`). Do not write to
`outputs/guizang/` — that is reserved for legacy Humanize adapter paths
and is no longer used in v0.6.4.
