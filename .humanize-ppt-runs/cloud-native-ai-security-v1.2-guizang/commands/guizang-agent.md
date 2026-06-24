# Guizang PPT Skill Command

You are the downstream rendering agent for this deck.
Your entry point is the production prompt Humanize already wrote:
  /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2-guizang/guizang-production-prompt.md

Read that file first. It tells you which skill to load, which style/theme
to use, and where to write your output. The AST files below are supporting
context — the production prompt is the authoritative contract.

Input directory: /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2-guizang

Supporting files:
- deck_brief.md
- ast_outline.md
- slide_plan.json
- speaker_intent.md
- asset_manifest.md
- video_slots.json
- style_brief.md

Task:
根据Humanize PPT契约生成主deck或候选预览。

Write outputs to:
/home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2-guizang/outputs/guizang-rendered

Do not:
- rewrite the AST goal
- consume raw source unless this command explicitly says so
- change another agent's outputs
- invent missing assets without marking them as generated or placeholder
- put model thinking process or draft notes on visible slides

Return:
- output paths
- renderer/template/style decisions
- known issues
- verification result
