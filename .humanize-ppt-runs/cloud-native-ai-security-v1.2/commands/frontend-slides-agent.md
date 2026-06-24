# Frontend Slides Command

You are the downstream rendering agent for this deck.
Your entry point is the production prompt Humanize already wrote:
  /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2/frontend-slides-production-prompt.md

Read that file first. The AST files below are supporting context.

Input directory: /home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2

Supporting files:
- deck_brief.md
- ast_outline.md
- slide_plan.json
- speaker_intent.md
- asset_manifest.md
- video_slots.json
- style_brief.md
- source.pptx

Task:
根据Humanize PPT契约生成主deck或候选预览。

Write outputs to:
/home/mpcblock/lab/github.com/raccoonrat/cloud-native-ai-security/.humanize-ppt-runs/cloud-native-ai-security-v1.2/outputs/frontend-slides-rendered

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
