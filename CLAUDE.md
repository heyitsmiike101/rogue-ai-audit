# Rogue AI Audit (dev)

Read-only PowerShell audit for shadow AI use on one Windows endpoint, with an HTML report. Public repo
`heyitsmiike101/rogue-ai-audit` (MIT). The companion SentinelOne SDL dashboard
stays in the Cowork workspace (see its root CONTEXT.md). User docs: `README.md`.

## Layout
- `Find-RogueAI.ps1` (v1 inventory), `Find-RogueAI-v2.ps1` (v1 + cached-prompt sensitive-data scan).
- `Reports/`: only `RogueAI-v2-Sample-Report.html` (made-up data) is tracked. Real reports stay local (gitignored):
  they describe a real machine's users and data.

## Rules
- Both scripts must stay Windows PowerShell 5.1 compatible (RMM runs) and ASCII-only.
- Read-only by design: never add anything that changes the endpoint. History output is AI sites only; full URLs only with `-IncludeUrls`.
- Detection lists are the catalogs at the top of each script (sites, apps, per-user paths, extension patterns); tune there.
- History is read via Windows' built-in `winsqlite3.dll` (P/Invoke); raw-file scan is the fallback.
- v2 is a standalone copy of v1 plus the prompt scan; fix shared logic in both. Its C# classes are suffixed `2`
  (`RogueAiSqlite2`, `RogueAiData2`, `RogueAiScan2`) so both scripts can load in one session.
- v2 detection is deterministic, never AI: regexes + validators in the C# `RogueAiScan2` class (matching runs in C#
  for speed; PowerShell loops were too slow on GBs of Claude Code transcripts). JSONL transcripts are prompts-only by
  default (`-FullTranscripts` for everything). LevelDB `.ldb` files are decoded in-script (table blocks + Snappy).
- v2 output must never contain raw sensitive values: examples are masked and snippets scrubbed over a wider window
  than shown. After changing rules or masking, run against a planted-data profile (`-ProfilePath`) and grep the
  CSV/HTML for the planted raw values.
- Public repo: no customer names, hostnames, usernames or real report data in commits.

## Test
`powershell -ExecutionPolicy Bypass -File .\Find-RogueAI.ps1 -OutputPath $env:TEMP\rogueai-test -NoOpen`
(elevated to cover all profiles). The HTML report lands next to the script (gitignored).

## Git
Public GitHub repo, branch `main`. Commit/push only when Mike asks. No GitHub Actions.
