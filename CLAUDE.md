# Rogue AI Audit (dev)

Read-only PowerShell audit of AI tools on one Windows endpoint, rated by the sensitive data in their local prompts/caches, with an HTML report and detection summary. Public repo
`heyitsmiike101/rogue-ai-audit` (MIT). The companion SentinelOne SDL dashboard
stays in the Cowork workspace (see its root CONTEXT.md). User docs: `README.md`.

## Layout
- `Find-RogueAI.ps1`: the one script (inventory of AI tools + rule-based scan of their local prompts/caches). The old
  v1 inventory-only script was removed 2026-10-30.
- `Reports/`: only `RogueAI-Sample-Report.html` (made-up data) is tracked. Real reports stay local (gitignored):
  they describe a real machine's users and data.

## Rules
- Must stay Windows PowerShell 5.1 compatible (RMM runs) and ASCII-only.
- Read-only by design: never add anything that changes the endpoint. History output is AI sites only; full URLs only with `-IncludeUrls`.
- No approved/sanctioned list: it's a generic report. A tool's rating comes only from sensitive data found in that
  tool's own local data, per (User, Tool): worst severity, else `None found` (data scanned, clean), `Not checked` (no
  readable data), or `Info` (governance tooling). Catalogs carry no risk column.
- `Tool` links inventory findings to data findings: `$PromptSources` entries carry a `Tool`, `$ToolAlias` and
  `Get-IdeToolName` normalize inventory items, site storage/page titles use the site name. New sources need a matching
  `Tool` or they won't rate the tool.
- The detection summary is fixed templates, never AI: rule lists are generated from `$DataRules`; explanations come from
  `$CategoryWhy` (per data category) and `$ToolTypeNote` (per tool category, plus the PRC-provider note).
- The HTML report is chart-first and fully self-contained (endpoints are often offline): charts are inline SVG/CSS
  built in PowerShell, small vanilla JS for tooltips and filters, no CDNs or external fonts. Rating colors use the
  dataviz status palette (Critical #d03b3b, High #ec835a, Medium #fab219, Low #3987e5, None found #0ca30c, Not checked
  gray) and always sit next to a text label. Keep wording short; long text belongs in collapsed sections. To look at
  a report in the browser pane, serve it over a local http server (file:// pages can't be inspected there).
- Detection lists are the catalogs at the top of the script (sites, apps, per-user paths, extension patterns); tune there.
- History is read via Windows' built-in `winsqlite3.dll` (P/Invoke); raw-file scan is the fallback.
- C# classes are suffixed `2` (`RogueAiSqlite2`, `RogueAiData2`, `RogueAiScan2`), a leftover from when v1 and v2 loaded
  in one session; leave the names.
- Data detection is deterministic: regexes + validators in the C# `RogueAiScan2` class (matching runs in C# for speed;
  PowerShell loops were too slow on GBs of Claude Code transcripts). JSONL transcripts are prompts-only by default
  (`-FullTranscripts` for everything). LevelDB `.ldb` files are decoded in-script (table blocks + Snappy).
- Output must never contain raw sensitive values: examples are masked and snippets scrubbed (`Protect-Text`) over a
  wider window than shown. After changing rules or masking, run against a planted-data profile (`-ProfilePath`) and grep
  the CSV/HTML/JSON for the planted raw values. Known test numbers (4111 1111 1111 1111, 123-45-6789) are excluded by
  the validators, so plant other valid values.
- Public repo: no customer names, hostnames, usernames or real report data in commits. Commit with the GitHub noreply
  email (set in this repo's local git config). To regenerate the sample: planted profile named `dlopez`, run with
  `COMPUTERNAME=NWD-LT-0417`, then replace local paths and the real username, and grep it before committing
  (machine-wide rows such as installed programs and processes come from the real PC).

## Test
`powershell -ExecutionPolicy Bypass -File .\Find-RogueAI.ps1 -OutputPath $env:TEMP\rogueai-test -NoOpen`
(elevated to cover all profiles). The HTML report lands next to the script (gitignored).

## Git
Public GitHub repo, branch `main`. Commit/push only when Mike asks. No GitHub Actions.
