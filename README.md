# Rogue AI Audit

Read-only PowerShell audit that finds unsanctioned ("rogue" / shadow) AI use on a Windows endpoint and writes a
filterable HTML report. Built for MSPs and IT teams running AI governance reviews, and safe to push from an RMM.

Two scripts, both standalone:

| Script | What it does |
|---|---|
| `Find-RogueAI.ps1` | Inventory of AI apps, local LLMs, AI CLIs and IDE extensions, AI browser extensions, AI site visits in browser history, and the DNS cache. |
| `Find-RogueAI-v2.ps1` | Everything in v1, plus a rule-based scan of AI prompts and conversations cached on disk for sensitive data (secrets, card numbers, SSNs, bank details, PHI, confidential markings, your own keywords). |

A demo report is in [`Reports/RogueAI-v2-Sample-Report.html`](Reports/RogueAI-v2-Sample-Report.html) (made-up data).

## What it looks for

- **Installed AI apps**: Programs and Features (machine and every loaded user hive), Store/MSIX packages, per-user
  install folders, running processes.
- **Local LLMs**: Ollama, LM Studio, GPT4All, Jan, Hugging Face cache and other model stores; optionally large model
  files (`*.gguf`, `*.safetensors`, `*.ggml`, `*.onnx`) with `-ScanModelFiles`.
- **AI CLIs and coding assistants**: Claude Code, Codex, Gemini CLI, and Copilot / Cline / Continue in VS Code-family editors.
- **AI browser extensions**: Chrome, Edge, Brave, Vivaldi, Opera, Firefox and forks.
- **AI website visits** in browser history for the last `-Days` days, plus the machine DNS client cache (which also
  catches private browsing and desktop apps). Only AI sites are reported, aggregated per site.
- **v2 only, cached prompts**: Claude Code, Codex and Gemini CLI transcripts, Ollama history, LM Studio, Jan, GPT4All,
  AnythingLLM, Msty, Continue, Cline/Roo, VS Code Copilot Chat, Cursor and Windsurf chat databases, Claude / ChatGPT /
  Copilot / Perplexity desktop app storage, browser IndexedDB for AI sites, and AI conversation page titles.

Each finding gets a default risk rating (High, Medium, Low, Review, Info) and a status: Sanctioned or Unsanctioned,
based on the domains and apps you approve.

## Requirements

- Windows 10/11 or Windows Server
- Windows PowerShell 5.1 or PowerShell 7
- Run elevated (or as SYSTEM from an RMM) to cover every user profile; otherwise only the current user is checked.

No modules or installs. Browser history is read through Windows' built-in `winsqlite3.dll`, with a raw file scan as a
fallback.

## Usage

```powershell
# Defaults: 30 days of history, report under %ProgramData%\RogueAIAudit
powershell -ExecutionPolicy Bypass -File .\Find-RogueAI.ps1

# Approve Microsoft 365 Copilot and fail the RMM check if anything else turns up
.\Find-RogueAI.ps1 -Days 90 -SanctionedDomains 'm365.cloud.microsoft','copilot.cloud.microsoft' `
    -SanctionedApps 'Microsoft 365 Copilot*' -FailOnUnsanctioned

# v2: also scan cached prompts and flag your own terms
.\Find-RogueAI-v2.ps1 -Keywords 'Project Falcon','Contoso' -FailOnSensitiveData
```

### Parameters (both scripts)

| Parameter | Default | Purpose |
|---|---|---|
| `-Days` | 30 | How far back to read browser history. |
| `-OutputPath` | `%ProgramData%\RogueAIAudit\<PC>_<time>` | Folder for the CSV and JSON output (falls back to `%TEMP%`). |
| `-SanctionedDomains` | none | Approved domains (subdomains included). |
| `-SanctionedApps` | none | Approved app / extension names, as `-like` wildcards. |
| `-IncludeUrls` | off | Also write `HistoryDetail.csv` with full URLs, page titles and visit times. |
| `-ScanModelFiles` | off | Search profiles for model files over 100 MB. Slower. |
| `-FailOnUnsanctioned` | off | Exit 1 if any unsanctioned High or Medium finding exists. |
| `-NoOpen` | off | Don't open the HTML report at the end (never opened as SYSTEM or non-interactive). |

### Extra parameters (v2)

| Parameter | Default | Purpose |
|---|---|---|
| `-PromptDays` | 90 | Only scan prompt/cache files changed in the last N days. |
| `-MaxFileMB` | 64 | Skip larger files and cap text pulled from chat databases. |
| `-Keywords` / `-KeywordFile` | none | Your own terms (code names, client names) to flag as High. |
| `-NoSnippets` | off | Leave masked context snippets out of the output. |
| `-SkipPromptScan` | off | Run only the v1 inventory. |
| `-FullTranscripts` | off | Scan whole JSONL transcripts, not just the user's prompts. |
| `-FailOnSensitiveData` | off | Exit 1 if any Critical or High data finding exists. |
| `-ProfilePath` | none | Scan one profile folder (useful for testing with planted data). |

## Output

- **HTML report** next to the script: `RogueAI-Report_<PC>_<time>.html` (v2: `RogueAI-v2-Report_...`), filterable
  by risk, status and category.
- **In `-OutputPath`**: `Findings.csv`, `Summary.json`, `HistoryDetail.csv` (with `-IncludeUrls`) and, for v2,
  `DataFindings.csv`.
- **Exit code** 0, or 1 when `-FailOnUnsanctioned` / `-FailOnSensitiveData` trips, so an RMM monitor can alert on it.

## Safety and privacy

- **Read-only.** Nothing on the machine changes apart from writing the report. History databases are copied to a temp
  folder, read there, and the copies deleted.
- **No AI in the detection.** v2 uses fixed rules: regular expressions plus validators (Luhn for cards, ABA checksum
  for routing numbers, mod-97 for IBANs, SSN area rules) and known secret formats (AWS, GitHub, OpenAI, Anthropic,
  Slack, Stripe, Google and Azure keys, private keys, JWTs, connection strings).
- **Masked output.** v2 reports only masked values (e.g. `***-**-1234`) and scrubbed snippets. The report still
  describes sensitive data, so store and share it as confidential.
- **Get approval first.** Reviewing browsing and AI prompts should be covered by the organization's acceptable-use or
  monitoring policy.

## Tuning

Detection lists are plain catalogs at the top of each script (websites, apps, per-user paths, extension patterns).
Add or re-rate entries there.

## License

MIT. See [LICENSE](LICENSE).
