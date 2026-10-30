# Rogue AI Audit

Read-only PowerShell audit that finds AI tools on a Windows endpoint, scans the prompts and conversations those tools
keep on disk for sensitive data, and writes a filterable HTML report with a plain-English detection summary. Built for
MSPs and IT teams running AI governance reviews, and safe to push from an RMM.

One script, `Find-RogueAI.ps1`, no installs or modules. A demo report is in
[`Reports/RogueAI-Sample-Report.html`](Reports/RogueAI-Sample-Report.html) (made-up data).

## What it looks for

**AI tools on the machine**
- **Installed AI apps**: Programs and Features (machine and every loaded user hive), Store/MSIX packages, per-user
  install folders, running processes.
- **Local LLMs**: Ollama, LM Studio, GPT4All, Jan, AnythingLLM, Msty, Hugging Face cache and other model stores;
  optionally large model files (`*.gguf`, `*.safetensors`, `*.ggml`, `*.onnx`) with `-ScanModelFiles`.
- **AI CLIs and coding assistants**: Claude Code, Codex, Gemini CLI, and Copilot / Cline / Continue in VS Code-family editors.
- **AI browser extensions**: Chrome, Edge, Brave, Vivaldi, Opera, Firefox and forks.
- **AI website visits** in browser history for the last `-Days` days, plus the machine DNS client cache (which also
  catches private browsing and desktop apps). Only AI sites are reported, aggregated per site.

**Sensitive data in those tools' local data**
- Claude Code, Codex and Gemini CLI transcripts, Ollama history, LM Studio, Jan, GPT4All, AnythingLLM, Msty, Continue,
  Cline/Roo, VS Code Copilot Chat, Cursor and Windsurf chat databases, Claude / ChatGPT / Copilot / Perplexity desktop
  app storage, browser IndexedDB for AI sites, and AI conversation page titles.
- Checked with fixed rules (no AI): credentials and secrets (AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, Google and
  Azure keys, private keys, JWTs, passwords, connection strings), payment cards, SSNs, bank/IBAN, passport, driver's
  license, date of birth, medical record numbers and ICD-10 codes, privileged/confidential markings, finance and HR/legal
  terms, contact details, internal IPs, and your own keywords (`-Keywords`).

## How tools are rated

There is no approved list. Each tool is rated by the **most severe sensitive data found in the data that tool keeps on
the PC**, per user profile:

| Rating | Meaning |
|---|---|
| **Critical** | Secrets and keys, payment card numbers, SSNs. |
| **High** | Passwords and tokens in text, bank and identity numbers, health record numbers, privileged/trade-secret markings, your keywords. |
| **Medium** | Health terms, confidential markings, finance and HR/legal terms. |
| **Low** | Email addresses, phone numbers, internal IP addresses. |
| **None found** | The tool's data was scanned and nothing matched. |
| **Not checked** | The tool keeps no data the script can read (browser extensions, DNS lookups, sites without cached storage), so it is reported but not scored. |
| **Info** | Governance tooling such as the Prompt Security extension. |

The exact rule list for each level is generated from the script's rules into every report.

## The report

A single self-contained HTML file (no internet needed to open it), chart-first, light and dark mode:
1. **Stat tiles**: AI tools found, tools with sensitive data, Critical and High data findings, profiles scanned.
2. **Tools by rating**: one bar split by rating.
3. **Where the sensitive data is**: each tool with hits, ranked by rating, bar length = number of hits.
4. **What kind of data**: a grid of tools against data types (secrets, financial, identity, health...), each cell
   showing the count and colored by its worst rating. Hover a cell for the rules that matched.
5. **Why it matters**: one short card per data type found.
6. **Present but not scored**: tools with no readable data, grouped by type; hover for what each type means.
7. **Collapsed sections**: how scoring works (every rule by rating), the full tools and data-findings tables with
   filters, and run notes.

A plain-text version of the summary is saved to `Summary.json` (`SummaryText`) and printed to the console.

## Requirements

- Windows 10/11 or Windows Server
- Windows PowerShell 5.1 or PowerShell 7
- Run elevated (or as SYSTEM from an RMM) to cover every user profile; otherwise only the current user is checked.

Browser history is read through Windows' built-in `winsqlite3.dll`, with a raw file scan as a fallback.

## Usage

```powershell
# Defaults: 30 days of history, 90 days of prompt files, report under %ProgramData%\RogueAIAudit
powershell -ExecutionPolicy Bypass -File .\Find-RogueAI.ps1

# Flag your own terms and fail the RMM check on Critical or High data
.\Find-RogueAI.ps1 -Keywords 'Project Falcon','Contoso' -FailOnSensitiveData

# Quick inventory only (every tool shows Not checked)
.\Find-RogueAI.ps1 -SkipPromptScan
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-Days` | 30 | How far back to read browser history. |
| `-OutputPath` | `%ProgramData%\RogueAIAudit\<PC>_<time>` | Folder for the CSV and JSON output (falls back to `%TEMP%`). |
| `-IncludeUrls` | off | Also write `HistoryDetail.csv` with full URLs, page titles and visit times. |
| `-ScanModelFiles` | off | Search profiles for model files over 100 MB. Slower. |
| `-NoOpen` | off | Don't open the HTML report at the end (never opened as SYSTEM or non-interactive). |
| `-PromptDays` | 90 | Only scan prompt/cache files changed in the last N days. |
| `-MaxFileMB` | 64 | Skip larger files and cap text pulled from chat databases. |
| `-Keywords` / `-KeywordFile` | none | Your own terms (code names, client names) to flag as High. |
| `-NoSnippets` | off | Leave masked context snippets out of the output. |
| `-SkipPromptScan` | off | Inventory only; no data scan, so nothing is rated. |
| `-FullTranscripts` | off | Scan whole JSONL transcripts, not just the user's prompts. |
| `-FailOnSensitiveData` | off | Exit 1 if any Critical or High data finding exists. |
| `-ProfilePath` | none | Scan one profile folder (useful for testing with planted data). |

## Output

- **HTML report** next to the script: `RogueAI-Report_<PC>_<time>.html`, with the detection summary, the tools table
  (rating, data hits, user, source, visits) and the data findings table, both filterable.
- **In `-OutputPath`**: `Findings.csv`, `DataFindings.csv`, `Summary.json` (counts, per-tool ratings, summary text)
  and `HistoryDetail.csv` (with `-IncludeUrls`).
- **Exit code** 0, or 1 when `-FailOnSensitiveData` trips, so an RMM monitor can alert on it.

## Safety and privacy

- **Read-only.** Nothing on the machine changes apart from writing the report. History databases are copied to a temp
  folder, read there, and the copies deleted.
- **No AI in the detection.** Regular expressions plus validators: Luhn for cards, ABA checksum for routing numbers,
  mod-97 for IBANs, SSN area rules, known test numbers excluded. A match is an indicator to review, not proof of a leak.
- **Masked output.** Only masked values (e.g. `***-**-1234`, `AKIAA...[20 chars]`) and scrubbed snippets are written.
  The report still describes sensitive data, so store and share it as confidential.
- **Get approval first.** Reviewing browsing and AI prompts should be covered by the organization's acceptable-use or
  monitoring policy.

## Tuning

Detection lists are plain catalogs at the top of the script (websites, apps, per-user paths, extension patterns), and
the data rules are the `Add-Rule` lines in the prompt-scan section. Add or change entries there.

## License

MIT. See [LICENSE](LICENSE).
