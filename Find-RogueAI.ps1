<#
.SYNOPSIS
    Read-only audit of a Windows endpoint for AI tools ("rogue" / shadow AI), with a scan of the prompts and caches
    those tools keep locally for sensitive data. Each tool is rated by the data found in its own local data.

.DESCRIPTION
    This is a generic report: there is no approved-tool list. It inventories the AI tools on the machine, scans the
    prompts and conversations each tool stores on disk, and rates every tool by the most severe sensitive data found
    in that tool's own data.

    Inventory:
      - Installed AI apps: Programs and Features (machine + loaded user hives), Store/MSIX packages,
        per-user install folders, and running processes.
      - Local LLM runtimes and downloaded model stores (Ollama, LM Studio, GPT4All, Jan, Hugging Face cache...).
      - AI CLIs and coding assistants (Claude Code, Codex, Gemini CLI, Copilot/Cline/Continue in VS Code-family editors).
      - AI browser extensions (Chrome, Edge, Brave, Vivaldi, Opera, Firefox and forks).
      - Visits to AI websites in browser history for the last -Days days, plus the machine DNS client cache
        (which also catches private/incognito browsing and desktop apps).

    Prompt and cache scan:
      - Reads prompts and conversations AI tools keep on disk: Claude Code, Codex and Gemini CLIs, Ollama CLI history,
        LM Studio, Jan, GPT4All, AnythingLLM, Msty, Continue, Cline/Roo, VS Code Copilot Chat, Cursor and Windsurf chat
        databases, the Claude / ChatGPT / Copilot / Perplexity desktop apps' local storage, browser IndexedDB storage
        for AI sites, and the page titles of AI conversations in browser history.
      - Checks that text with fixed rules, no AI involved: regular expressions plus validators (Luhn for card numbers,
        ABA checksum for routing numbers, mod-97 for IBANs, SSN area rules), keyword-anchored patterns (DOB, passport,
        driver's license, account number, MRN, ICD-10), known secret formats (AWS, GitHub, OpenAI, Anthropic, Slack,
        Stripe, Google, Azure keys, private keys, JWTs, passwords and connection strings), document markings
        (privileged, confidential), finance/HR/health keywords, and optional customer keywords (-Keywords).
      - LevelDB stores (Electron apps, Chromium IndexedDB) are decoded in-script (table blocks + Snappy) and scanned
        for text; values a browser compresses itself may still be missed.
      - Reports only masked values (e.g. ***-**-1234, sk-pro...[164 chars]) and masked context snippets. Even so the
        report describes sensitive data: store and share it as confidential.

    Ratings: each tool is rated per user profile by the most severe sensitive data found in that tool's own prompts,
    conversations and caches (changed in the last -PromptDays days): Critical, High, Medium or Low. "None found" means
    the tool's data was scanned and nothing matched. "Not checked" means the tool keeps no data this script can read
    (extensions, sites without cached storage, DNS lookups, apps without a known store, or -SkipPromptScan), so it is
    reported but not scored. "Info" marks governance tooling (the Prompt Security extension). The HTML report opens with
    a detection summary that explains the scoring and what was found.

    Only AI-related history is reported, aggregated per site. Full URLs and page titles are written only with
    -IncludeUrls. Make sure browsing review is covered by the customer's acceptable-use / monitoring policy.

    Run elevated (or as SYSTEM from an RMM) to cover every user profile on the machine; otherwise only the
    current user is checked. Nothing on the machine is changed apart from writing the report folder; history
    databases are copied to a temp folder, read there, and the copies deleted.

.PARAMETER Days
    How far back to read browser history. Default 30.

.PARAMETER OutputPath
    Report folder. Default: %ProgramData%\RogueAIAudit\<COMPUTER>_<timestamp> (falls back to %TEMP%).

.PARAMETER IncludeUrls
    Also write HistoryDetail.csv with every matching URL, page title and visit time.

.PARAMETER ScanModelFiles
    Also search each profile for large local model files (*.gguf, *.safetensors, *.ggml, *.onnx over 100 MB). Slower.

.PARAMETER NoOpen
    Don't open the HTML report when the run finishes. It is never opened when running as SYSTEM or non-interactively.

.PARAMETER PromptDays
    Only scan prompt/cache files changed in the last N days. Default 90.

.PARAMETER MaxFileMB
    Skip prompt/cache files larger than this (and cap text pulled from chat databases). Default 64.

.PARAMETER Keywords
    Customer-specific terms to flag as High (project code names, client names, product names).

.PARAMETER KeywordFile
    Text file with one customer keyword per line (added to -Keywords).

.PARAMETER NoSnippets
    Leave masked context snippets out of the report (masked example values are still shown).

.PARAMETER SkipPromptScan
    Run only the inventory (no tool is rated; all show "Not checked").

.PARAMETER FullTranscripts
    For Claude Code / Codex JSONL transcripts, scan everything (tool output, file contents read by the agent) instead
    of only the lines a person typed. Much slower on heavy users (gigabytes of transcripts).

.PARAMETER FailOnSensitiveData
    Exit with code 1 when any Critical or High data finding exists (for RMM monitors). Default exit code is 0.

.PARAMETER ProfilePath
    Scan only this folder as a user profile (testing, or a mounted disk image) instead of the machine's profiles.

.OUTPUTS
    An HTML report (RogueAI-Report_<COMPUTER>_<timestamp>.html) saved in the script's own folder and opened in the
    default browser, plus Findings.csv, DataFindings.csv and Summary.json in -OutputPath. If the script folder is
    read-only, the HTML goes to -OutputPath instead.

.EXAMPLE
    .\Find-RogueAI.ps1
    Audit with defaults (30 days of history, 90 days of prompt files), report under %ProgramData%\RogueAIAudit.

.EXAMPLE
    .\Find-RogueAI.ps1 -Days 90 -Keywords 'Project Falcon','Contoso' -FailOnSensitiveData
    Also flag customer keywords as High and fail the RMM check if any Critical or High data is found.

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. History is read through Windows' built-in winsqlite3.dll; if that is
    unavailable the script falls back to a raw scan of the database file (sites found, but no visit dates or counts).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$Days = 30,
    [string]$OutputPath,
    [switch]$IncludeUrls,
    [switch]$ScanModelFiles,
    [switch]$NoOpen,
    [ValidateRange(1, 3650)][int]$PromptDays = 90,
    [ValidateRange(1, 4096)][int]$MaxFileMB = 64,
    [string[]]$Keywords = @(),
    [string]$KeywordFile,
    [switch]$NoSnippets,
    [switch]$SkipPromptScan,
    [switch]$FullTranscripts,
    [switch]$FailOnSensitiveData,
    [string]$ProfilePath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

#region Catalogs (edit these to tune detection)

# Websites. Domain matches itself and every subdomain. Path (regex) narrows a match on shared domains.
$SiteCatalog = @'
Domain;Name;Category;Path
chatgpt.com;ChatGPT;Chat assistant;
chat.openai.com;ChatGPT;Chat assistant;
openai.com;OpenAI;Chat assistant;
platform.openai.com;OpenAI API platform;Developer API;
sora.com;OpenAI Sora;Image/video generation;
claude.ai;Claude;Chat assistant;
claude.com;Claude;Chat assistant;
console.anthropic.com;Anthropic API console;Developer API;
gemini.google.com;Google Gemini;Chat assistant;
bard.google.com;Google Gemini;Chat assistant;
aistudio.google.com;Google AI Studio;Developer API;
notebooklm.google.com;NotebookLM;Research assistant;
labs.google;Google Labs;Image/video generation;
copilot.microsoft.com;Microsoft Copilot;Chat assistant;
m365.cloud.microsoft;Microsoft 365 Copilot;Chat assistant;
copilot.cloud.microsoft;Microsoft 365 Copilot;Chat assistant;
bing.com;Copilot in Bing;Chat assistant;^/chat
github.com;GitHub Copilot;Code assistant;^/copilot
x.com;Grok on X;Chat assistant;^/i/grok
grok.com;Grok;Chat assistant;
x.ai;xAI;Chat assistant;
meta.ai;Meta AI;Chat assistant;
mistral.ai;Mistral Le Chat;Chat assistant;
perplexity.ai;Perplexity / Comet;Search assistant;
you.com;You.com;Search assistant;
pi.ai;Pi;Chat assistant;
phind.com;Phind;Code assistant;
deepai.org;DeepAI;Chat assistant;
poe.com;Poe;Model aggregator;
openrouter.ai;OpenRouter;Model aggregator;
huggingface.co;Hugging Face;Model hub;
civitai.com;Civitai;Model hub;
together.ai;Together AI;Developer API;
groq.com;Groq;Developer API;
fireworks.ai;Fireworks AI;Developer API;
replicate.com;Replicate;Developer API;
fal.ai;fal;Developer API;
cohere.com;Cohere;Developer API;
deepseek.com;DeepSeek;Chat assistant;
kimi.com;Kimi (Moonshot);Chat assistant;
moonshot.cn;Kimi (Moonshot);Chat assistant;
qwen.ai;Qwen (Alibaba);Chat assistant;
tongyi.aliyun.com;Tongyi Qianwen (Alibaba);Chat assistant;
doubao.com;Doubao (ByteDance);Chat assistant;
yiyan.baidu.com;ERNIE Bot (Baidu);Chat assistant;
chatglm.cn;ChatGLM (Zhipu);Chat assistant;
z.ai;Z.ai (Zhipu);Chat assistant;
minimax.io;MiniMax;Chat assistant;
hailuoai.com;Hailuo AI (MiniMax);Image/video generation;
klingai.com;Kling AI (Kuaishou);Image/video generation;
trae.ai;Trae (ByteDance);Code assistant;
manus.im;Manus;AI agent;
genspark.ai;Genspark;AI agent;
character.ai;Character.AI;AI companion;
janitorai.com;Janitor AI;AI companion;
replika.com;Replika;AI companion;
crushon.ai;CrushOn.AI;AI companion;
undetectable.ai;Undetectable AI;AI humanizer;
stealthgpt.ai;StealthGPT;AI humanizer;
stealthwriter.ai;StealthWriter;AI humanizer;
chatpdf.com;ChatPDF;Document upload AI;
humata.ai;Humata;Document upload AI;
jasper.ai;Jasper;Writing assistant;
copy.ai;Copy.ai;Writing assistant;
writesonic.com;Writesonic;Writing assistant;
rytr.me;Rytr;Writing assistant;
quillbot.com;QuillBot;Writing assistant;
wordtune.com;Wordtune;Writing assistant;
grammarly.com;Grammarly;Writing assistant;
gamma.app;Gamma;Presentation AI;
tome.app;Tome;Presentation AI;
beautiful.ai;Beautiful.ai;Presentation AI;
otter.ai;Otter.ai;Meeting transcription;
fireflies.ai;Fireflies.ai;Meeting transcription;
fathom.video;Fathom;Meeting transcription;
tldv.io;tl;dv;Meeting transcription;
read.ai;Read AI;Meeting transcription;
krisp.ai;Krisp;Meeting transcription;
midjourney.com;Midjourney;Image/video generation;
leonardo.ai;Leonardo.Ai;Image/video generation;
ideogram.ai;Ideogram;Image/video generation;
runwayml.com;Runway;Image/video generation;
pika.art;Pika;Image/video generation;
lumalabs.ai;Luma AI;Image/video generation;
krea.ai;Krea;Image/video generation;
stability.ai;Stability AI;Image/video generation;
firefly.adobe.com;Adobe Firefly;Image/video generation;
heygen.com;HeyGen;Image/video generation;
synthesia.io;Synthesia;Image/video generation;
elevenlabs.io;ElevenLabs;Voice/music generation;
suno.com;Suno;Voice/music generation;
udio.com;Udio;Voice/music generation;
cursor.com;Cursor;Code assistant;
windsurf.com;Windsurf / Codeium;Code assistant;
codeium.com;Windsurf / Codeium;Code assistant;
tabnine.com;Tabnine;Code assistant;
replit.com;Replit;Code assistant;
blackbox.ai;Blackbox AI;Code assistant;
bolt.new;Bolt;App builder;
lovable.dev;Lovable;App builder;
v0.dev;v0;App builder;
v0.app;v0;App builder;
monica.im;Monica;Browser assistant;
sider.ai;Sider;Browser assistant;
maxai.me;MaxAI;Browser assistant;
harpa.ai;HARPA AI;Browser assistant;
getmerlin.in;Merlin;Browser assistant;
'@ | ConvertFrom-Csv -Delimiter ';'

# Unknown hosts matching this are reported as 'Possible AI site (keyword)' (likely ChatGPT clones / wrappers).
$KeywordHostPattern = '(chat-?gpt|gpt-?[0-9o]|openai|llm|chatbot|ai-?chat|\.ai$)'

# Desktop apps. Pattern (regex) is tested against uninstall DisplayName, Store package name and process name.
$AppCatalog = @'
Name;Pattern;Category
ChatGPT desktop;^ChatGPT|OpenAI\.ChatGPT;Chat assistant
Claude desktop;^Claude$|^Claude |AnthropicClaude|Claude_pzs8sxrjxfjjc;Chat assistant
Microsoft 365 Copilot;Microsoft 365 Copilot|Microsoft\.MicrosoftOfficeHub;Chat assistant
Microsoft Copilot;^Microsoft\.Copilot$|^Copilot$|^Microsoft Copilot;Chat assistant
Perplexity / Comet;Perplexity|^Comet$;Search assistant
DeepSeek;DeepSeek;Chat assistant
Kimi;\bKimi\b;Chat assistant
Doubao;Doubao;Chat assistant
Ollama;Ollama;Local LLM runtime
LM Studio;LM.?Studio;Local LLM runtime
GPT4All;GPT4All;Local LLM runtime
Jan;^Jan$|^Jan \d;Local LLM runtime
AnythingLLM;AnythingLLM;Local LLM runtime
Msty;^Msty;Local LLM runtime
KoboldCpp;kobold;Local LLM runtime
llama.cpp / llamafile;^llama-(server|cli)$|llamafile;Local LLM runtime
text-generation-webui;oobabooga|text-generation-webui;Local LLM runtime
Local image generation;ComfyUI|Stable.?Diffusion|Fooocus|InvokeAI|Automatic1111;Image/video generation
Cursor;^Cursor$|^Cursor \(|Anysphere;Code assistant
Windsurf / Codeium;Windsurf|Codeium;Code assistant
Trae (ByteDance);^Trae( |$);Code assistant
Tabnine;Tabnine;Code assistant
Pieces;^Pieces( |$)|Pieces OS;Code assistant
Grammarly;Grammarly;Writing assistant
Otter.ai;Otter\.ai|^Otter$;Meeting transcription
Fireflies;Fireflies;Meeting transcription
Krisp;^Krisp;Meeting transcription
Fathom;^Fathom;Meeting transcription
Poe;^Poe$;Model aggregator
'@ | ConvertFrom-Csv -Delimiter ';'

# Per-user paths (relative to the profile) that show an AI tool is or was installed. Size=1 reports folder size.
$UserIndicators = @'
Rel;Name;Category;Size
AppData\Local\AnthropicClaude;Claude desktop;Chat assistant;0
AppData\Local\Programs\Ollama;Ollama;Local LLM runtime;0
.ollama\models;Ollama model store;Local model files;1
AppData\Local\Programs\LM Studio;LM Studio;Local LLM runtime;0
.lmstudio\models;LM Studio model store;Local model files;1
.cache\lm-studio\models;LM Studio model store;Local model files;1
AppData\Local\nomic.ai\GPT4All;GPT4All model store;Local model files;1
AppData\Roaming\Jan;Jan;Local LLM runtime;0
AppData\Roaming\anythingllm-desktop;AnythingLLM;Local LLM runtime;0
AppData\Roaming\Msty;Msty;Local LLM runtime;0
.cache\huggingface\hub;Hugging Face model cache;Local model files;1
AppData\Local\Programs\cursor;Cursor;Code assistant;0
AppData\Local\Programs\Windsurf;Windsurf;Code assistant;0
AppData\Local\Programs\Trae;Trae (ByteDance);Code assistant;0
.claude;Claude Code CLI;AI CLI agent;0
.codex;OpenAI Codex CLI;AI CLI agent;0
.gemini;Gemini CLI;AI CLI agent;0
.continue;Continue (IDE assistant);Code assistant;0
AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code;Claude Code CLI (npm);AI CLI agent;0
AppData\Roaming\npm\node_modules\@openai\codex;OpenAI Codex CLI (npm);AI CLI agent;0
AppData\Roaming\npm\node_modules\@google\gemini-cli;Gemini CLI (npm);AI CLI agent;0
'@ | ConvertFrom-Csv -Delimiter ';'

# VS Code-family extension IDs (folder name prefix).
$IdeExtensionPattern = '^(github\.copilot|continue\.|codeium\.|saoudrizwan\.claude-dev|rooveterinaryinc\.roo-cline|kilocode\.|tabnine\.|anthropic\.|openai\.|amazonwebservices\.amazon-q|google\.geminicodeassist|sourcegraph\.cody|blackboxapp\.|danielsanmedium\.dscodegpt|genieai\.|ms-windows-ai-studio\.)'

# Browser extension names.
$ExtensionNamePattern = '\b(AI|GPT|ChatGPT|Claude|Gemini|Copilot|Perplexity|Bard|LLM|Monica|Merlin|Sider|MaxAI|HARPA|Grammarly|QuillBot|Wordtune|Otter|Fireflies|tl;?dv|Liner|Glasp|DeepSeek|Poe)\b'

$ChromiumBrowsers = @(
    @{ Name = 'Chrome';   Rel = 'AppData\Local\Google\Chrome\User Data' }
    @{ Name = 'Edge';     Rel = 'AppData\Local\Microsoft\Edge\User Data' }
    @{ Name = 'Brave';    Rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
    @{ Name = 'Vivaldi';  Rel = 'AppData\Local\Vivaldi\User Data' }
    @{ Name = 'Chromium'; Rel = 'AppData\Local\Chromium\User Data' }
    @{ Name = 'Opera';    Rel = 'AppData\Roaming\Opera Software\Opera Stable' }
    @{ Name = 'Opera GX'; Rel = 'AppData\Roaming\Opera Software\Opera GX Stable' }
)
$FirefoxBrowsers = @(
    @{ Name = 'Firefox';   Rel = 'AppData\Roaming\Mozilla\Firefox\Profiles' }
    @{ Name = 'Waterfox';  Rel = 'AppData\Roaming\Waterfox\Profiles' }
    @{ Name = 'LibreWolf'; Rel = 'AppData\Roaming\librewolf\Profiles' }
    @{ Name = 'Zen';       Rel = 'AppData\Roaming\zen\Profiles' }
)

#endregion

#region Helpers

$Findings = New-Object System.Collections.Generic.List[object]
$DataFindings = New-Object System.Collections.Generic.List[object]
$AiTitles = @{}
$ScannedPairs = @{}      # "User|Tool" -> $true when a file for that tool was actually read (even with zero hits)
$ToolCategory = @{}      # Tool -> category, learned while scanning (used for tools found only through their data)
$PromptScanRan = $false
$DataRules = $null
$HistoryDetail = New-Object System.Collections.Generic.List[object]
$Notes = New-Object System.Collections.Generic.List[string]

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Inventory item names that are the same product as a prompt-store tool share one Tool key, so a finding links to the
# data found in that tool's own caches.
$ToolAlias = @{
    'Claude Code CLI (npm)'     = 'Claude Code CLI'
    'OpenAI Codex CLI (npm)'    = 'OpenAI Codex CLI'
    'Gemini CLI (npm)'          = 'Gemini CLI'
    'Ollama model store'        = 'Ollama'
    'LM Studio model store'     = 'LM Studio'
    'GPT4All model store'       = 'GPT4All'
    'Continue (IDE assistant)'  = 'Continue'
    'Windsurf'                  = 'Windsurf / Codeium'
}

# IDE extension id (folder name prefix) -> Tool key.
function Get-IdeToolName([string]$Id) {
    switch -Regex ($Id) {
        '^github\.copilot'                                                { return 'GitHub Copilot' }
        '^continue\.'                                                     { return 'Continue' }
        '^codeium\.'                                                      { return 'Windsurf / Codeium' }
        '^(saoudrizwan\.claude-dev|rooveterinaryinc\.roo-cline|kilocode\.)' { return 'Cline / Roo / Kilo' }
    }
    $Id
}

# Risk is only set here for informational rows ('Info'); every other rating is computed from the data found (see Report).
function Add-Finding {
    param(
        [string]$User, [string]$Source, [string]$Category, [string]$Item, [string]$Detail, [string]$Risk = '',
        $Count = $null, $FirstSeen = $null, $LastSeen = $null, [string]$Tool = ''
    )
    if (-not $Tool) { $Tool = if ($ToolAlias.ContainsKey($Item)) { $ToolAlias[$Item] } else { $Item } }
    $Findings.Add([pscustomobject]@{
        Computer  = $env:COMPUTERNAME
        User      = $User
        Tool      = $Tool
        Source    = $Source
        Category  = $Category
        Item      = $Item
        Detail    = $Detail
        Risk      = $Risk
        DataHits  = 0
        Count     = $Count
        FirstSeen = $FirstSeen
        LastSeen  = $LastSeen
    })
}

function Find-AppMatch([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    foreach ($a in $AppCatalog) { if ($Name -match $a.Pattern) { return $a } }
    $null
}

$SiteIndex = @{}
foreach ($s in $SiteCatalog) {
    $key = $s.Domain.ToLowerInvariant()
    if (-not $SiteIndex.ContainsKey($key)) { $SiteIndex[$key] = New-Object System.Collections.ArrayList }
    [void]$SiteIndex[$key].Add($s)
}

# Walks host -> parent domains. Entries with a Path only match when a path is supplied and matches.
function Find-SiteMatch([string]$HostName, [string]$PathAndQuery) {
    $h = $HostName.ToLowerInvariant().TrimEnd('.')
    while ($h) {
        if ($SiteIndex.ContainsKey($h)) {
            foreach ($e in $SiteIndex[$h]) {
                if ([string]::IsNullOrEmpty($e.Path)) { return $e }
                if ($PathAndQuery -and $PathAndQuery -match $e.Path) { return $e }
            }
        }
        $i = $h.IndexOf('.')
        if ($i -lt 0) { break }
        $h = $h.Substring($i + 1)
    }
    $null
}

function Get-FolderSizeGB([string]$Path) {
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { $sum = 0 }
    [math]::Round($sum / 1GB, 2)
}

# Copies a file the browser may hold open.
function Copy-LockedFile([string]$Source, [string]$Destination) {
    $in = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    try {
        $out = [IO.File]::Create($Destination)
        try { $in.CopyTo($out) } finally { $out.Dispose() }
    } finally { $in.Dispose() }
}

function Copy-SqliteDb([string]$Source) {
    $dest = Join-Path $TempDir ([guid]::NewGuid().ToString('N') + '.db')
    Copy-LockedFile $Source $dest
    foreach ($suffix in '-wal', '-journal') {
        if (Test-Path -LiteralPath ($Source + $suffix)) {
            try { Copy-LockedFile ($Source + $suffix) ($dest + $suffix) } catch { }
        }
    }
    $dest
}

$SqliteAvailable = $false
if (Test-Path (Join-Path ([Environment]::SystemDirectory) 'winsqlite3.dll')) {
    try {
        if (-not ('RogueAiSqlite2' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class RogueAiSqlite2 {
    [DllImport("winsqlite3.dll", CharSet = CharSet.Unicode)] static extern int sqlite3_open16(string filename, out IntPtr db);
    [DllImport("winsqlite3.dll")] static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", CharSet = CharSet.Unicode)] static extern int sqlite3_prepare16_v2(IntPtr db, string sql, int nBytes, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll")] static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll")] static extern int sqlite3_column_count(IntPtr stmt);
    [DllImport("winsqlite3.dll")] static extern IntPtr sqlite3_column_text16(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll")] static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport("winsqlite3.dll")] static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll")] static extern IntPtr sqlite3_errmsg16(IntPtr db);

    static string Err(IntPtr db) {
        IntPtr p = sqlite3_errmsg16(db);
        return p == IntPtr.Zero ? "unknown error" : Marshal.PtrToStringUni(p);
    }

    public static List<string[]> Query(string path, string sql) {
        IntPtr db;
        if (sqlite3_open16(path, out db) != 0) {
            string e = Err(db); sqlite3_close(db);
            throw new Exception("open failed: " + e);
        }
        return Run(db, sql);
    }

    // Opens the live file read-only without locking (immutable=1), so large or in-use databases need no copy.
    public static List<string[]> QueryImmutable(string path, string sql) {
        string p = path.Replace('\\', '/').Replace("%", "%25").Replace("?", "%3f").Replace("#", "%23").Replace(" ", "%20");
        byte[] name = Encoding.UTF8.GetBytes("file:///" + p + "?immutable=1\0");
        IntPtr db;
        if (sqlite3_open_v2(name, out db, 0x01 | 0x40, IntPtr.Zero) != 0) {
            string e = Err(db); sqlite3_close(db);
            throw new Exception("open failed: " + e);
        }
        return Run(db, sql);
    }

    static List<string[]> Run(IntPtr db, string sql) {
        try {
            IntPtr stmt;
            if (sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero) != 0) throw new Exception("prepare failed: " + Err(db));
            List<string[]> rows = new List<string[]>();
            try {
                int n = sqlite3_column_count(stmt);
                int rc;
                while ((rc = sqlite3_step(stmt)) == 100) {
                    string[] row = new string[n];
                    for (int i = 0; i < n; i++) {
                        IntPtr p = sqlite3_column_text16(stmt, i);
                        row[i] = p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
                    }
                    rows.Add(row);
                }
                if (rc != 101) throw new Exception("step failed: " + Err(db));
            } finally { sqlite3_finalize(stmt); }
            return rows;
        } finally { sqlite3_close(db); }
    }
}
'@
        }
        $SqliteAvailable = $true
    } catch {
        $Notes.Add("winsqlite3 could not be loaded ($($_.Exception.Message)); using raw history scan.")
    }
} else {
    $Notes.Add('winsqlite3.dll not found; using raw history scan (no visit dates or counts).')
}

# Binary helpers for the prompt scan: printable-string extraction and LevelDB table (.ldb) decoding.
$DataHelpersAvailable = $false
try {
    if (-not ('RogueAiData2' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

public class ScanHit2 { public string Value; public int Index; public int Length; }
public class ScanResult2 { public int Count; public int Unique; public bool Stopped; public List<ScanHit2> Samples = new List<ScanHit2>(); }

// Rule matching and validators run here (not in PowerShell) so multi-GB prompt stores scan in reasonable time.
public static class RogueAiScan2 {
    static readonly HashSet<string> TestCards = new HashSet<string> {
        "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "5555555555554444",
        "5105105105105100", "5200828282828210", "2223003122003222", "378282246310005", "371449635398431",
        "6011111111111117", "6011000990139424", "3530111333300000", "30569309025904", "38520000023237" };
    static readonly Regex CardPrefix = new Regex("^(4|5[1-5]|2[2-7]|3[47]|6011|65|64[4-9]|35|30[0-5]|36|38)");
    static readonly Regex Placeholder = new Regex(@"^(x+|\*+|\.+|0+|<.*>?|\$.*|%.*%|\{\{.*)$", RegexOptions.IgnoreCase);
    static readonly Regex PlaceholderWord = new Regex("^(your|my|example|sample|placeholder|changeme|redacted|dummy|test|fake|null|none|undefined|string|password|secret|token|true|false)", RegexOptions.IgnoreCase);
    static readonly Regex EmailSkip = new Regex(@"noreply|no-reply|@example\.|@users\.noreply|@anthropic\.com$|\.(png|jpg|gif|svg|webp)$", RegexOptions.IgnoreCase);
    static readonly Regex UserLine = new Regex("\"(?:role|type)\"\\s*:\\s*\"user\"");

    static string Digits(string v) {
        StringBuilder sb = new StringBuilder();
        foreach (char c in v) if (c >= '0' && c <= '9') sb.Append(c);
        return sb.ToString();
    }
    static bool HasDigit(string v) { foreach (char c in v) if (c >= '0' && c <= '9') return true; return false; }
    static bool HasLetter(string v) { foreach (char c in v) if (char.IsLetter(c)) return true; return false; }
    static bool HasSymbol(string v) { foreach (char c in v) if (!char.IsLetterOrDigit(c)) return true; return false; }
    static bool MixedCase(string v) {
        bool up = false, low = false;
        foreach (char c in v) { if (char.IsUpper(c)) up = true; else if (char.IsLower(c)) low = true; }
        return up && low;
    }
    static readonly Regex EnvName = new Regex("^[A-Z][A-Z0-9_]+$");

    static bool Luhn(string d) {
        int sum = 0; bool alt = false;
        for (int i = d.Length - 1; i >= 0; i--) {
            int n = d[i] - '0';
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n; alt = !alt;
        }
        return sum % 10 == 0;
    }
    static bool Card(string v) {
        string d = Digits(v);
        if (d.Length < 13 || d.Length > 19 || !CardPrefix.IsMatch(d) || TestCards.Contains(d)) return false;
        if (d.Replace(d[0].ToString(), "").Length == 0) return false;
        return Luhn(d);
    }
    static bool Ssn(string v) {
        string d = Digits(v);
        if (d.Length != 9) return false;
        int area = int.Parse(d.Substring(0, 3));
        if (area == 0 || area == 666 || area >= 900) return false;
        if (d.Substring(3, 2) == "00" || d.Substring(5) == "0000") return false;
        return d != "123456789" && d != "078051120" && d != "219099999";   // well-known example numbers
    }
    static bool Aba(string v) {
        string d = Digits(v);
        if (d.Length != 9) return false;
        int pre = int.Parse(d.Substring(0, 2));
        if (!(pre <= 12 || (pre >= 21 && pre <= 32) || (pre >= 61 && pre <= 72) || pre == 80)) return false;
        int[] n = new int[9]; int total = 0;
        for (int i = 0; i < 9; i++) { n[i] = d[i] - '0'; total += n[i]; }
        if (total == 0) return false;
        return (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + (n[2] + n[5] + n[8])) % 10 == 0;
    }
    static bool Iban(string v) {
        string s = v.Replace(" ", "").ToUpperInvariant();
        if (s.Length < 15 || s.Length > 34) return false;
        int m = 0;
        foreach (char c in s.Substring(4) + s.Substring(0, 4)) {
            if (c >= '0' && c <= '9') m = (m * 10 + (c - '0')) % 97;
            else if (c >= 'A' && c <= 'Z') m = (m * 100 + (c - 'A' + 10)) % 97;
            else return false;
        }
        return m == 1;
    }
    static bool Secret(string v) {
        if (Placeholder.IsMatch(v) || PlaceholderWord.IsMatch(v)) return false;
        return v.IndexOfAny(new char[] { '(', ')', '[', ']' }) < 0;   // code such as getpass() or os.environ[...]
    }

    public static bool Check(string name, string v) {
        switch (name) {
            case "card": return Card(v);
            case "ssn": return Ssn(v);
            case "aba": return Aba(v);
            case "iban": return Iban(v);
            case "secret": return Secret(v);
            case "secretmixed": return Secret(v) && HasDigit(v) && HasLetter(v);
            // a real password has a digit, symbol or mixed case; plain words ("replaced") and ENV_VAR names do not count
            case "password": {
                string w = v.TrimEnd('.', ',', '!', '?', ':', ';', ')', '\'', '"', '`');   // sentence punctuation is not part of it
                return w.Length >= 6 && Secret(w) && !EnvName.IsMatch(w) && (HasDigit(w) || HasSymbol(w) || MixedCase(w));
            }
            case "digit": return HasDigit(v);
            case "email": return !EmailSkip.IsMatch(v);
            default: return true;
        }
    }

    public static ScanResult2 Run(string text, Regex rx, int group, string check, int maxSamples, int maxHits) {
        ScanResult2 r = new ScanResult2();
        HashSet<string> seen = new HashSet<string>();
        try {
            Match m = rx.Match(text);
            while (m.Success) {
                Group g = (group > 0 && m.Groups[group].Success) ? m.Groups[group] : (Group)m;
                if (Check(check, g.Value)) {
                    r.Count++;
                    if (seen.Add(g.Value.ToLowerInvariant()) && r.Samples.Count < maxSamples)
                        r.Samples.Add(new ScanHit2 { Value = g.Value, Index = g.Index, Length = g.Length });
                    if (r.Count >= maxHits) { r.Stopped = true; break; }
                }
                m = m.NextMatch();
            }
        } catch (RegexMatchTimeoutException) { r.Stopped = true; }
        r.Unique = seen.Count;
        return r;
    }

    // Undo JSON escaping (\n, \t, \", \\, \uXXXX) so patterns see the real text.
    public static string DecodeJson(string t) {
        StringBuilder sb = new StringBuilder(t.Length);
        for (int i = 0; i < t.Length; i++) {
            char c = t[i];
            if (c != '\\' || i + 1 >= t.Length) { sb.Append(c); continue; }
            char n = t[i + 1];
            if (n == 'n' || n == 'r' || n == 't') { sb.Append(' '); i++; }
            else if (n == '"' || n == '\\' || n == '/') { sb.Append(n); i++; }
            else if (n == 'u' && i + 5 < t.Length) {
                int code;
                if (int.TryParse(t.Substring(i + 2, 4), System.Globalization.NumberStyles.HexNumber, null, out code)) { sb.Append((char)code); i += 5; }
                else sb.Append(c);
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // JSONL transcripts: keep only lines a person typed (role/type "user"), not tool results fed back to the model.
    public static string UserLines(string t) {
        StringBuilder sb = new StringBuilder();
        foreach (string line in t.Split('\n')) {
            if (!UserLine.IsMatch(line)) continue;
            if (line.Contains("\"tool_result\"") || line.Contains("\"toolUseResult\"") || line.Contains("function_call_output")) continue;
            sb.Append(line).Append('\n');
        }
        return sb.ToString();
    }
}

public static class RogueAiData2 {
    // ASCII runs plus UTF-16LE runs (both byte alignments), one per line.
    public static string Strings(byte[] b, int min) {
        StringBuilder sb = new StringBuilder();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < b.Length; i++) {
            byte c = b[i];
            if ((c >= 0x20 && c < 0x7f) || c == 9) { cur.Append((char)c); }
            else { if (cur.Length >= min) sb.Append(cur).Append('\n'); cur.Length = 0; }
        }
        if (cur.Length >= min) sb.Append(cur).Append('\n');
        for (int start = 0; start < 2; start++) {
            cur.Length = 0;
            for (int i = start; i + 1 < b.Length; i += 2) {
                int ch = b[i] | (b[i + 1] << 8);
                if ((ch >= 0x20 && ch < 0x7f) || (ch >= 0xa0 && ch < 0x2000)) { cur.Append((char)ch); }
                else { if (cur.Length >= min) sb.Append(cur).Append('\n'); cur.Length = 0; }
            }
            if (cur.Length >= min) sb.Append(cur).Append('\n');
        }
        return sb.ToString();
    }

    static ulong Varint(byte[] b, ref int p) {
        ulong v = 0; int shift = 0;
        while (true) {
            byte x = b[p++];
            v |= (ulong)(x & 0x7f) << shift;
            if ((x & 0x80) == 0) return v;
            shift += 7;
            if (shift > 63) throw new InvalidDataException("bad varint");
        }
    }

    public static byte[] Snappy(byte[] src, int start, int len) {
        int pos = start, end = start + len;
        int ulen = (int)Varint(src, ref pos);
        byte[] dst = new byte[ulen];
        int d = 0;
        while (pos < end) {
            byte tag = src[pos++];
            int type = tag & 3;
            if (type == 0) {
                int l = tag >> 2;
                if (l >= 60) { int nb = l - 59; l = 0; for (int i = 0; i < nb; i++) l |= src[pos++] << (8 * i); }
                l += 1;
                Buffer.BlockCopy(src, pos, dst, d, l); pos += l; d += l;
            } else {
                int l, off;
                if (type == 1) { l = ((tag >> 2) & 7) + 4; off = ((tag >> 5) << 8) | src[pos++]; }
                else if (type == 2) { l = (tag >> 2) + 1; off = src[pos] | (src[pos + 1] << 8); pos += 2; }
                else { l = (tag >> 2) + 1; off = src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16) | (src[pos + 3] << 24); pos += 4; }
                if (off <= 0 || off > d) throw new InvalidDataException("bad snappy offset");
                for (int i = 0; i < l; i++) { dst[d] = dst[d - off]; d++; }
            }
        }
        return dst;
    }

    static byte[] Block(byte[] f, int off, int size) {
        byte type = f[off + size];
        if (type == 1) return Snappy(f, off, size);
        byte[] b = new byte[size];
        Buffer.BlockCopy(f, off, b, 0, size);
        return b;
    }

    // Decompresses every data block of a LevelDB table file; returns the input unchanged if it is not one.
    public static byte[] ReadLdb(byte[] f) {
        if (f.Length < 48 || BitConverter.ToUInt64(f, f.Length - 8) != 0xdb4775248b80fb57UL) return f;
        try {
            int p = f.Length - 48;
            Varint(f, ref p); Varint(f, ref p);
            int io = (int)Varint(f, ref p), isz = (int)Varint(f, ref p);
            byte[] index = Block(f, io, isz);
            int nRestarts = BitConverter.ToInt32(index, index.Length - 4);
            int limit = index.Length - 4 - 4 * nRestarts;
            MemoryStream ms = new MemoryStream();
            int q = 0;
            while (q < limit) {
                Varint(index, ref q);
                int nonShared = (int)Varint(index, ref q), vlen = (int)Varint(index, ref q);
                q += nonShared;
                int vp = q;
                int bo = (int)Varint(index, ref vp), bs = (int)Varint(index, ref vp);
                q += vlen;
                try { byte[] blk = Block(f, bo, bs); ms.Write(blk, 0, blk.Length); ms.WriteByte(10); } catch { }
            }
            return ms.ToArray();
        } catch { return f; }
    }
}
'@
    }
    $DataHelpersAvailable = $true
} catch {
    $Notes.Add("Binary decoder could not be loaded ($($_.Exception.Message)); app/browser storage was not scanned.")
}

#endregion

#region Setup

$IsAdmin = Test-IsAdmin
$Started = Get-Date
$CutoffUtc = $Started.ToUniversalTime().AddDays(-$Days)

if (-not $OutputPath) {
    $OutputPath = Join-Path $env:ProgramData ('RogueAIAudit\{0}_{1}' -f $env:COMPUTERNAME, $Started.ToString('yyyyMMdd-HHmmss'))
}
try {
    New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
} catch {
    $OutputPath = Join-Path $env:TEMP ('RogueAIAudit_{0}_{1}' -f $env:COMPUTERNAME, $Started.ToString('yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
}
$TempDir = Join-Path $env:TEMP ('RogueAI_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

if ($ProfilePath) {
    $resolved = (Resolve-Path -LiteralPath $ProfilePath -ErrorAction Stop).Path
    $Profiles = @([pscustomobject]@{ User = Split-Path $resolved -Leaf; Path = $resolved; Sid = '' })
    $Notes.Add("Profile scan limited to $resolved (-ProfilePath).")
} elseif ($IsAdmin) {
    $Profiles = @(Get-CimInstance Win32_UserProfile -Filter 'Special=False' -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and $_.LocalPath -notlike "$env:windir*" -and (Test-Path -LiteralPath $_.LocalPath) } |
        ForEach-Object { [pscustomobject]@{ User = Split-Path $_.LocalPath -Leaf; Path = $_.LocalPath; Sid = $_.SID } })
} else {
    $Profiles = @([pscustomobject]@{
        User = $env:USERNAME; Path = $env:USERPROFILE
        Sid  = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    })
    $Notes.Add('Not elevated: only the current user profile was checked. Run as admin or SYSTEM to cover all users.')
}
$SidToUser = @{}
foreach ($p in $Profiles) { $SidToUser[$p.Sid] = $p.User }

Write-Output ("Rogue AI audit on {0} | elevated: {1} | profiles: {2} | history window: {3} days" -f
    $env:COMPUTERNAME, $IsAdmin, (($Profiles | ForEach-Object User) -join ', '), $Days)

#endregion

try {

#region Installed apps

    $uninstallKeys = @(
        @{ User = '(machine)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
        @{ User = '(machine)'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    )
    if ($IsAdmin) {
        Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object {
                $u = if ($SidToUser.ContainsKey($_.PSChildName)) { $SidToUser[$_.PSChildName] } else { $_.PSChildName }
                $uninstallKeys += @{ User = $u; Path = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
            }
    } else {
        $uninstallKeys += @{ User = $env:USERNAME; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    }
    foreach ($k in $uninstallKeys) {
        Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.DisplayName
            $m = Find-AppMatch $name
            if ($m) {
                Add-Finding -User $k.User -Source 'Installed program' -Category $m.Category -Item $name -Tool $m.Name `
                    -Detail (('{0} {1} {2}' -f $_.Publisher, $_.DisplayVersion, $_.InstallLocation).Trim())
            }
        }
    }

    try {
        $pkgs = if ($IsAdmin) { Get-AppxPackage -AllUsers -ErrorAction Stop } else { Get-AppxPackage -ErrorAction Stop }
        foreach ($p in $pkgs) {
            $m = Find-AppMatch $p.Name
            if (-not $m) { continue }
            $users = $env:USERNAME
            if ($p.PackageUserInformation) {
                $users = ($p.PackageUserInformation | ForEach-Object { $_.UserSecurityId.Username } |
                    Where-Object { $_ } | Select-Object -Unique) -join ', '
            }
            Add-Finding -User $users -Source 'Store/MSIX package' -Category $m.Category -Item $m.Name `
                -Detail "$($p.Name) $($p.Version)"
        }
    } catch {
        $Notes.Add("Store packages not checked: $($_.Exception.Message)")
    }

    $procs = try { Get-Process -IncludeUserName -ErrorAction Stop } catch { Get-Process }
    $seen = @{}
    foreach ($p in $procs) {
        $m = Find-AppMatch $p.ProcessName
        if (-not $m) { continue }
        $u = if ($p.PSObject.Properties['UserName'] -and $p.UserName) { $p.UserName } else { '' }
        $key = "$($p.ProcessName)|$u"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $path = try { $p.Path } catch { '' }
        Add-Finding -User $u -Source 'Running process' -Category $m.Category -Item $m.Name `
            -Detail "$($p.ProcessName).exe $path"
    }

#endregion

#region Per-user indicators, IDE extensions, model files

    foreach ($prof in $Profiles) {
        foreach ($ind in $UserIndicators) {
            $full = Join-Path $prof.Path $ind.Rel
            if (-not (Test-Path -LiteralPath $full)) { continue }
            $detail = $full
            if ($ind.Size -eq '1') { $detail = '{0} ({1} GB)' -f $full, (Get-FolderSizeGB $full) }
            $last = (Get-Item -LiteralPath $full -Force).LastWriteTime
            Add-Finding -User $prof.User -Source 'Profile folder' -Category $ind.Category -Item $ind.Name `
                -Detail $detail -LastSeen $last
        }

        foreach ($editor in '.vscode', '.vscode-insiders', '.cursor', '.windsurf', '.vscode-oss') {
            $extRoot = Join-Path $prof.Path "$editor\extensions"
            if (-not (Test-Path -LiteralPath $extRoot)) { continue }
            $ids = Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { if ($_.Name -match '^(.+?)-\d+\.\d+') { $matches[1].ToLowerInvariant() } } |
                Where-Object { $_ -match $IdeExtensionPattern } | Select-Object -Unique
            foreach ($id in $ids) {
                Add-Finding -User $prof.User -Source "IDE extension ($($editor.TrimStart('.')))" -Category 'Code assistant' `
                    -Item $id -Tool (Get-IdeToolName $id) -Detail $extRoot
            }
        }

        if ($ScanModelFiles) {
            Get-ChildItem -LiteralPath $prof.Path -Recurse -File -Force -Include *.gguf, *.safetensors, *.ggml, *.onnx -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 100MB } |
                Group-Object DirectoryName | ForEach-Object {
                    $gb = [math]::Round((($_.Group | Measure-Object Length -Sum).Sum) / 1GB, 2)
                    Add-Finding -User $prof.User -Source 'Model file scan' -Category 'Local model files' -Item 'Local model weights' `
                        -Count $_.Count -Detail "$($_.Name) ($gb GB): $(($_.Group | Select-Object -First 3 -ExpandProperty Name) -join ', ')" `
                        -LastSeen (($_.Group | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime)
                }
        }
    }

#endregion

#region Browser extensions

    function Get-ExtensionDisplayName($Manifest, [string]$Dir) {
        $name = [string]$Manifest.name
        if ($name -notmatch '^__MSG_(.+)__$') { return $name }
        $key = $matches[1]
        $locales = @($Manifest.default_locale, 'en', 'en_US') | Where-Object { $_ } | Select-Object -Unique
        foreach ($loc in $locales) {
            $file = Join-Path $Dir "_locales\$loc\messages.json"
            if (-not (Test-Path -LiteralPath $file)) { continue }
            try {
                $msgs = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
                $prop = $msgs.PSObject.Properties | Where-Object { $_.Name -eq $key } | Select-Object -First 1
                if ($prop -and $prop.Value.message) { return [string]$prop.Value.message }
            } catch { }
        }
        $name
    }

    function Add-ExtensionFinding([string]$User, [string]$Browser, [string]$Name, [string]$Id, [bool]$AllSites) {
        if ($Name -match 'Prompt Security') {
            Add-Finding -User $User -Source "Browser extension ($Browser)" -Category 'AI governance' -Item $Name -Risk 'Info' -Detail $Id
            return
        }
        if ($Name -notmatch $ExtensionNamePattern) { return }
        $detail = if ($AllSites) { "$Id; can read every site" } else { $Id }
        Add-Finding -User $User -Source "Browser extension ($Browser)" -Category 'Browser AI extension' -Item $Name -Detail $detail
    }

    function Get-ChromiumProfiles([string]$Root) {
        if (-not (Test-Path -LiteralPath $Root)) { return @() }
        $list = @()
        if (Test-Path -LiteralPath (Join-Path $Root 'History')) { $list += $Root }   # Opera keeps the profile at the root
        $list += Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | ForEach-Object FullName
        $list
    }

    foreach ($prof in $Profiles) {
        foreach ($b in $ChromiumBrowsers) {
            foreach ($bp in (Get-ChromiumProfiles (Join-Path $prof.Path $b.Rel))) {
                $extRoot = Join-Path $bp 'Extensions'
                if (-not (Test-Path -LiteralPath $extRoot)) { continue }
                foreach ($idDir in Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue) {
                    $ver = Get-ChildItem -LiteralPath $idDir.FullName -Directory -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if (-not $ver) { continue }
                    $mf = Join-Path $ver.FullName 'manifest.json'
                    if (-not (Test-Path -LiteralPath $mf)) { continue }
                    try { $manifest = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                    $name = Get-ExtensionDisplayName $manifest $ver.FullName
                    $hostPerms = @($manifest.permissions) + @($manifest.host_permissions) +
                        @($manifest.content_scripts | ForEach-Object { $_.matches })
                    $allSites = [bool]($hostPerms | Where-Object { $_ -in '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*' })
                    Add-ExtensionFinding $prof.User "$($b.Name)/$(Split-Path $bp -Leaf)" $name $idDir.Name $allSites
                }
            }
        }
        foreach ($b in $FirefoxBrowsers) {
            $root = Join-Path $prof.Path $b.Rel
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($fp in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                $ej = Join-Path $fp.FullName 'extensions.json'
                if (-not (Test-Path -LiteralPath $ej)) { continue }
                try { $data = Get-Content -LiteralPath $ej -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                foreach ($a in $data.addons) {
                    if ($a.type -ne 'extension' -or $a.location -in 'app-builtin', 'app-system-defaults') { continue }
                    $origins = @($a.userPermissions.origins)
                    $allSites = [bool]($origins | Where-Object { $_ -in '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*' })
                    Add-ExtensionFinding $prof.User "$($b.Name)/$($fp.Name)" ([string]$a.defaultLocale.name) $a.id $allSites
                }
            }
        }
    }

#endregion

#region Browser history

    $Agg = @{}
    function Register-Visit([string]$User, [string]$Browser, [string]$Url, [string]$Title, $VisitUtc) {
        $uri = $null
        if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return }
        if ($uri.Scheme -notin 'http', 'https') { return }
        $hostName = $uri.Host.ToLowerInvariant()
        $site = Find-SiteMatch $hostName $uri.PathAndQuery
        if ($site) {
            $item = $site.Name; $cat = $site.Category
        } elseif ($hostName -match $KeywordHostPattern) {
            $item = $hostName; $cat = 'Possible AI site (keyword)'
        } else { return }

        # AI conversation page titles often summarize the prompt; the prompt scan checks them later (per site, so the
        # data is linked to that site's tool).
        if ($site -and $Title) {
            $tk = "$User|$Browser|$($site.Name)"
            if (-not $AiTitles.ContainsKey($tk)) { $AiTitles[$tk] = @{} }
            $AiTitles[$tk][$Title] = $true
        }

        $key = "$User|$Browser|$item"
        if (-not $Agg.ContainsKey($key)) {
            $Agg[$key] = [pscustomobject]@{ User = $User; Browser = $Browser; Item = $item; Category = $cat
                Count = 0; First = $null; Last = $null; Hosts = @{} }
        }
        $a = $Agg[$key]
        $a.Count++
        $a.Hosts[$hostName] = $true
        if ($VisitUtc) {
            $local = $VisitUtc.ToLocalTime()
            if (-not $a.First -or $local -lt $a.First) { $a.First = $local }
            if (-not $a.Last -or $local -gt $a.Last) { $a.Last = $local }
        }
        if ($IncludeUrls) {
            $HistoryDetail.Add([pscustomobject]@{
                Computer = $env:COMPUTERNAME; User = $User; Browser = $Browser; Site = $item
                VisitTime = if ($VisitUtc) { $VisitUtc.ToLocalTime() } else { $null }; Title = $Title; Url = $Url
            })
        }
    }

    # Fallback: pull URL strings straight out of the database file (no dates, all-time).
    function Read-HistoryRaw([string]$User, [string]$Browser, [string]$DbCopy) {
        $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($DbCopy))
        $urls = [regex]::Matches($text, 'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&''()*+,;=%]+') | ForEach-Object Value | Select-Object -Unique
        foreach ($u in $urls) { Register-Visit $User $Browser $u '' $null }
    }

    function Read-History([string]$User, [string]$Browser, [string]$DbPath, [string]$Kind) {
        try { $copy = Copy-SqliteDb $DbPath } catch {
            $Notes.Add("Could not copy $Browser history for ${User}: $($_.Exception.Message)"); return
        }
        if ($SqliteAvailable) {
            try {
                if ($Kind -eq 'chromium') {
                    # visit_time = microseconds since 1601-01-01 UTC (FILETIME / 10)
                    $cut = [long]($CutoffUtc.ToFileTimeUtc() / 10)
                    $rows = [RogueAiSqlite2]::Query($copy, "SELECT u.url, u.title, v.visit_time FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time > $cut")
                    foreach ($r in $rows) { Register-Visit $User $Browser $r[0] $r[1] ([DateTime]::FromFileTimeUtc([long]$r[2] * 10)) }
                } else {
                    # visit_date = microseconds since 1970-01-01 UTC
                    $cut = ([DateTimeOffset]$CutoffUtc).ToUnixTimeMilliseconds() * 1000
                    $rows = [RogueAiSqlite2]::Query($copy, "SELECT p.url, p.title, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id WHERE v.visit_date > $cut")
                    foreach ($r in $rows) { Register-Visit $User $Browser $r[0] $r[1] ([DateTimeOffset]::FromUnixTimeMilliseconds([long]$r[2] / 1000).UtcDateTime) }
                }
                return
            } catch {
                $Notes.Add("SQLite read failed for $Browser ($User), used raw scan: $($_.Exception.Message)")
            }
        }
        Read-HistoryRaw $User "$Browser (raw scan, all-time)" $copy
    }

    foreach ($prof in $Profiles) {
        foreach ($b in $ChromiumBrowsers) {
            foreach ($bp in (Get-ChromiumProfiles (Join-Path $prof.Path $b.Rel))) {
                $db = Join-Path $bp 'History'
                if (Test-Path -LiteralPath $db) { Read-History $prof.User "$($b.Name)/$(Split-Path $bp -Leaf)" $db 'chromium' }
            }
        }
        foreach ($b in $FirefoxBrowsers) {
            $root = Join-Path $prof.Path $b.Rel
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($fp in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                $db = Join-Path $fp.FullName 'places.sqlite'
                if (Test-Path -LiteralPath $db) { Read-History $prof.User "$($b.Name)/$($fp.Name)" $db 'firefox' }
            }
        }
    }

    foreach ($a in $Agg.Values) {
        $hosts = @($a.Hosts.Keys)
        Add-Finding -User $a.User -Source "Browser history ($($a.Browser))" -Category $a.Category -Item $a.Item `
            -Count $a.Count -FirstSeen $a.First -LastSeen $a.Last -Detail (($hosts | Sort-Object) -join ', ')
    }

#endregion

#region DNS cache

    try {
        $dnsHosts = Get-DnsClientCache -ErrorAction Stop | ForEach-Object Entry | Where-Object { $_ } | Select-Object -Unique
        $dnsAgg = @{}
        foreach ($h in $dnsHosts) {
            $site = Find-SiteMatch $h $null
            if ($site) { $item = $site.Name; $cat = $site.Category }
            elseif ($h -match $KeywordHostPattern) { $item = $h; $cat = 'Possible AI site (keyword)' }
            else { continue }
            if (-not $dnsAgg.ContainsKey($item)) { $dnsAgg[$item] = [pscustomobject]@{ Cat = $cat; Hosts = @() } }
            $dnsAgg[$item].Hosts += $h.ToLowerInvariant()
        }
        foreach ($item in $dnsAgg.Keys) {
            $d = $dnsAgg[$item]
            Add-Finding -User '(machine)' -Source 'DNS cache (recent lookups)' -Category $d.Cat -Item $item `
                -Detail ($d.Hosts -join ', ')
        }
    } catch {
        $Notes.Add("DNS cache not checked: $($_.Exception.Message)")
    }

#endregion

#region Prompt and cache scan (high-value data sent to AI; rule-based, no AI)

    if ($SkipPromptScan) {
    } elseif (-not $DataHelpersAvailable) {
        $Notes.Add('Prompt scan skipped: the C# scan helper could not be compiled on this machine.')
    } else {

    $PromptScanRan = $true
    $PromptCutoff = $Started.AddDays(-$PromptDays)
    $MaxBytes = [long]$MaxFileMB * 1MB
    $RxOpt = [Text.RegularExpressions.RegexOptions]'CultureInvariant'
    $RxOptI = [Text.RegularExpressions.RegexOptions]'CultureInvariant, IgnoreCase'
    $RxTimeout = [TimeSpan]::FromSeconds(10)
    function New-Rx([string]$Pattern, [switch]$CaseSensitive) {
        $o = if ($CaseSensitive) { $RxOpt } else { $RxOptI }
        $o = $o -bor [Text.RegularExpressions.RegexOptions]::Compiled
        New-Object Text.RegularExpressions.Regex($Pattern, $o, $RxTimeout)
    }


    # Rules: Rx = pattern; Group = capture holding the value (0 = whole match); Check = validator name (C# RogueAiScan2.Check); Mask = how to show it.
    $DataRules = New-Object System.Collections.Generic.List[object]
    function Add-Rule($Name, $Severity, $Category, $Rx, $Group = 0, $Check = $null, $Mask = 'partial') {
        $DataRules.Add([pscustomobject]@{ Name = $Name; Sev = $Severity; Cat = $Category; Rx = $Rx; Group = $Group; Check = $Check; Mask = $Mask })
    }

    # Credentials and secrets
    Add-Rule 'Private key' 'Critical' 'Credential / secret' (New-Rx '(?<!webrtc[^\n]{0,120})-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----' -CaseSensitive) 0 $null 'keyword'
    Add-Rule 'AWS access key ID' 'Critical' 'Credential / secret' (New-Rx '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'AWS secret access key' 'Critical' 'Credential / secret' (New-Rx 'aws.{0,20}(?:secret|private).{0,20}?[:=]\s*["'']?([A-Za-z0-9/+=]{40})\b') 1 $null 'secret'
    Add-Rule 'GitHub token' 'Critical' 'Credential / secret' (New-Rx '\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'OpenAI API key' 'Critical' 'Credential / secret' (New-Rx '\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Anthropic API key' 'Critical' 'Credential / secret' (New-Rx '\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_\-]{80,}' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Slack token' 'Critical' 'Credential / secret' (New-Rx '\bxox[abposr]-[0-9A-Za-z\-]{10,}' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Stripe live key' 'Critical' 'Credential / secret' (New-Rx '\b(?:sk|rk)_live_[0-9A-Za-z]{24,}' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Google API key' 'High' 'Credential / secret' (New-Rx '\bAIza[0-9A-Za-z_\-]{35}\b' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Azure storage account key' 'Critical' 'Credential / secret' (New-Rx 'AccountKey=([A-Za-z0-9+/=]{40,})') 1 $null 'secret'
    Add-Rule 'Database connection string with password' 'Critical' 'Credential / secret' (New-Rx '(?:Server|Data Source|Host)=[^;"\r\n]{1,100};[^"\r\n]{0,200}?(?:Password|Pwd)=([^;"\s]{3,})') 1 'secret' 'secret'
    Add-Rule 'Credentials in URL' 'High' 'Credential / secret' (New-Rx '\b(?:https?|ftp|sftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|smb)://[^\s:/@"'']{1,64}:([^\s:/@"'']{3,64})@[^\s/"'']+') 1 'secret' 'secret'
    Add-Rule 'JSON Web Token' 'High' 'Credential / secret' (New-Rx '\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' -CaseSensitive) 0 $null 'secret'
    Add-Rule 'Password in text' 'High' 'Credential / secret' (New-Rx '\b(?:password|passwd|pwd|passcode|passphrase)\b["'']?\s*(?:is\s*[:=]?|[:=])\s*["'']?([^\s"''`<>{},;]{6,64})') 1 'password' 'secret'
    Add-Rule 'API key / token assignment' 'High' 'Credential / secret' (New-Rx '\b(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|bearer)\b["'']?\s*[:=]?\s*["'']?([A-Za-z0-9_\-\.+/=]{20,})') 1 'secretmixed' 'secret'

    # Financial and identity data
    Add-Rule 'Payment card number' 'Critical' 'Financial' (New-Rx '(?<![\w/=.\-])(?:\d[ \-]?){12,18}\d(?![\w\-]|\.\d)') 0 'card' 'last4'
    Add-Rule 'US Social Security number' 'Critical' 'Personal identity' (New-Rx '\b\d{3}-\d{2}-\d{4}\b') 0 'ssn' 'last4'
    Add-Rule 'US Social Security number (labeled)' 'Critical' 'Personal identity' (New-Rx '\b(?:SSN|social security(?: number| no\.?| #)?|soc\.? sec\.?)\s*[:#]?\s*(\d{3} ?\d{2} ?\d{4})\b') 1 'ssn' 'last4'
    Add-Rule 'Bank routing number (labeled)' 'High' 'Financial' (New-Rx '\b(?:routing|ABA|RTN)(?:\s*(?:number|no\.?|num|#))?\s*[:#]?\s*(\d{9})\b') 1 'aba' 'last4'
    Add-Rule 'Bank account number (labeled)' 'High' 'Financial' (New-Rx '\b(?:bank\s*)?(?:account|acct)\s*(?:number|no\.?|num|#)\s*[:#]?\s*(\d[\d \-]{4,20}\d)\b') 1 $null 'last4'
    Add-Rule 'IBAN' 'High' 'Financial' (New-Rx '\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b' -CaseSensitive) 0 'iban' 'last4'
    Add-Rule 'Passport number (labeled)' 'High' 'Personal identity' (New-Rx '\bpassport\s*(?:number|no\.?|num|#)?\s*[:#]?\s*([A-Z0-9]{6,9})\b') 1 'digit' 'last4'
    Add-Rule "Driver's license (labeled)" 'High' 'Personal identity' (New-Rx '\b(?:driver\W?s?\s*licen[cs]e(?:\s*(?:number|no\.?|num|#))?|(?-i:DL)\s*(?:number|no\.?|num|#))\s*[:#]?\s*([A-Z]?\d[\dA-Z\-]{4,16})\b') 1 'digit' 'last4'
    Add-Rule 'Date of birth (labeled)' 'High' 'Personal identity' (New-Rx '\b(?:DOB|date of birth|birth\s?date|born(?: on)?)\s*[:#]?\s*(\d{1,2}[/\-]\d{1,2}[/\-](?:19|20)\d{2}|(?:19|20)\d{2}-\d{2}-\d{2}|[A-Z][a-z]{2,8}\.? \d{1,2},? (?:19|20)\d{2})') 1 $null 'partial'

    # Health
    Add-Rule 'Medical record number' 'High' 'Health (PHI)' (New-Rx '\b(?:MRN|medical record (?:number|no\.?|#))\s*[:#]?\s*([A-Z0-9\-]{5,})') 1 'digit' 'last4'
    Add-Rule 'Diagnosis code (ICD-10)' 'High' 'Health (PHI)' (New-Rx '\b(?:diagnos[ie]s|dx|ICD-?10)\b[^\n]{0,40}?\b([A-TV-Z]\d{2}\.\d{1,4})\b') 1 $null 'keyword'
    Add-Rule 'Health information terms' 'Medium' 'Health (PHI)' (New-Rx '\b(patient name|diagnosed with|medical history|treatment plan|prescribed|prescription for|lab results|HIPAA|protected health information)\b') 1 $null 'keyword'

    # Document markings and business-sensitive topics
    Add-Rule 'Privileged / trade secret marking' 'High' 'Confidential marking' (New-Rx '\b(attorney[\- ]client privileged?|privileged (?:and|&) confidential|trade secrets?|strictly confidential|export controlled)\b') 1 $null 'keyword'
    Add-Rule 'Confidential marking' 'Medium' 'Confidential marking' (New-Rx '\b(confidential|internal use only|do not (?:distribute|forward|share)|not for (?:public )?distribution|proprietary (?:and|&) confidential|under NDA|non-disclosure agreement)\b') 1 $null 'keyword'
    Add-Rule 'Finance terms' 'Medium' 'Business sensitive' (New-Rx '\b(payroll|salary|salaries|compensation plan|bonus structure|wire instructions|wire transfer|tax return|W-2|balance sheet|profit and loss|revenue forecast|earnings (?:call|report|release)|term sheet|due diligence|merger|acquisition target|cap table|valuation)\b') 1 $null 'keyword'
    Add-Rule 'HR / legal terms' 'Medium' 'Business sensitive' (New-Rx '\b(performance improvement plan|disciplinary action|termination letter|layoffs?|reduction in force|severance|harassment complaint|lawsuit|litigation|settlement agreement|subpoena|legal hold)\b') 1 $null 'keyword'

    # Contact and infrastructure details (volume indicators)
    Add-Rule 'Email address' 'Low' 'Contact details' (New-Rx '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b') 0 'email' 'partial'
    Add-Rule 'US phone number' 'Low' 'Contact details' (New-Rx '(?<![\d\-])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\d\-])') 0 $null 'last4'
    Add-Rule 'Internal IP address' 'Low' 'Infrastructure' (New-Rx '\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b') 0 $null 'keyword'

    # Customer keywords
    $allKeywords = @($Keywords)
    if ($KeywordFile) {
        if (Test-Path -LiteralPath $KeywordFile) { $allKeywords += Get-Content -LiteralPath $KeywordFile | ForEach-Object { $_.Trim() } }
        else { $Notes.Add("Keyword file not found: $KeywordFile") }
    }
    $allKeywords = @($allKeywords | Where-Object { $_ } | Select-Object -Unique)
    if ($allKeywords.Count) {
        $kwPattern = '(?<![\w])(' + (($allKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![\w])'
        Add-Rule 'Customer keyword' 'High' 'Customer keyword' (New-Rx $kwPattern) 1 $null 'keyword'
    }

    function Get-MaskedValue([string]$v, [string]$Mode) {
        $v = $v.Trim()
        switch ($Mode) {
            'keyword' { return $v }
            'last4' {
                $d = $v -replace '[^0-9A-Za-z]', ''
                if ($d.Length -le 4) { return '****' }
                return ('*' * ($d.Length - 4)) + $d.Substring($d.Length - 4)
            }
            'secret' {
                $n = [Math]::Min(6, [int][Math]::Floor($v.Length / 4))
                return $v.Substring(0, $n) + '...[' + $v.Length + ' chars]'
            }
            default {
                if ($v.Length -le 4) { return '****' }
                return $v.Substring(0, 2) + ('*' * ($v.Length - 4)) + $v.Substring($v.Length - 2)
            }
        }
    }

    # Context around a hit, with the hit masked and other likely secrets / long numbers blanked.
    function Protect-Text([string]$t) {
        # any 7+ digits, even split by spaces/dashes/dots (cards, SSNs, phone and account numbers)
        $t = [regex]::Replace($t, '\d(?:[ \-./]?\d){6,}', { param($m) [regex]::Replace($m.Value, '\d', '#') })
        $t = [regex]::Replace($t, '\d{5,}', { param($m) '#' * $m.Value.Length })
        # key-like tokens: 16+ chars mixing letters and digits, or any 24+ char token
        $t = [regex]::Replace($t, '[A-Za-z0-9_\-+/=.]{16,}', {
            param($m)
            $v = $m.Value
            if ($v.Length -ge 24 -or $v -cmatch '^(?:AKIA|ASIA)[0-9A-Z]{16}$' -or ($v -match '\d' -and $v -match '[A-Za-z]')) { $v.Substring(0, 4) + '...' } else { $v }
        })
        $t = [regex]::Replace($t, '[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}', { param($m) $m.Value.Substring(0, [Math]::Min(2, $m.Value.Length)) + '***@***' })
        [regex]::Replace($t, '(?i)\b(password|passwd|pwd|passcode|secret|token|api[_\-]?key|accountkey)(\W{1,4})([^\s;,"'']+)', '$1$2***')
    }
    # Scrubs a wider window than it shows, so a value cut at the edge is still masked.
    function Get-Snippet([string]$Text, [int]$Index, [int]$Length, [string]$Mode) {
        $show = 70; $pad = 100
        $s = [Math]::Max(0, $Index - $show - $pad)
        $e = [Math]::Min($Text.Length, $Index + $Length + $show + $pad)
        $before = Protect-Text $Text.Substring($s, $Index - $s)
        $after = Protect-Text $Text.Substring($Index + $Length, $e - $Index - $Length)
        if ($before.Length -gt $show) { $before = $before.Substring($before.Length - $show) }
        if ($after.Length -gt $show) { $after = $after.Substring(0, $show) }
        $mid = Get-MaskedValue $Text.Substring($Index, $Length) $Mode
        ('...' + $before + '[' + $mid + ']' + $after + '...') -replace '\s+', ' '
    }

    # Tool = the key that links these data findings to the inventory row for the same product.
    function Invoke-SensitiveScan($Text, [string]$User, [string]$App, [string]$Tool, [string]$Location, $Modified, [string[]]$SkipRules = @()) {
        if ($null -eq $Text) { return }                 # file was skipped or unreadable: nothing was scanned
        $ScannedPairs["$User|$Tool"] = $true            # data for this tool was read, even if nothing matches
        if ($Text.Length -eq 0) { return }
        foreach ($rule in $DataRules) {
            if ($SkipRules -contains $rule.Name) { continue }
            $res = [RogueAiScan2]::Run($Text, $rule.Rx, [int]$rule.Group, [string]$rule.Check, 3, 10000)
            if ($res.Count -eq 0) { continue }
            $examples = New-Object System.Collections.Generic.List[string]
            $snips = New-Object System.Collections.Generic.List[string]
            foreach ($h in $res.Samples) {
                $examples.Add((Get-MaskedValue $h.Value $rule.Mask))
                if (-not $NoSnippets -and $snips.Count -lt 2) { $snips.Add((Get-Snippet $Text $h.Index $h.Length $rule.Mask)) }
            }
            $DataFindings.Add([pscustomobject]@{
                Computer = $env:COMPUTERNAME
                User     = $User
                Tool     = $Tool
                App      = $App
                Severity = $rule.Sev
                Category = $rule.Cat
                Rule     = $rule.Name
                Matches  = if ($res.Stopped) { "$($res.Count)+" } else { $res.Count }
                Unique   = $res.Unique
                Examples = $examples -join ' | '
                Context  = $snips -join ' || '
                Location = $Location
                Modified = $Modified
            })
        }
    }

    function Read-SharedBytes([string]$Path) {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try {
            $buf = New-Object byte[] $fs.Length
            $read = 0
            while ($read -lt $buf.Length) {
                $n = $fs.Read($buf, $read, $buf.Length - $read)
                if ($n -le 0) { break }
                $read += $n
            }
            , $buf   # comma: return the array as one object (PowerShell would otherwise unroll it byte by byte)
        } finally { $fs.Dispose() }
    }

    # Kind: Text (JSON/JSONL/plain), Strings (binary stores; .ldb files are LevelDB-decoded first), VsCodeDb (chat keys of state.vscdb)
    function Get-FileText([IO.FileInfo]$File, [string]$Kind) {
        if ($Kind -eq 'VsCodeDb') {
            if ($SqliteAvailable) {
                try {
                    $parts = New-Object System.Text.StringBuilder
                    $queries = @(
                        "SELECT key, value FROM ItemTable WHERE key LIKE '%chat%' OR key LIKE '%prompt%' OR key LIKE '%composer%' OR key LIKE '%aiService%' OR key LIKE '%interactive%' OR key LIKE '%cascade%'",
                        "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%' OR key LIKE 'bubbleId:%'"
                    )
                    foreach ($q in $queries) {
                        try { $rows = [RogueAiSqlite2]::QueryImmutable($File.FullName, $q) } catch { continue }
                        foreach ($r in $rows) {
                            if ($parts.Length -ge $MaxBytes) { break }
                            [void]$parts.AppendLine($r[1])
                        }
                    }
                    return (ConvertFrom-JsonEscapes $parts.ToString())
                } catch { }
            }
            if ($File.Length -gt $MaxBytes) { return $null }
            $Kind = 'Strings'
        }
        if ($File.Length -gt $MaxBytes) {
            $Notes.Add("Skipped (over $MaxFileMB MB): $($File.FullName)")
            return $null
        }
        $bytes = Read-SharedBytes $File.FullName
        if ($Kind -eq 'Jsonl') {
            $raw = [Text.Encoding]::UTF8.GetString($bytes)
            if (-not $FullTranscripts) { $raw = [RogueAiScan2]::UserLines($raw) }
            return (ConvertFrom-JsonEscapes $raw)
        }
        if ($Kind -eq 'Text') { return (ConvertFrom-JsonEscapes ([Text.Encoding]::UTF8.GetString($bytes))) }
        if ($File.Extension -eq '.ldb') { $bytes = [RogueAiData2]::ReadLdb($bytes) }
        [RogueAiData2]::Strings($bytes, 6)
    }

    function ConvertFrom-JsonEscapes([string]$t) { [RogueAiScan2]::DecodeJson($t) }

    # Where AI tools keep prompts and conversations. Rel is relative to the profile and may contain wildcards;
    # Under (regex on the full path) narrows which files count.
    $PromptSources = @(
        @{ App = 'Claude Code CLI';        Tool = 'Claude Code CLI';      Cat = 'AI CLI agent';       Rel = '.claude\projects';                          Include = '*.jsonl'; Kind = 'Jsonl' }
        @{ App = 'Claude Code CLI';        Tool = 'Claude Code CLI';      Cat = 'AI CLI agent';       Rel = '.claude';                                   Include = 'history.jsonl'; Kind = 'Text'; Flat = $true }
        @{ App = 'OpenAI Codex CLI';       Tool = 'OpenAI Codex CLI';     Cat = 'AI CLI agent';       Rel = '.codex\sessions';                           Include = '*.jsonl'; Kind = 'Jsonl' }
        @{ App = 'OpenAI Codex CLI';       Tool = 'OpenAI Codex CLI';     Cat = 'AI CLI agent';       Rel = '.codex';                                    Include = 'history.jsonl'; Kind = 'Text'; Flat = $true }
        @{ App = 'Gemini CLI';             Tool = 'Gemini CLI';           Cat = 'AI CLI agent';       Rel = '.gemini\tmp';                               Include = '*.json', '*.jsonl'; Kind = 'Text' }
        @{ App = 'Ollama CLI';             Tool = 'Ollama';               Cat = 'Local LLM runtime';  Rel = '.ollama';                                   Include = 'history'; Kind = 'Text'; Flat = $true }
        @{ App = 'LM Studio';              Tool = 'LM Studio';            Cat = 'Local LLM runtime';  Rel = '.lmstudio\conversations';                   Include = '*.json'; Kind = 'Text' }
        @{ App = 'LM Studio';              Tool = 'LM Studio';            Cat = 'Local LLM runtime';  Rel = '.cache\lm-studio\conversations';            Include = '*.json'; Kind = 'Text' }
        @{ App = 'Jan';                    Tool = 'Jan';                  Cat = 'Local LLM runtime';  Rel = 'AppData\Roaming\Jan\data\threads';          Include = '*.json', '*.jsonl'; Kind = 'Text' }
        @{ App = 'Continue';               Tool = 'Continue';             Cat = 'Code assistant';     Rel = '.continue\sessions';                        Include = '*.json'; Kind = 'Text' }
        @{ App = 'GPT4All';                Tool = 'GPT4All';              Cat = 'Local LLM runtime';  Rel = 'AppData\Local\nomic.ai\GPT4All';            Include = '*.chat'; Kind = 'Strings' }
        @{ App = 'AnythingLLM';            Tool = 'AnythingLLM';          Cat = 'Local LLM runtime';  Rel = 'AppData\Roaming\anythingllm-desktop\storage'; Include = '*.db'; Kind = 'Strings' }
        @{ App = 'Msty';                   Tool = 'Msty';                 Cat = 'Local LLM runtime';  Rel = 'AppData\Roaming\Msty';                      Include = '*.db', '*.sqlite', '*.ldb', '*.log'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\|\.(db|sqlite)$' }
        @{ App = 'Windsurf Cascade';       Tool = 'Windsurf / Codeium';   Cat = 'Code assistant';     Rel = '.codeium\windsurf\cascade';                 Include = '*.pb'; Kind = 'Strings' }
        @{ App = 'Claude desktop';         Tool = 'Claude desktop';       Cat = 'Chat assistant';     Rel = 'AppData\Roaming\Claude';                    Include = '*.ldb', '*.log'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\' }
        @{ App = 'Claude desktop';         Tool = 'Claude desktop';       Cat = 'Chat assistant';     Rel = 'AppData\Local\Packages\Claude_*\LocalCache'; Include = '*.ldb', '*.log'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\' }
        @{ App = 'ChatGPT desktop';        Tool = 'ChatGPT desktop';      Cat = 'Chat assistant';     Rel = 'AppData\Local\Packages\OpenAI.ChatGPT*';   Include = '*.ldb', '*.log', '*.db', '*.sqlite'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\|\.(db|sqlite)$' }
        @{ App = 'Microsoft Copilot app';  Tool = 'Microsoft Copilot';    Cat = 'Chat assistant';     Rel = 'AppData\Local\Packages\Microsoft.Copilot_*'; Include = '*.ldb', '*.log'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\' }
        @{ App = 'Perplexity desktop';     Tool = 'Perplexity / Comet';   Cat = 'Search assistant';   Rel = 'AppData\Roaming\Perplexity';                Include = '*.ldb', '*.log'; Kind = 'Strings'; Under = '\\(IndexedDB|Local Storage|Session Storage)\\' }
        @{ App = 'VS Code-family chat';    Tool = 'GitHub Copilot';       Cat = 'Code assistant';     Rel = 'AppData\Roaming\*\User';                    Include = '*.json'; Kind = 'Text'; Under = '\\(chatSessions|emptyWindowChatSessions|chatEditingSessions)\\' }
        @{ App = 'Cline / Roo / Kilo';     Tool = 'Cline / Roo / Kilo';   Cat = 'Code assistant';     Rel = 'AppData\Roaming\*\User\globalStorage';      Include = 'api_conversation_history.json', 'ui_messages.json'; Kind = 'Text' }
        @{ App = 'Cursor chat';            Tool = 'Cursor';               Cat = 'Code assistant';     Rel = 'AppData\Roaming\Cursor\User';               Include = 'state.vscdb'; Kind = 'VsCodeDb' }
        @{ App = 'Windsurf chat';          Tool = 'Windsurf / Codeium';   Cat = 'Code assistant';     Rel = 'AppData\Roaming\Windsurf\User';             Include = 'state.vscdb'; Kind = 'VsCodeDb' }
    )

    # Sites keep their own keys in browser storage (e.g. ChatGPT's WebRTC certificate for voice); no user typed them.
    $SiteStorageSkip = @('Private key')

    $scannedFiles = 0
    foreach ($prof in $Profiles) {
        $done = @{}
        foreach ($src in $PromptSources) {
            $roots = @(Get-Item -Path (Join-Path $prof.Path $src.Rel) -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })
            foreach ($root in $roots) {
                # -Include is unreliable with -LiteralPath on Windows PowerShell 5.1, so filter names here.
                $files = Get-ChildItem -LiteralPath $root.FullName -File -Force -Recurse:(-not $src.Flat) -ErrorAction SilentlyContinue |
                    Where-Object { $n = $_.Name; @($src.Include | Where-Object { $n -like $_ }).Count }
                foreach ($f in $files) {
                    if ($done.ContainsKey($f.FullName)) { continue }
                    if ($f.LastWriteTime -lt $PromptCutoff) { continue }
                    if ($src.Under -and $f.FullName -notmatch $src.Under) { continue }
                    $done[$f.FullName] = $true
                    try { $text = Get-FileText $f $src.Kind } catch {
                        $Notes.Add("Could not read $($f.FullName): $($_.Exception.Message)"); continue
                    }
                    $scannedFiles++
                    $ToolCategory[$src.Tool] = $src.Cat
                    Invoke-SensitiveScan $text $prof.User $src.App $src.Tool $f.FullName $f.LastWriteTime
                }
            }
        }

        # Browser storage (IndexedDB) that belongs to AI sites
        foreach ($b in $ChromiumBrowsers) {
            foreach ($bp in (Get-ChromiumProfiles (Join-Path $prof.Path $b.Rel))) {
                $idb = Join-Path $bp 'IndexedDB'
                if (-not (Test-Path -LiteralPath $idb)) { continue }
                foreach ($d in Get-ChildItem -LiteralPath $idb -Directory -ErrorAction SilentlyContinue) {
                    if ($d.Name -notmatch '^https?_(.+?)_\d+\.indexeddb\.(leveldb|blob)$') { continue }
                    $site = Find-SiteMatch $matches[1] $null
                    if (-not $site) { continue }
                    foreach ($f in Get-ChildItem -LiteralPath $d.FullName -File -Recurse -Force -ErrorAction SilentlyContinue) {
                        if ($f.LastWriteTime -lt $PromptCutoff) { continue }
                        if ($d.Name -like '*.leveldb' -and $f.Extension -notin '.ldb', '.log') { continue }
                        try { $text = Get-FileText $f 'Strings' } catch { continue }
                        $scannedFiles++
                        if (-not $ToolCategory.ContainsKey($site.Name)) { $ToolCategory[$site.Name] = $site.Category }
                        Invoke-SensitiveScan $text $prof.User "$($site.Name) site storage ($($b.Name)/$(Split-Path $bp -Leaf))" $site.Name $f.FullName $f.LastWriteTime $SiteStorageSkip
                    }
                }
            }
        }
        foreach ($b in $FirefoxBrowsers) {
            $root = Join-Path $prof.Path $b.Rel
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($fp in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                $storage = Join-Path $fp.FullName 'storage\default'
                if (-not (Test-Path -LiteralPath $storage)) { continue }
                foreach ($d in Get-ChildItem -LiteralPath $storage -Directory -ErrorAction SilentlyContinue) {
                    if ($d.Name -notmatch '^https?\+\+\+([^+^]+)') { continue }
                    $site = Find-SiteMatch $matches[1] $null
                    if (-not $site) { continue }
                    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $d.FullName 'idb') -File -Filter *.sqlite -ErrorAction SilentlyContinue) {
                        if ($f.LastWriteTime -lt $PromptCutoff) { continue }
                        try { $text = Get-FileText $f 'Strings' } catch { continue }
                        $scannedFiles++
                        if (-not $ToolCategory.ContainsKey($site.Name)) { $ToolCategory[$site.Name] = $site.Category }
                        Invoke-SensitiveScan $text $prof.User "$($site.Name) site storage ($($b.Name)/$($fp.Name))" $site.Name $f.FullName $f.LastWriteTime $SiteStorageSkip
                    }
                }
            }
        }
    }

    # Page titles of AI conversations seen in browser history
    foreach ($k in $AiTitles.Keys) {
        $u, $br, $siteName = $k -split '\|', 3
        Invoke-SensitiveScan (($AiTitles[$k].Keys) -join "`n") $u "AI page titles ($br)" $siteName "Browser history titles, last $Days days" $null
    }

    $Notes.Add("Prompt scan: $scannedFiles files changed in the last $PromptDays days, plus AI page titles from history.")
    }

#endregion

} finally {
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

#region Report

function ConvertTo-HtmlText($Value) {
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$SevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$RiskOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; 'None found' = 4; 'Not checked' = 5; Info = 6 }
$RatedRisks = 'Critical', 'High', 'Medium', 'Low', 'None found', 'Not checked'

# --- Link inventory rows to the data found in each tool's own caches ---------------------------------------------

$ProfileNames = @($Profiles | ForEach-Object User)

# The profile a finding belongs to, or '' when it is machine-wide / spans users / is not a known profile
# (those rows use the worst result across every user for that tool).
function Get-BaseUser([string]$User) {
    if ([string]::IsNullOrWhiteSpace($User)) { return '' }
    $u = $User
    if ($u.Contains('\')) { $u = $u.Substring($u.LastIndexOf('\') + 1) }
    if ($ProfileNames -contains $u) { return $u }
    ''
}

$DataByTool = @{}
foreach ($d in $DataFindings) {
    if (-not $DataByTool.ContainsKey($d.Tool)) { $DataByTool[$d.Tool] = New-Object System.Collections.Generic.List[object] }
    $DataByTool[$d.Tool].Add($d)
}
$ScannedTools = @{}
foreach ($k in @($ScannedPairs.Keys)) { $ScannedTools[$k.Substring($k.IndexOf('|') + 1)] = $true }

# A tool whose data was read for a profile but has no inventory row there (e.g. a CLI history with no install folder
# match) still gets a row, so its rating shows up in the table.
foreach ($k in @($ScannedPairs.Keys)) {
    $i = $k.IndexOf('|'); $u = $k.Substring(0, $i); $t = $k.Substring($i + 1)
    $has = @($Findings | Where-Object { $_.Tool -eq $t -and (Get-BaseUser $_.User) -eq $u }).Count
    if ($has) { continue }
    $cat = if ($ToolCategory.ContainsKey($t)) { $ToolCategory[$t] } else { 'AI tool' }
    Add-Finding -User $u -Source 'Local AI data' -Category $cat -Item $t -Tool $t `
        -Detail 'Prompts, conversations or caches found on disk (no install record matched)'
}

function Get-ToolRating([string]$Tool, [string]$User) {
    $hits = @()
    if ($DataByTool.ContainsKey($Tool)) {
        $hits = @(if ($User) { @($DataByTool[$Tool].ToArray() | Where-Object { $_.User -eq $User }) } else { $DataByTool[$Tool].ToArray() })
    }
    if ($hits.Count) {
        $worst = ($hits | Sort-Object @{ Expression = { $SevOrder[$_.Severity] } } | Select-Object -First 1).Severity
        return [pscustomobject]@{ Risk = $worst; Hits = $hits.Count; Data = $hits }
    }
    $scanned = if ($User) { $ScannedPairs.ContainsKey("$User|$Tool") } else { $ScannedTools.ContainsKey($Tool) }
    $risk = if ($scanned) { 'None found' } else { 'Not checked' }
    [pscustomobject]@{ Risk = $risk; Hits = 0; Data = @() }
}

foreach ($f in $Findings) {
    if ($f.Risk -eq 'Info') { continue }          # governance tooling: shown, never scored
    $r = Get-ToolRating $f.Tool (Get-BaseUser $f.User)
    $f.Risk = $r.Risk
    $f.DataHits = $r.Hits
}

# One entry per tool (worst result across users) for the cards, Summary.json and the detection summary.
$AppSources = 'Installed program', 'Store/MSIX package', 'Running process', 'Profile folder', 'Model file scan', 'Local AI data'
$ToolInfo = New-Object System.Collections.Generic.List[object]
foreach ($t in @($Findings | Where-Object { $_.Risk -ne 'Info' } | ForEach-Object Tool | Sort-Object -Unique)) {
    $rows = @($Findings | Where-Object { $_.Tool -eq $t -and $_.Risk -ne 'Info' })
    $r = Get-ToolRating $t ''
    $users = @(@($rows | ForEach-Object { Get-BaseUser $_.User }) + @($r.Data | ForEach-Object User) |
        Where-Object { $_ } | Sort-Object -Unique)
    if (-not $users.Count) { $users = @('(machine)') }
    $group = if (@($rows | Where-Object { $_.Source -in $AppSources -or $_.Source -like 'IDE extension*' }).Count) { 'Installed apps and CLIs' }
             elseif (@($rows | Where-Object { $_.Source -like 'Browser extension*' }).Count) { 'Browser extensions' }
             else { 'Sites visited without local data' }
    $visits = 0
    foreach ($row in @($rows | Where-Object { $_.Source -like 'Browser history*' })) { if ($row.Count) { $visits += [int]$row.Count } }
    $ToolInfo.Add([pscustomobject]@{
        Tool = $t; Users = $users; Risk = $r.Risk; DataHits = $r.Hits; Category = $rows[0].Category; Group = $group; Visits = $visits
        DataCategories = @($r.Data | ForEach-Object Category | Sort-Object -Unique)
    })
}
$ToolInfo = @($ToolInfo | Sort-Object @{ Expression = { $RiskOrder[$_.Risk] } }, Tool)
$toolsByRisk = [ordered]@{}
foreach ($n in $RatedRisks) { $toolsByRisk[$n] = @($ToolInfo | Where-Object Risk -eq $n).Count }

$Sorted = @($Findings | Sort-Object @{ Expression = { $RiskOrder[$_.Risk] } }, Tool, User, Item)

$findingsCsv = Join-Path $OutputPath 'Findings.csv'
$Sorted | Export-Csv -LiteralPath $findingsCsv -NoTypeInformation -Encoding UTF8
if ($IncludeUrls) {
    $HistoryDetail | Sort-Object User, VisitTime |
        Export-Csv -LiteralPath (Join-Path $OutputPath 'HistoryDetail.csv') -NoTypeInformation -Encoding UTF8
}

$SortedData = @($DataFindings | Sort-Object @{ Expression = { $SevOrder[$_.Severity] } }, @{ Expression = 'Matches'; Descending = $true }, User, App)
$SortedData | Export-Csv -LiteralPath (Join-Path $OutputPath 'DataFindings.csv') -NoTypeInformation -Encoding UTF8
$dataBySev = [ordered]@{}
foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $dataBySev[$s] = @($DataFindings | Where-Object Severity -eq $s).Count }

# --- Detection summary (fixed templates over this run's data; no AI) ---------------------------------------------

# Why each kind of data matters (plain-English, one or two sentences).
$CategoryWhy = @{
    'Credential / secret'   = 'A live key, token or password sent to or stored by an AI tool can be read by anyone with access to that tool''s history, the provider''s logs or this cache, and then reused. Treat it as exposed and rotate it.'
    'Financial'             = 'Card, bank and account numbers in prompts can be kept by the tool or its provider, and are regulated data (for example under PCI DSS). They should not be pasted into AI tools.'
    'Personal identity'     = 'Government IDs, dates of birth and similar identifiers are enough to commit identity fraud and are regulated personal data. Keeping them in an AI tool''s history widens who could see them.'
    'Health (PHI)'          = 'Health information can be protected by HIPAA or similar rules, and most consumer AI tools have no agreement that allows it to be processed there.'
    'Confidential marking'  = 'Text marked confidential, privileged or under NDA suggests business or legal material was shared with a tool that may not be approved to hold it.'
    'Business sensitive'    = 'Finance, HR and legal topics in prompts point to internal business material that may be kept or used outside the company''s control.'
    'Customer keyword'      = 'Matches on the customer-supplied keywords (project, client or product names) show that protected business context was entered into this tool.'
    'Contact details'       = 'Email addresses and phone numbers identify real people, such as staff or customers. A few are routine; large volumes suggest pasted contact lists.'
    'Infrastructure'        = 'Internal IP addresses describe the layout of the company network, which helps an attacker map it if the history is ever exposed.'
}

# What the presence of each kind of tool means, whatever was found in it.
$ToolTypeNote = @{
    'Local LLM runtime'          = 'Local LLM runtime: models run on this PC outside any company control, logging or content filtering.'
    'Local model files'          = 'Local model files: downloaded models are unvetted and can be run with no company logging or filtering.'
    'AI CLI agent'               = 'AI CLI agent: transcripts can include file contents and command output, not only what the user typed.'
    'Code assistant'             = 'Code assistant: source code and file contents may be sent to the provider, and prompts may be retained depending on the plan.'
    'Chat assistant'             = 'Chat assistant: on consumer plans, prompts may be retained or used for training without an enterprise agreement.'
    'Search assistant'           = 'Search assistant: queries and pasted text go to a consumer service and may be retained or used for training.'
    'Research assistant'         = 'Research assistant: uploaded documents and notes are stored with a consumer service.'
    'Developer API'              = 'Developer API console: API keys and request logs live in the account, and keys can be used from anywhere.'
    'Model aggregator'           = 'Model aggregator: relays prompts to many third-party models, so it is hard to know who handles the data.'
    'Model hub'                  = 'Model hub: models and datasets downloaded from here are unvetted.'
    'Image/video generation'     = 'Image/video generation: prompts and uploaded images go to the provider and may be retained.'
    'Voice/music generation'     = 'Voice/music generation: recordings and prompts go to the provider and may be retained.'
    'Browser AI extension'       = 'Browser AI extension: can read the pages the user visits and send their content to the provider.'
    'Browser assistant'          = 'Browser assistant: can read the pages the user visits and send their content to the provider.'
    'Writing assistant'          = 'Writing assistant: text pasted in, which can include business documents, is processed by the provider.'
    'Presentation AI'            = 'Presentation AI: slide content and source documents are processed and stored by the provider.'
    'Meeting transcription'      = 'Meeting transcription: records and transcribes calls, which can capture confidential conversations, including other participants.'
    'AI companion'               = 'AI companion: personal conversations with a consumer service that often has weak data protection; not a business tool.'
    'AI humanizer'               = 'AI humanizer: submitted text is rewritten by a third party, which may keep a copy.'
    'Document upload AI'         = 'Document upload AI: whole documents are uploaded to a third-party service.'
    'AI agent'                   = 'AI agent: acts for the user and may hold broad access to accounts and files.'
    'App builder'                = 'App builder: prompts and generated code are stored with the provider.'
    'Possible AI site (keyword)' = 'Possible AI site: matched by hostname only; check it by hand.'
}
# Providers in the catalogs that keep data under PRC jurisdiction.
$ForeignPattern = '^(DeepSeek|Kimi|Qwen|Tongyi|Doubao|ERNIE|ChatGLM|Z\.ai|MiniMax|Hailuo|Kling|Trae)'

function Get-ToolTypeNote([string]$Category, [string]$Tool) {
    $n = if ($ToolTypeNote.ContainsKey($Category)) { $ToolTypeNote[$Category] } else { 'AI tool: prompts and files may be kept by the provider.' }
    if ($Tool -match $ForeignPattern) { $n += ' Data is stored under PRC jurisdiction.' }
    $n
}

$SummaryItems = New-Object System.Collections.Generic.List[object]
function Add-SummaryItem([string]$Kind, [string]$Text) { $SummaryItems.Add([pscustomobject]@{ Kind = $Kind; Text = $Text }) }
function Join-Natural([string[]]$Parts) { ($Parts | Where-Object { $_ }) -join ', ' }

# 1. Headline
$toolCount = @($ToolInfo).Count
$profCount = @($Profiles).Count
$profWord = if ($profCount -eq 1) { 'user profile' } else { 'user profiles' }
if ($toolCount -eq 0) {
    Add-SummaryItem 'headline' "No AI tools were found across $profCount $profWord."
} else {
    $toolWord = if ($toolCount -eq 1) { 'AI tool was' } else { 'AI tools were' }
    $head = "$toolCount $toolWord found across $profCount $profWord."
    if (-not $PromptScanRan) {
        $head += ' The prompt and cache scan did not run, so no tool was rated for sensitive data.'
    } else {
        $withData = @($ToolInfo | Where-Object { $_.DataHits -gt 0 })
        if ($withData.Count) {
            $parts = foreach ($n in 'Critical', 'High', 'Medium', 'Low') {
                $c = @($withData | Where-Object Risk -eq $n).Count
                if ($c) { "$c $n" }
            }
            $head += " Sensitive data was found in the local data of $($withData.Count) of them: $(Join-Natural $parts)."
        } else {
            $head += ' No sensitive data was found in the AI tool data scanned.'
        }
    }
    Add-SummaryItem 'headline' $head
}

# 2. How scoring works
Add-SummaryItem 'h' 'How scoring works'
if ($PromptScanRan -and $DataRules) {
    Add-SummaryItem 'p' ("Each tool is rated by the most severe sensitive data found in the prompts, conversations and caches that tool keeps on this PC (files changed in the last $PromptDays days). " +
        'Ratings are worked out per user profile; where a tool appears in several profiles, the summary uses the most severe result.')
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
        $rs = @($DataRules | Where-Object { $_.Sev -eq $sev })
        if (-not $rs.Count) { continue }
        $cats = @($rs | ForEach-Object Cat | Select-Object -Unique)
        $names = @($rs | ForEach-Object Name | Select-Object -Unique)
        Add-SummaryItem 'li' "**$sev** - data types: $($cats -join ', '). Rules: $($names -join '; ')."
    }
} else {
    Add-SummaryItem 'p' 'Each tool would be rated by the most severe sensitive data found in the prompts, conversations and caches it keeps on this PC. The prompt and cache scan did not run in this report, so every tool shows as Not checked.'
}
Add-SummaryItem 'li' '**None found** - the tool''s data was scanned and nothing matched.'
Add-SummaryItem 'li' '**Not checked** - the tool keeps no data this script can read (for example browser extensions, DNS lookups, or sites without cached storage), so its presence is reported but not scored.'
Add-SummaryItem 'li' '**Info** - governance tooling such as the Prompt Security extension; shown for context and never scored.'
Add-SummaryItem 'p' 'Values are always masked in this report. Matching is rule-based, not AI: regular expressions with checksum validators (Luhn for card numbers, ABA for routing numbers, mod-97 for IBANs, SSN area rules), so a match is an indicator to review rather than proof of a leak.'

# 3. What was found and why it matters
if ($PromptScanRan) {
    Add-SummaryItem 'h' 'What was found and why it matters'
    $categoryOf = @{}
    foreach ($ti in $ToolInfo) { $categoryOf[$ti.Tool] = $ti.Category }
    $units = New-Object System.Collections.Generic.List[object]
    foreach ($g in ($DataFindings | Group-Object { "$($_.Tool)|$($_.User)" })) {
        $items = @($g.Group)
        $worst = ($items | Sort-Object @{ Expression = { $SevOrder[$_.Severity] } } | Select-Object -First 1).Severity
        if ($worst -notin 'Critical', 'High', 'Medium') { continue }
        $units.Add([pscustomobject]@{ Tool = $items[0].Tool; User = $items[0].User; Risk = $worst; Items = $items })
    }
    $units = @($units | Sort-Object @{ Expression = { $SevOrder[$_.Risk] } }, @{ Expression = { $_.Items.Count }; Descending = $true }, Tool, User)
    if (-not $units.Count) {
        Add-SummaryItem 'p' 'No Critical, High or Medium sensitive data was found in any tool''s local data.'
    } else {
        foreach ($u in ($units | Select-Object -First 15)) {
            # what was found: rules ordered by severity then volume
            $byRule = foreach ($rg in ($u.Items | Group-Object Rule)) {
                $total = 0; $plus = $false
                foreach ($it in $rg.Group) {
                    $m = [string]$it.Matches
                    if ($m.EndsWith('+')) { $plus = $true; $m = $m.TrimEnd('+') }
                    $total += [int]$m
                }
                [pscustomobject]@{ Rule = $rg.Name; Sev = $SevOrder[$rg.Group[0].Severity]; N = $total; Plus = $plus }
            }
            $byRule = @($byRule | Sort-Object Sev, @{ Expression = 'N'; Descending = $true }, Rule)
            $found = @($byRule | Select-Object -First 6 | ForEach-Object { '{0} ({1}{2})' -f $_.Rule, $_.N, $(if ($_.Plus) { '+' } else { '' }) }) -join ', '
            if ($byRule.Count -gt 6) { $found += ", +$($byRule.Count - 6) more rules" }
            # why it matters: explanations for the categories found, most severe category first
            $catOrder = foreach ($cg in ($u.Items | Group-Object Category)) {
                [pscustomobject]@{ Cat = $cg.Name; Sev = ($cg.Group | ForEach-Object { $SevOrder[$_.Severity] } | Measure-Object -Minimum).Minimum }
            }
            $why = @($catOrder | Sort-Object Sev, Cat | Select-Object -First 3 | ForEach-Object { if ($CategoryWhy.ContainsKey($_.Cat)) { $CategoryWhy[$_.Cat] } }) -join ' '
            $cat = if ($categoryOf.ContainsKey($u.Tool)) { $categoryOf[$u.Tool] } else { '' }
            Add-SummaryItem 'li' ("**$($u.Tool)** ($($u.User)) - $($u.Risk). Found: $found. Why it matters: $why " +
                "About this tool: $(Get-ToolTypeNote $cat $u.Tool)")
        }
        if ($units.Count -gt 15) { Add-SummaryItem 'p' "+$($units.Count - 15) more in the table below." }
    }
}

# 4. Present but not scored
Add-SummaryItem 'h' 'Present but not scored'
$unscored = @($ToolInfo | Where-Object { $_.Risk -eq 'Not checked' })
if (-not $unscored.Count) {
    Add-SummaryItem 'p' 'Every tool found had local data that could be scanned.'
} else {
    foreach ($grp in 'Installed apps and CLIs', 'Browser extensions', 'Sites visited without local data') {
        $members = @($unscored | Where-Object Group -eq $grp)
        if (-not $members.Count) { continue }
        $names = ($members | ForEach-Object {
            if ($grp -eq 'Sites visited without local data' -and $_.Visits -gt 0) { '{0} ({1} visits)' -f $_.Tool, $_.Visits } else { $_.Tool }
        }) -join ', '
        $typeNotes = @($members | ForEach-Object { Get-ToolTypeNote $_.Category $_.Tool } | Select-Object -Unique) -join ' '
        Add-SummaryItem 'li' "**$grp**: $names. $typeNotes"
    }
}

# Render: plain text (console + Summary.json) and HTML
$SummaryText = New-Object System.Collections.Generic.List[string]
foreach ($it in $SummaryItems) {
    $plain = $it.Text -replace '\*\*', ''
    switch ($it.Kind) {
        'h'  { $SummaryText.Add(''); $SummaryText.Add($plain.ToUpperInvariant()) }
        'li' { $SummaryText.Add('- ' + $plain) }
        default { $SummaryText.Add($plain) }
    }
}
$summaryHtml = New-Object System.Text.StringBuilder
$inList = $false
foreach ($it in $SummaryItems) {
    $h = (ConvertTo-HtmlText $it.Text) -replace '\*\*(.+?)\*\*', '<b>$1</b>'
    if ($it.Kind -ne 'li' -and $inList) { [void]$summaryHtml.Append('</ul>'); $inList = $false }
    switch ($it.Kind) {
        'headline' { [void]$summaryHtml.Append("<p class=`"headline`">$h</p>") }
        'h'        { [void]$summaryHtml.Append("<h3>$h</h3>") }
        'li'       { if (-not $inList) { [void]$summaryHtml.Append('<ul>'); $inList = $true }; [void]$summaryHtml.Append("<li>$h</li>") }
        default    { [void]$summaryHtml.Append("<p>$h</p>") }
    }
}
if ($inList) { [void]$summaryHtml.Append('</ul>') }

$summary = [ordered]@{
    Computer          = $env:COMPUTERNAME
    RunAt             = $Started.ToString('s')
    Elevated          = $IsAdmin
    HistoryDays       = $Days
    ProfilesScanned   = @($Profiles | ForEach-Object User)
    TotalFindings     = $Findings.Count
    ToolsFound        = $toolCount
    ToolsByRisk       = $toolsByRisk
    Tools             = @($ToolInfo | ForEach-Object {
        [ordered]@{ Tool = $_.Tool; Users = @($_.Users); Risk = $_.Risk; DataHits = $_.DataHits; Categories = @($_.DataCategories) }
    })
    PromptScan        = -not $SkipPromptScan
    PromptDays        = $PromptDays
    DataFindings      = $DataFindings.Count
    DataBySeverity    = $dataBySev
    DataRulesHit      = @($DataFindings | ForEach-Object Rule | Sort-Object -Unique)
    SummaryText       = @($SummaryText)
    Notes             = @($Notes)
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputPath 'Summary.json') -Encoding UTF8

Write-Output ''
if ($Findings.Count -eq 0) {
    Write-Output 'No AI apps, extensions or AI site visits found.'
} else {
    Write-Output ("{0} findings for {1} tools ({2} Critical, {3} High, {4} Medium, {5} Low, {6} None found, {7} Not checked)" -f $Findings.Count,
        $toolCount, $toolsByRisk['Critical'], $toolsByRisk['High'], $toolsByRisk['Medium'], $toolsByRisk['Low'],
        $toolsByRisk['None found'], $toolsByRisk['Not checked'])
    $Sorted | Format-Table Risk, DataHits, User, Tool, Item, Category, Source, Count, LastSeen -AutoSize | Out-String -Width 220 | Write-Output
}
Write-Output 'DETECTION SUMMARY'
foreach ($line in $SummaryText) { Write-Output $line }
Write-Output ''
if (-not $SkipPromptScan) {
    Write-Output ("Prompt/cache scan: {0} data findings ({1} Critical, {2} High, {3} Medium, {4} Low)" -f $DataFindings.Count,
        $dataBySev.Critical, $dataBySev.High, $dataBySev.Medium, $dataBySev.Low)
    if ($DataFindings.Count) {
        $SortedData | Select-Object -First 40 | Format-Table Severity, User, Tool, App, Rule, Matches, Unique, Examples -AutoSize |
            Out-String -Width 220 | Write-Output
        if ($DataFindings.Count -gt 40) { Write-Output '(first 40 shown; see the HTML report or DataFindings.csv)' }
    }
}
foreach ($n in $Notes) { Write-Output "Note: $n" }
Write-Output "Report: $OutputPath"

# HTML report, saved next to the script
$rowsHtml = New-Object System.Text.StringBuilder
foreach ($f in $Sorted) {
    $seen = if ($f.LastSeen) { ([datetime]$f.LastSeen).ToString('yyyy-MM-dd HH:mm') } else { '' }
    $first = if ($f.FirstSeen) { ([datetime]$f.FirstSeen).ToString('yyyy-MM-dd HH:mm') } else { '' }
    $slug = (Get-Culture).TextInfo.ToTitleCase($f.Risk) -replace '\s', ''   # 'None found' -> 'NoneFound' (CSS class)
    $hits = if ($f.Risk -in 'Info', 'Not checked') { '' } else { [string]$f.DataHits }
    $detail = ConvertTo-HtmlText $f.Detail
    if ($f.Tool -and $f.Tool -ne $f.Item) { $detail = 'Tool: ' + (ConvertTo-HtmlText $f.Tool) + '<br>' + $detail }
    [void]$rowsHtml.AppendFormat('<tr data-risk="{0}"><td><span class="badge {1}">{0}</span></td><td class="num">{2}</td><td>{3}</td><td><b>{4}</b><div class="detail">{5}</div></td><td>{6}</td><td>{7}</td><td class="num">{8}</td><td>{9}</td><td>{10}</td></tr>',
        (ConvertTo-HtmlText $f.Risk), $slug, $hits, (ConvertTo-HtmlText $f.User), (ConvertTo-HtmlText $f.Item),
        $detail, (ConvertTo-HtmlText $f.Category), (ConvertTo-HtmlText $f.Source),
        (ConvertTo-HtmlText $f.Count), $first, $seen)
    [void]$rowsHtml.AppendLine()
}
$notesHtml = ($Notes | ForEach-Object { '<li>' + (ConvertTo-HtmlText $_) + '</li>' }) -join ''
if (-not $notesHtml) { $notesHtml = '<li>None.</li>' }

$dataRowsHtml = New-Object System.Text.StringBuilder
foreach ($f in $SortedData) {
    $mod = if ($f.Modified) { ([datetime]$f.Modified).ToString('yyyy-MM-dd HH:mm') } else { '' }
    [void]$dataRowsHtml.AppendFormat('<tr data-risk="{0}"><td><span class="badge {0}">{0}</span></td><td>{1}</td><td>{2}</td><td><b>{3}</b><div class="detail">{4}</div></td><td class="num">{5}</td><td class="num">{6}</td><td class="mono">{7}</td><td class="mono ctx">{8}</td><td class="detail">{9}<br>{10}</td></tr>',
        (ConvertTo-HtmlText $f.Severity), (ConvertTo-HtmlText $f.User), (ConvertTo-HtmlText $f.App), (ConvertTo-HtmlText $f.Rule),
        (ConvertTo-HtmlText $f.Category), $f.Matches, $f.Unique, (ConvertTo-HtmlText $f.Examples),
        ((ConvertTo-HtmlText $f.Context) -replace ' \|\| ', '<hr>'), (ConvertTo-HtmlText $f.Location), $mod)
    [void]$dataRowsHtml.AppendLine()
}
if ($SkipPromptScan) {
    $dataSection = '<h2>High-value data in AI prompts and caches</h2><p class="sub">Not run (-SkipPromptScan).</p>'
} else {
    $dataSection = @"
<h2>High-value data in AI prompts and caches</h2>
<div class="sub">Rule-based scan (patterns, checksums, keywords; no AI) of prompts and conversations AI tools stored on this PC in the last $PromptDays days. Values are masked. This section still describes sensitive data: treat the report as confidential.</div>
<div class="cards">
<div class="card"><div class="n">$($DataFindings.Count)</div><div class="l">Data findings</div></div>
<div class="card Critical"><div class="n">$($dataBySev.Critical)</div><div class="l">Critical</div></div>
<div class="card High"><div class="n">$($dataBySev.High)</div><div class="l">High</div></div>
<div class="card Medium"><div class="n">$($dataBySev.Medium)</div><div class="l">Medium</div></div>
<div class="card Low"><div class="n">$($dataBySev.Low)</div><div class="l">Low</div></div>
</div>
<div class="tools" data-for="drows">
<input type="search" placeholder="Filter by app, rule, user, file...">
<select class="f-risk"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
</div>
<div class="wrap"><table><thead><tr><th>Severity</th><th>User</th><th>App / source</th><th>Rule</th><th>Hits</th><th>Unique</th><th>Examples (masked)</th><th>Context (masked)</th><th>File</th></tr></thead>
<tbody id="drows">
$($dataRowsHtml.ToString())</tbody></table></div>
"@
}

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rogue AI Audit - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>
:root { --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5d6675; --line:#dfe3ea; --critical:#7f1d1d;
  --high:#c62828; --medium:#d97706; --low:#2f7d32; --info:#3a6fb0; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171c; --card:#1d2129; --fg:#e6e9ef; --muted:#9aa3b2; --line:#2e3440; --critical:#fca5a5;
  --high:#ef5350; --medium:#f59e0b; --low:#66bb6a; --info:#64a0e6; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg); font:14px/1.45 "Segoe UI", system-ui, sans-serif; }
main { max-width:1400px; margin:0 auto; }
h1 { margin:0 0 4px; font-size:22px; } .sub { color:var(--muted); margin-bottom:20px; }
.summary { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 18px; margin-bottom:20px; max-width:1100px; }
.summary h3 { margin:16px 0 4px; font-size:14px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.summary p { margin:6px 0; } .summary ul { margin:4px 0; padding-left:20px; } .summary li { margin:6px 0; }
.summary .headline { font-size:16px; font-weight:600; margin-top:0; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card .n { font-size:26px; font-weight:600; } .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.card.High .n { color:var(--high); } .card.Medium .n { color:var(--medium); } .card.Low .n { color:var(--low); }
.card.NoneFound .n { color:var(--low); } .card.NotChecked .n { color:var(--muted); }
.tools { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px; }
.tools input, .tools select { padding:7px 10px; border:1px solid var(--line); border-radius:6px; background:var(--card); color:var(--fg); font:inherit; }
.tools input { flex:1; min-width:200px; }
.wrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { position:sticky; top:0; background:var(--card); font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
td.num { text-align:right; } .detail { color:var(--muted); font-size:12px; word-break:break-all; max-width:520px; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; color:#fff; white-space:nowrap; }
.badge.High { background:var(--high); } .badge.Medium { background:var(--medium); }
.badge.Low { background:var(--low); } .badge.Info { background:var(--info); }
.badge.NoneFound { background:transparent; color:var(--low); border:1px solid var(--low); }
.badge.NotChecked { background:var(--line); color:var(--muted); }
.notes { margin-top:20px; color:var(--muted); } .notes ul { margin:4px 0 0; padding-left:20px; }
h2 { margin:32px 0 4px; font-size:18px; }
.card.Critical .n { color:var(--critical); } .badge.Critical { background:#7f1d1d; }
.mono { font-family:Consolas, "Cascadia Mono", monospace; font-size:12px; word-break:break-all; }
.ctx { max-width:460px; color:var(--muted); } .ctx hr { border:0; border-top:1px dashed var(--line); margin:6px 0; }
</style></head><body><main>
<h1>Rogue AI Audit: $(ConvertTo-HtmlText $env:COMPUTERNAME)</h1>
<div class="sub">Run $($Started.ToString('yyyy-MM-dd HH:mm')) &middot; elevated: $IsAdmin &middot; profiles: $(ConvertTo-HtmlText ($summary.ProfilesScanned -join ', ')) &middot; history window: $Days days</div>
<div class="summary"><h2 style="margin-top:0">Detection summary</h2>
$($summaryHtml.ToString())
</div>
<div class="cards">
<div class="card"><div class="n">$toolCount</div><div class="l">Tools found</div></div>
<div class="card Critical"><div class="n">$($toolsByRisk['Critical'])</div><div class="l">Critical</div></div>
<div class="card High"><div class="n">$($toolsByRisk['High'])</div><div class="l">High</div></div>
<div class="card Medium"><div class="n">$($toolsByRisk['Medium'])</div><div class="l">Medium</div></div>
<div class="card Low"><div class="n">$($toolsByRisk['Low'])</div><div class="l">Low</div></div>
<div class="card NoneFound"><div class="n">$($toolsByRisk['None found'])</div><div class="l">None found</div></div>
<div class="card NotChecked"><div class="n">$($toolsByRisk['Not checked'])</div><div class="l">Not checked</div></div>
</div>
<h2>AI apps, extensions and sites</h2>
<div class="tools" data-for="rows">
<input type="search" placeholder="Filter by app, site, user, source...">
<select class="f-risk"><option value="">All risks</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>None found</option><option>Not checked</option><option>Info</option></select>
</div>
<div class="wrap"><table><thead><tr><th>Risk</th><th>Data hits</th><th>User</th><th>Item</th><th>Category</th><th>Source</th><th>Visits</th><th>First seen</th><th>Last seen</th></tr></thead>
<tbody id="rows">
$($rowsHtml.ToString())</tbody></table></div>
$dataSection
<div class="notes"><b>Notes</b><ul>$notesHtml</ul>
<p>CSV and JSON: $(ConvertTo-HtmlText $OutputPath)</p></div>
</main>
<script>
document.querySelectorAll('.tools').forEach(function (bar) {
  var q = bar.querySelector('input'), r = bar.querySelector('.f-risk');
  var rows = document.querySelectorAll('#' + bar.dataset.for + ' tr');
  function apply() {
    var t = q.value.toLowerCase();
    rows.forEach(function (tr) {
      var ok = (!r.value || tr.dataset.risk === r.value) && (!t || tr.textContent.toLowerCase().indexOf(t) !== -1);
      tr.style.display = ok ? '' : 'none';
    });
  }
  q.addEventListener('input', apply); r.addEventListener('change', apply);
});
</script></body></html>
"@

$htmlName = 'RogueAI-Report_{0}_{1}.html' -f $env:COMPUTERNAME, $Started.ToString('yyyyMMdd-HHmmss')
$htmlPath = Join-Path $PSScriptRoot $htmlName
try {
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8 -ErrorAction Stop
} catch {
    $htmlPath = Join-Path $OutputPath $htmlName
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
}
Write-Output "HTML report: $htmlPath"

# Open it unless told not to or running non-interactively (SYSTEM / RMM)
$isSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
if (-not $NoOpen -and -not $isSystem -and [Environment]::UserInteractive) {
    try { Start-Process -FilePath $htmlPath } catch { Write-Output "Could not open the report: $($_.Exception.Message)" }
}

if ($FailOnSensitiveData -and ($DataFindings | Where-Object { $_.Severity -in 'Critical', 'High' })) { exit 1 }
exit 0

#endregion
