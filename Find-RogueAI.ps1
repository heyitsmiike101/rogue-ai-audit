<#
.SYNOPSIS
    Read-only audit of a Windows endpoint for unsanctioned ("rogue" / shadow) AI use.

.DESCRIPTION
    Looks for:
      - Installed AI apps: Programs and Features (machine + loaded user hives), Store/MSIX packages,
        per-user install folders, and running processes.
      - Local LLM runtimes and downloaded model stores (Ollama, LM Studio, GPT4All, Jan, Hugging Face cache...).
      - AI CLIs and coding assistants (Claude Code, Codex, Gemini CLI, Copilot/Cline/Continue in VS Code-family editors).
      - AI browser extensions (Chrome, Edge, Brave, Vivaldi, Opera, Firefox and forks).
      - Visits to AI websites in browser history for the last -Days days, plus the machine DNS client cache
        (which also catches private/incognito browsing and desktop apps).

    Only AI-related history is reported, aggregated per site. Full URLs and page titles are written only with
    -IncludeUrls. Make sure browsing review is covered by the customer's acceptable-use / monitoring policy.

    Run elevated (or as SYSTEM from an RMM) to cover every user profile on the machine; otherwise only the
    current user is checked. Nothing on the machine is changed apart from writing the report folder; history
    databases are copied to a temp folder, read there, and the copies deleted.

    Risk ratings are defaults, not verdicts:
      High    data leaves to a foreign-jurisdiction (PRC) provider, an AI companion/"humanizer", an aggregator that
              relays prompts to many models, a local model runtime outside any control, or an extension that reads
              every page.
      Medium  mainstream consumer AI where prompts may be retained or used for training without an enterprise plan.
      Low     usually enterprise-licensed or narrow-purpose (Microsoft 365 Copilot, GitHub Copilot, Grammarly...).
      Review  heuristic match (keyword in a hostname or extension name); check it by hand.
      Info    governance tooling (e.g. the Prompt Security extension).

.PARAMETER Days
    How far back to read browser history. Default 30.

.PARAMETER OutputPath
    Report folder. Default: %ProgramData%\RogueAIAudit\<COMPUTER>_<timestamp> (falls back to %TEMP%).

.PARAMETER SanctionedDomains
    Domains the customer has approved (subdomains included), e.g. 'copilot.cloud.microsoft','m365.cloud.microsoft'.
    Matching findings are marked Status=Sanctioned instead of Unsanctioned.

.PARAMETER SanctionedApps
    App / extension names the customer has approved, as -like wildcards, e.g. 'Microsoft 365 Copilot*','GitHub Copilot*'.

.PARAMETER IncludeUrls
    Also write HistoryDetail.csv with every matching URL, page title and visit time.

.PARAMETER ScanModelFiles
    Also search each profile for large local model files (*.gguf, *.safetensors, *.ggml, *.onnx over 100 MB). Slower.

.PARAMETER FailOnUnsanctioned
    Exit with code 1 when any unsanctioned High or Medium finding exists (for RMM monitors). Default exit code is 0.

.PARAMETER NoOpen
    Don't open the HTML report when the run finishes. It is never opened when running as SYSTEM or non-interactively.

.OUTPUTS
    An HTML report (RogueAI-Report_<COMPUTER>_<timestamp>.html) saved in the script's own folder and opened in the
    default browser, plus Findings.csv / Summary.json in -OutputPath. If the script folder is read-only, the HTML goes
    to -OutputPath instead.

.EXAMPLE
    .\Find-RogueAI.ps1
    Audit with defaults (30 days of history), report under %ProgramData%\RogueAIAudit.

.EXAMPLE
    .\Find-RogueAI.ps1 -Days 90 -SanctionedDomains 'm365.cloud.microsoft','copilot.cloud.microsoft' -SanctionedApps 'Microsoft 365 Copilot*' -FailOnUnsanctioned
    Treat Microsoft 365 Copilot as approved and fail the RMM check if anything else turns up.

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. History is read through Windows' built-in winsqlite3.dll; if that is
    unavailable the script falls back to a raw scan of the database file (sites found, but no visit dates or counts).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$Days = 30,
    [string]$OutputPath,
    [string[]]$SanctionedDomains = @(),
    [string[]]$SanctionedApps = @(),
    [switch]$IncludeUrls,
    [switch]$ScanModelFiles,
    [switch]$FailOnUnsanctioned,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

#region Catalogs (edit these to tune detection)

# Websites. Domain matches itself and every subdomain. Path (regex) narrows a match on shared domains.
$SiteCatalog = @'
Domain;Name;Category;Risk;Path
chatgpt.com;ChatGPT;Chat assistant;Medium;
chat.openai.com;ChatGPT;Chat assistant;Medium;
openai.com;OpenAI;Chat assistant;Low;
platform.openai.com;OpenAI API platform;Developer API;Medium;
sora.com;OpenAI Sora;Image/video generation;Medium;
claude.ai;Claude;Chat assistant;Medium;
claude.com;Claude;Chat assistant;Medium;
console.anthropic.com;Anthropic API console;Developer API;Medium;
gemini.google.com;Google Gemini;Chat assistant;Medium;
bard.google.com;Google Gemini;Chat assistant;Medium;
aistudio.google.com;Google AI Studio;Developer API;Medium;
notebooklm.google.com;NotebookLM;Research assistant;Medium;
labs.google;Google Labs;Image/video generation;Medium;
copilot.microsoft.com;Microsoft Copilot (consumer);Chat assistant;Medium;
m365.cloud.microsoft;Microsoft 365 Copilot;Chat assistant;Low;
copilot.cloud.microsoft;Microsoft 365 Copilot;Chat assistant;Low;
bing.com;Copilot in Bing;Chat assistant;Medium;^/chat
github.com;GitHub Copilot;Code assistant;Low;^/copilot
x.com;Grok on X;Chat assistant;Medium;^/i/grok
grok.com;Grok;Chat assistant;Medium;
x.ai;xAI;Chat assistant;Medium;
meta.ai;Meta AI;Chat assistant;Medium;
mistral.ai;Mistral Le Chat;Chat assistant;Medium;
perplexity.ai;Perplexity;Search assistant;Medium;
you.com;You.com;Search assistant;Medium;
pi.ai;Pi;Chat assistant;Medium;
phind.com;Phind;Code assistant;Medium;
deepai.org;DeepAI;Chat assistant;High;
poe.com;Poe;Model aggregator;High;
openrouter.ai;OpenRouter;Model aggregator;High;
huggingface.co;Hugging Face;Model hub;Medium;
civitai.com;Civitai;Model hub;High;
together.ai;Together AI;Developer API;Medium;
groq.com;Groq;Developer API;Medium;
fireworks.ai;Fireworks AI;Developer API;Medium;
replicate.com;Replicate;Developer API;Medium;
fal.ai;fal;Developer API;Medium;
cohere.com;Cohere;Developer API;Medium;
deepseek.com;DeepSeek;Chat assistant;High;
kimi.com;Kimi (Moonshot);Chat assistant;High;
moonshot.cn;Kimi (Moonshot);Chat assistant;High;
qwen.ai;Qwen (Alibaba);Chat assistant;High;
tongyi.aliyun.com;Tongyi Qianwen (Alibaba);Chat assistant;High;
doubao.com;Doubao (ByteDance);Chat assistant;High;
yiyan.baidu.com;ERNIE Bot (Baidu);Chat assistant;High;
chatglm.cn;ChatGLM (Zhipu);Chat assistant;High;
z.ai;Z.ai (Zhipu);Chat assistant;High;
minimax.io;MiniMax;Chat assistant;High;
hailuoai.com;Hailuo AI (MiniMax);Image/video generation;High;
klingai.com;Kling AI (Kuaishou);Image/video generation;High;
trae.ai;Trae (ByteDance);Code assistant;High;
manus.im;Manus;AI agent;High;
genspark.ai;Genspark;AI agent;Medium;
character.ai;Character.AI;AI companion;High;
janitorai.com;Janitor AI;AI companion;High;
replika.com;Replika;AI companion;High;
crushon.ai;CrushOn.AI;AI companion;High;
undetectable.ai;Undetectable AI;AI humanizer;High;
stealthgpt.ai;StealthGPT;AI humanizer;High;
stealthwriter.ai;StealthWriter;AI humanizer;High;
chatpdf.com;ChatPDF;Document upload AI;High;
humata.ai;Humata;Document upload AI;High;
jasper.ai;Jasper;Writing assistant;Medium;
copy.ai;Copy.ai;Writing assistant;Medium;
writesonic.com;Writesonic;Writing assistant;Medium;
rytr.me;Rytr;Writing assistant;Medium;
quillbot.com;QuillBot;Writing assistant;Medium;
wordtune.com;Wordtune;Writing assistant;Medium;
grammarly.com;Grammarly;Writing assistant;Low;
gamma.app;Gamma;Presentation AI;Medium;
tome.app;Tome;Presentation AI;Medium;
beautiful.ai;Beautiful.ai;Presentation AI;Medium;
otter.ai;Otter.ai;Meeting transcription;Medium;
fireflies.ai;Fireflies.ai;Meeting transcription;Medium;
fathom.video;Fathom;Meeting transcription;Medium;
tldv.io;tl;dv;Meeting transcription;Medium;
read.ai;Read AI;Meeting transcription;Medium;
krisp.ai;Krisp;Meeting transcription;Medium;
midjourney.com;Midjourney;Image/video generation;Medium;
leonardo.ai;Leonardo.Ai;Image/video generation;Medium;
ideogram.ai;Ideogram;Image/video generation;Medium;
runwayml.com;Runway;Image/video generation;Medium;
pika.art;Pika;Image/video generation;Medium;
lumalabs.ai;Luma AI;Image/video generation;Medium;
krea.ai;Krea;Image/video generation;Medium;
stability.ai;Stability AI;Image/video generation;Medium;
firefly.adobe.com;Adobe Firefly;Image/video generation;Low;
heygen.com;HeyGen;Image/video generation;Medium;
synthesia.io;Synthesia;Image/video generation;Medium;
elevenlabs.io;ElevenLabs;Voice/music generation;Medium;
suno.com;Suno;Voice/music generation;Medium;
udio.com;Udio;Voice/music generation;Medium;
cursor.com;Cursor;Code assistant;Medium;
windsurf.com;Windsurf;Code assistant;Medium;
codeium.com;Codeium;Code assistant;Medium;
tabnine.com;Tabnine;Code assistant;Low;
replit.com;Replit;Code assistant;Medium;
blackbox.ai;Blackbox AI;Code assistant;High;
bolt.new;Bolt;App builder;Medium;
lovable.dev;Lovable;App builder;Medium;
v0.dev;v0;App builder;Medium;
v0.app;v0;App builder;Medium;
monica.im;Monica;Browser assistant;High;
sider.ai;Sider;Browser assistant;High;
maxai.me;MaxAI;Browser assistant;Medium;
harpa.ai;HARPA AI;Browser assistant;Medium;
getmerlin.in;Merlin;Browser assistant;Medium;
'@ | ConvertFrom-Csv -Delimiter ';'

# Unknown hosts matching this are reported as Risk=Review (likely ChatGPT clones / wrappers).
$KeywordHostPattern = '(chat-?gpt|gpt-?[0-9o]|openai|llm|chatbot|ai-?chat|\.ai$)'

# Desktop apps. Pattern (regex) is tested against uninstall DisplayName, Store package name and process name.
$AppCatalog = @'
Name;Pattern;Category;Risk
ChatGPT desktop;^ChatGPT|OpenAI\.ChatGPT;Chat assistant;Medium
Claude desktop;^Claude$|^Claude |AnthropicClaude|Claude_pzs8sxrjxfjjc;Chat assistant;Medium
Microsoft 365 Copilot;Microsoft 365 Copilot|Microsoft\.MicrosoftOfficeHub;Chat assistant;Low
Microsoft Copilot;^Microsoft\.Copilot$|^Copilot$|^Microsoft Copilot;Chat assistant;Low
Perplexity / Comet;Perplexity|^Comet$;Search assistant;Medium
DeepSeek;DeepSeek;Chat assistant;High
Kimi;\bKimi\b;Chat assistant;High
Doubao;Doubao;Chat assistant;High
Ollama;Ollama;Local LLM runtime;High
LM Studio;LM.?Studio;Local LLM runtime;High
GPT4All;GPT4All;Local LLM runtime;High
Jan;^Jan$|^Jan \d;Local LLM runtime;High
AnythingLLM;AnythingLLM;Local LLM runtime;High
Msty;^Msty;Local LLM runtime;High
KoboldCpp;kobold;Local LLM runtime;High
llama.cpp / llamafile;^llama-(server|cli)$|llamafile;Local LLM runtime;High
text-generation-webui;oobabooga|text-generation-webui;Local LLM runtime;High
Local image generation;ComfyUI|Stable.?Diffusion|Fooocus|InvokeAI|Automatic1111;Image/video generation;Medium
Cursor;^Cursor$|^Cursor \(|Anysphere;Code assistant;Medium
Windsurf / Codeium;Windsurf|Codeium;Code assistant;Medium
Trae (ByteDance);^Trae( |$);Code assistant;High
Tabnine;Tabnine;Code assistant;Low
Pieces;^Pieces( |$)|Pieces OS;Code assistant;Medium
Grammarly;Grammarly;Writing assistant;Low
Otter.ai;Otter\.ai|^Otter$;Meeting transcription;Medium
Fireflies;Fireflies;Meeting transcription;Medium
Krisp;^Krisp;Meeting transcription;Medium
Fathom;^Fathom;Meeting transcription;Medium
Poe;^Poe$;Model aggregator;High
'@ | ConvertFrom-Csv -Delimiter ';'

# Per-user paths (relative to the profile) that show an AI tool is or was installed. Size=1 reports folder size.
$UserIndicators = @'
Rel;Name;Category;Risk;Size
AppData\Local\AnthropicClaude;Claude desktop;Chat assistant;Medium;0
AppData\Local\Programs\Ollama;Ollama;Local LLM runtime;High;0
.ollama\models;Ollama model store;Local model files;High;1
AppData\Local\Programs\LM Studio;LM Studio;Local LLM runtime;High;0
.lmstudio\models;LM Studio model store;Local model files;High;1
.cache\lm-studio\models;LM Studio model store;Local model files;High;1
AppData\Local\nomic.ai\GPT4All;GPT4All model store;Local model files;High;1
AppData\Roaming\Jan;Jan;Local LLM runtime;High;0
AppData\Roaming\anythingllm-desktop;AnythingLLM;Local LLM runtime;High;0
AppData\Roaming\Msty;Msty;Local LLM runtime;High;0
.cache\huggingface\hub;Hugging Face model cache;Local model files;Medium;1
AppData\Local\Programs\cursor;Cursor;Code assistant;Medium;0
AppData\Local\Programs\Windsurf;Windsurf;Code assistant;Medium;0
AppData\Local\Programs\Trae;Trae (ByteDance);Code assistant;High;0
.claude;Claude Code CLI;AI CLI agent;Medium;0
.codex;OpenAI Codex CLI;AI CLI agent;Medium;0
.gemini;Gemini CLI;AI CLI agent;Medium;0
.continue;Continue (IDE assistant);Code assistant;Medium;0
AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code;Claude Code CLI (npm);AI CLI agent;Medium;0
AppData\Roaming\npm\node_modules\@openai\codex;OpenAI Codex CLI (npm);AI CLI agent;Medium;0
AppData\Roaming\npm\node_modules\@google\gemini-cli;Gemini CLI (npm);AI CLI agent;Medium;0
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
$HistoryDetail = New-Object System.Collections.Generic.List[object]
$Notes = New-Object System.Collections.Generic.List[string]

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Sanctioned([string]$Item, [string[]]$Domains) {
    foreach ($pattern in $SanctionedApps) { if ($Item -like $pattern) { return $true } }
    foreach ($d in $Domains) {
        if (-not $d) { continue }
        foreach ($s in $SanctionedDomains) {
            $s = $s.Trim().TrimStart('.').ToLowerInvariant()
            if ($d -eq $s -or $d.EndsWith(".$s")) { return $true }
        }
    }
    $false
}

function Add-Finding {
    param(
        [string]$User, [string]$Source, [string]$Category, [string]$Item, [string]$Detail, [string]$Risk,
        $Count = $null, $FirstSeen = $null, $LastSeen = $null, [string[]]$Domains = @()
    )
    $status = if (Test-Sanctioned -Item $Item -Domains $Domains) { 'Sanctioned' } else { 'Unsanctioned' }
    if ($Risk -eq 'Info') { $status = 'Governance' }
    $Findings.Add([pscustomobject]@{
        Computer  = $env:COMPUTERNAME
        User      = $User
        Source    = $Source
        Category  = $Category
        Item      = $Item
        Detail    = $Detail
        Risk      = $Risk
        Status    = $status
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
        if (-not ('RogueAiSqlite' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class RogueAiSqlite {
    [DllImport("winsqlite3.dll", CharSet = CharSet.Unicode)] static extern int sqlite3_open16(string filename, out IntPtr db);
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

if ($IsAdmin) {
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
                Add-Finding -User $k.User -Source 'Installed program' -Category $m.Category -Item $name -Risk $m.Risk `
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
            Add-Finding -User $users -Source 'Store/MSIX package' -Category $m.Category -Item $m.Name -Risk $m.Risk `
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
        Add-Finding -User $u -Source 'Running process' -Category $m.Category -Item $m.Name -Risk $m.Risk `
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
            Add-Finding -User $prof.User -Source 'Profile folder' -Category $ind.Category -Item $ind.Name -Risk $ind.Risk `
                -Detail $detail -LastSeen $last
        }

        foreach ($editor in '.vscode', '.vscode-insiders', '.cursor', '.windsurf', '.vscode-oss') {
            $extRoot = Join-Path $prof.Path "$editor\extensions"
            if (-not (Test-Path -LiteralPath $extRoot)) { continue }
            $ids = Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { if ($_.Name -match '^(.+?)-\d+\.\d+') { $matches[1].ToLowerInvariant() } } |
                Where-Object { $_ -match $IdeExtensionPattern } | Select-Object -Unique
            foreach ($id in $ids) {
                $risk = if ($id -like 'github.copilot*' -or $id -like 'tabnine.*') { 'Low' } else { 'Medium' }
                Add-Finding -User $prof.User -Source "IDE extension ($($editor.TrimStart('.')))" -Category 'Code assistant' `
                    -Item $id -Risk $risk -Detail $extRoot
            }
        }

        if ($ScanModelFiles) {
            Get-ChildItem -LiteralPath $prof.Path -Recurse -File -Force -Include *.gguf, *.safetensors, *.ggml, *.onnx -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 100MB } |
                Group-Object DirectoryName | ForEach-Object {
                    $gb = [math]::Round((($_.Group | Measure-Object Length -Sum).Sum) / 1GB, 2)
                    Add-Finding -User $prof.User -Source 'Model file scan' -Category 'Local model files' -Item 'Local model weights' `
                        -Risk 'High' -Count $_.Count -Detail "$($_.Name) ($gb GB): $(($_.Group | Select-Object -First 3 -ExpandProperty Name) -join ', ')" `
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
        $risk = if ($AllSites) { 'High' } else { 'Medium' }
        $detail = if ($AllSites) { "$Id; can read every site" } else { $Id }
        Add-Finding -User $User -Source "Browser extension ($Browser)" -Category 'Browser AI extension' -Item $Name -Risk $risk -Detail $detail
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
            $item = $site.Name; $cat = $site.Category; $risk = $site.Risk
        } elseif ($hostName -match $KeywordHostPattern) {
            $item = $hostName; $cat = 'Possible AI site (keyword)'; $risk = 'Review'
        } else { return }

        $key = "$User|$Browser|$item"
        if (-not $Agg.ContainsKey($key)) {
            $Agg[$key] = [pscustomobject]@{ User = $User; Browser = $Browser; Item = $item; Category = $cat; Risk = $risk
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
                Computer = $env:COMPUTERNAME; User = $User; Browser = $Browser; Site = $item; Risk = $risk
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
                    $rows = [RogueAiSqlite]::Query($copy, "SELECT u.url, u.title, v.visit_time FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time > $cut")
                    foreach ($r in $rows) { Register-Visit $User $Browser $r[0] $r[1] ([DateTime]::FromFileTimeUtc([long]$r[2] * 10)) }
                } else {
                    # visit_date = microseconds since 1970-01-01 UTC
                    $cut = ([DateTimeOffset]$CutoffUtc).ToUnixTimeMilliseconds() * 1000
                    $rows = [RogueAiSqlite]::Query($copy, "SELECT p.url, p.title, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id WHERE v.visit_date > $cut")
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
        Add-Finding -User $a.User -Source "Browser history ($($a.Browser))" -Category $a.Category -Item $a.Item -Risk $a.Risk `
            -Count $a.Count -FirstSeen $a.First -LastSeen $a.Last -Detail (($hosts | Sort-Object) -join ', ') -Domains $hosts
    }

#endregion

#region DNS cache

    try {
        $dnsHosts = Get-DnsClientCache -ErrorAction Stop | ForEach-Object Entry | Where-Object { $_ } | Select-Object -Unique
        $dnsAgg = @{}
        foreach ($h in $dnsHosts) {
            $site = Find-SiteMatch $h $null
            if ($site) { $item = $site.Name; $cat = $site.Category; $risk = $site.Risk }
            elseif ($h -match $KeywordHostPattern) { $item = $h; $cat = 'Possible AI site (keyword)'; $risk = 'Review' }
            else { continue }
            if (-not $dnsAgg.ContainsKey($item)) { $dnsAgg[$item] = [pscustomobject]@{ Cat = $cat; Risk = $risk; Hosts = @() } }
            $dnsAgg[$item].Hosts += $h.ToLowerInvariant()
        }
        foreach ($item in $dnsAgg.Keys) {
            $d = $dnsAgg[$item]
            Add-Finding -User '(machine)' -Source 'DNS cache (recent lookups)' -Category $d.Cat -Item $item -Risk $d.Risk `
                -Detail ($d.Hosts -join ', ') -Domains $d.Hosts
        }
    } catch {
        $Notes.Add("DNS cache not checked: $($_.Exception.Message)")
    }

#endregion

} finally {
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

#region Report

$RiskOrder = @{ High = 0; Medium = 1; Review = 2; Low = 3; Info = 4 }
$Sorted = $Findings | Sort-Object @{ Expression = { $RiskOrder[$_.Risk] } }, Status, Item, User

$findingsCsv = Join-Path $OutputPath 'Findings.csv'
$Sorted | Export-Csv -LiteralPath $findingsCsv -NoTypeInformation -Encoding UTF8
if ($IncludeUrls) {
    $HistoryDetail | Sort-Object User, VisitTime |
        Export-Csv -LiteralPath (Join-Path $OutputPath 'HistoryDetail.csv') -NoTypeInformation -Encoding UTF8
}

$unsanctioned = @($Findings | Where-Object { $_.Status -eq 'Unsanctioned' })
$summary = [ordered]@{
    Computer          = $env:COMPUTERNAME
    RunAt             = $Started.ToString('s')
    Elevated          = $IsAdmin
    HistoryDays       = $Days
    ProfilesScanned   = @($Profiles | ForEach-Object User)
    TotalFindings     = $Findings.Count
    Unsanctioned      = $unsanctioned.Count
    UnsanctionedByRisk = [ordered]@{
        High   = @($unsanctioned | Where-Object Risk -eq 'High').Count
        Medium = @($unsanctioned | Where-Object Risk -eq 'Medium').Count
        Review = @($unsanctioned | Where-Object Risk -eq 'Review').Count
        Low    = @($unsanctioned | Where-Object Risk -eq 'Low').Count
    }
    AiItemsFound      = @($Findings | ForEach-Object Item | Sort-Object -Unique)
    Notes             = @($Notes)
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputPath 'Summary.json') -Encoding UTF8

Write-Output ''
if ($Findings.Count -eq 0) {
    Write-Output 'No AI apps, extensions or AI site visits found.'
} else {
    Write-Output ("{0} findings ({1} unsanctioned: {2} High, {3} Medium, {4} Review, {5} Low)" -f $Findings.Count,
        $unsanctioned.Count, $summary.UnsanctionedByRisk.High, $summary.UnsanctionedByRisk.Medium,
        $summary.UnsanctionedByRisk.Review, $summary.UnsanctionedByRisk.Low)
    $Sorted | Format-Table Risk, Status, User, Item, Category, Source, Count, LastSeen -AutoSize | Out-String -Width 220 | Write-Output
}
foreach ($n in $Notes) { Write-Output "Note: $n" }
Write-Output "Report: $OutputPath"

# HTML report, saved next to the script
function ConvertTo-HtmlText($Value) {
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
$rowsHtml = New-Object System.Text.StringBuilder
foreach ($f in $Sorted) {
    $seen = if ($f.LastSeen) { ([datetime]$f.LastSeen).ToString('yyyy-MM-dd HH:mm') } else { '' }
    $first = if ($f.FirstSeen) { ([datetime]$f.FirstSeen).ToString('yyyy-MM-dd HH:mm') } else { '' }
    [void]$rowsHtml.AppendFormat('<tr data-risk="{0}" data-status="{1}"><td><span class="badge {0}">{0}</span></td><td>{1}</td><td>{2}</td><td><b>{3}</b><div class="detail">{4}</div></td><td>{5}</td><td>{6}</td><td class="num">{7}</td><td>{8}</td><td>{9}</td></tr>',
        (ConvertTo-HtmlText $f.Risk), (ConvertTo-HtmlText $f.Status), (ConvertTo-HtmlText $f.User), (ConvertTo-HtmlText $f.Item),
        (ConvertTo-HtmlText $f.Detail), (ConvertTo-HtmlText $f.Category), (ConvertTo-HtmlText $f.Source),
        (ConvertTo-HtmlText $f.Count), $first, $seen)
    [void]$rowsHtml.AppendLine()
}
$notesHtml = ($Notes | ForEach-Object { '<li>' + (ConvertTo-HtmlText $_) + '</li>' }) -join ''
if (-not $notesHtml) { $notesHtml = '<li>None.</li>' }
$byRisk = $summary.UnsanctionedByRisk

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rogue AI Audit - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>
:root { --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5d6675; --line:#dfe3ea;
  --high:#c62828; --medium:#d97706; --review:#6d4fc2; --low:#2f7d32; --info:#3a6fb0; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171c; --card:#1d2129; --fg:#e6e9ef; --muted:#9aa3b2; --line:#2e3440;
  --high:#ef5350; --medium:#f59e0b; --review:#a78bfa; --low:#66bb6a; --info:#64a0e6; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg); font:14px/1.45 "Segoe UI", system-ui, sans-serif; }
main { max-width:1400px; margin:0 auto; }
h1 { margin:0 0 4px; font-size:22px; } .sub { color:var(--muted); margin-bottom:20px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card .n { font-size:26px; font-weight:600; } .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.card.High .n { color:var(--high); } .card.Medium .n { color:var(--medium); } .card.Review .n { color:var(--review); } .card.Low .n { color:var(--low); }
.tools { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px; }
.tools input, .tools select { padding:7px 10px; border:1px solid var(--line); border-radius:6px; background:var(--card); color:var(--fg); font:inherit; }
.tools input { flex:1; min-width:200px; }
.wrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { position:sticky; top:0; background:var(--card); font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
td.num { text-align:right; } .detail { color:var(--muted); font-size:12px; word-break:break-all; max-width:520px; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; color:#fff; }
.badge.High { background:var(--high); } .badge.Medium { background:var(--medium); } .badge.Review { background:var(--review); }
.badge.Low { background:var(--low); } .badge.Info { background:var(--info); }
.notes { margin-top:20px; color:var(--muted); } .notes ul { margin:4px 0 0; padding-left:20px; }
</style></head><body><main>
<h1>Rogue AI Audit: $(ConvertTo-HtmlText $env:COMPUTERNAME)</h1>
<div class="sub">Run $($Started.ToString('yyyy-MM-dd HH:mm')) &middot; elevated: $IsAdmin &middot; profiles: $(ConvertTo-HtmlText ($summary.ProfilesScanned -join ', ')) &middot; history window: $Days days</div>
<div class="cards">
<div class="card"><div class="n">$($Findings.Count)</div><div class="l">Findings</div></div>
<div class="card"><div class="n">$($unsanctioned.Count)</div><div class="l">Unsanctioned</div></div>
<div class="card High"><div class="n">$($byRisk.High)</div><div class="l">High</div></div>
<div class="card Medium"><div class="n">$($byRisk.Medium)</div><div class="l">Medium</div></div>
<div class="card Review"><div class="n">$($byRisk.Review)</div><div class="l">Review</div></div>
<div class="card Low"><div class="n">$($byRisk.Low)</div><div class="l">Low</div></div>
</div>
<div class="tools">
<input id="q" type="search" placeholder="Filter by app, site, user, source...">
<select id="risk"><option value="">All risks</option><option>High</option><option>Medium</option><option>Review</option><option>Low</option><option>Info</option></select>
<select id="status"><option value="">All statuses</option><option>Unsanctioned</option><option>Sanctioned</option><option>Governance</option></select>
</div>
<div class="wrap"><table><thead><tr><th>Risk</th><th>Status</th><th>User</th><th>Item</th><th>Category</th><th>Source</th><th>Visits</th><th>First seen</th><th>Last seen</th></tr></thead>
<tbody id="rows">
$($rowsHtml.ToString())</tbody></table></div>
<div class="notes"><b>Notes</b><ul>$notesHtml</ul>
<p>CSV and JSON: $(ConvertTo-HtmlText $OutputPath)</p></div>
</main>
<script>
(function () {
  var q = document.getElementById('q'), r = document.getElementById('risk'), s = document.getElementById('status');
  var rows = document.querySelectorAll('#rows tr');
  function apply() {
    var t = q.value.toLowerCase();
    rows.forEach(function (tr) {
      var ok = (!r.value || tr.dataset.risk === r.value) && (!s.value || tr.dataset.status === s.value) &&
               (!t || tr.textContent.toLowerCase().indexOf(t) !== -1);
      tr.style.display = ok ? '' : 'none';
    });
  }
  q.addEventListener('input', apply); r.addEventListener('change', apply); s.addEventListener('change', apply);
})();
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

if ($FailOnUnsanctioned -and ($unsanctioned | Where-Object { $_.Risk -in 'High', 'Medium' })) { exit 1 }
exit 0

#endregion
