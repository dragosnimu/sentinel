#Requires -Version 5.1
<#
.SYNOPSIS
    Build the Sentinel deploy package from what git tracks, plus nothing else.

.DESCRIPTION
    The PowerShell twin of scripts/lib/build-package.sh -- same boundary (git
    tracked, not a hand-maintained --exclude list) and the same categories
    trimmed out of what IS tracked (secrets/, tests/, docs/, watcher/,
    aggregator/, scratchpad/, .claude/worktrees/). The full reasoning is
    argued once, in the bash twin, so this file and that one cannot drift
    apart on WHY each category is trimmed -- only on how a Windows tar reads a
    file list, which is the only thing actually different here.

    Short version of the reasoning: `credentiale.txt` and `env.txt` sat at the
    repo root, matched by .gitignore, never `git add`ed -- and still reached a
    tarball built as "everything minus a denylist", because the denylist did
    not know either name. `git ls-files` already knows, the moment such a file
    is created, because .gitignore told it once.

    Uses newline-delimited `git ls-files` output (not `-z`/NUL-delimited,
    which Windows PowerShell 5.1 cannot pass through a pipeline without a
    binary-safe redirect that 5.1 does not have). `core.quotepath=false`
    keeps a non-ASCII filename from being C-quoted into something that would
    not match itself on disk. This repo carries no filenames with an embedded
    newline today (checked 2026-09-08: zero quoted paths under default
    core.quotepath); a future one would silently truncate an entry rather
    than fail loudly, which the bash twin (NUL-delimited, immune to this)
    does not share.

.PARAMETER Tarball
    Destination .tar.gz path.

.PARAMETER RepoRoot
    Repository root -- the git working tree to package. Content is read from
    this WORKING TREE, not from git's object store: an uncommitted fix in a
    tracked file still ships, same as every deploy before this one.

.OUTPUTS
    Exit code only (this runs as a separate process via `&`, like its
    Check-LineEndings.ps1 sibling):
        0  package built at -Tarball
        2  could not determine what belongs in the package -- no git.exe, not
           a git working tree, or git returned an empty list. Never falls
           back to "ship everything" or "ship nothing" silently.
        3  untracked, non-ignored files sit under a shipped category -- named
           on the console. `sentinel/telegram/callback_sign.py`, 8 Sep 2026:
           new, untracked, imported by the SAME commit's modified `bot.py`,
           which WAS tracked and shipped -- host crash-looped on import after
           a green build and a green test suite, because nothing in the
           working tree was missing, only from git's index. This is a
           correctness gate, not a prompt: nothing the caller passes skips it.
        *  whatever tar.exe returned
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Tarball,
    [Parameter(Mandatory = $true)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Unknown {
    param([string]$Message)
    Write-Host "error: build-package could not run: $Message" -ForegroundColor Red
    exit 2
}

function Stop-Untracked {
    param([string[]]$Paths)
    Write-Host "error: untracked, non-ignored files sit under what this package would ship. adauga in git sau sterge:" -ForegroundColor Red
    foreach ($p in $Paths) { Write-Host "    $p" -ForegroundColor Red }
    exit 3
}

$gitCmd = Get-Command 'git.exe' -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Stop-Unknown 'git.exe is not on PATH -- this packaging depends on git to keep gitignored files out and cannot fall back to shipping the whole tree without reintroducing that hole.'
}
$git = $gitCmd.Source

# The bundled Windows tar (bsdtar) by preference, and by explicit path.
# `Get-Command tar.exe` finds Git for Windows' MSYS tar first on most developer
# machines, and that one reads "C:\Users\..." as a REMOTE HOST and dies with
# "Cannot connect to C:" -- caught by Check-LineEndings.ps1 first, 2026-08-10.
$tarSource = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $tarSource -PathType Leaf)) {
    $tarCmd = Get-Command 'tar.exe' -ErrorAction SilentlyContinue
    if (-not $tarCmd) { Stop-Unknown 'tar.exe is not on PATH' }
    $tarSource = $tarCmd.Source
}

$savedEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
& $git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
$gitRc = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
if ($gitRc -ne 0) {
    Stop-Unknown "$RepoRoot is not a git working tree -- deploy from a git clone (docs/DEPLOYMENT.md section 3.1)."
}

# The pathspecs trim CATEGORIES that ARE tracked but do not belong on the
# wire -- see scripts/lib/build-package.sh for why each one exists; that
# reasoning has not changed, only the mechanism that enforces it. ONE array,
# used for both the tracked list below and the untracked-file check further
# down -- two separate copies of this same list is exactly the shape of drift
# that let credentiale.txt slip past the old --exclude list in the first place.
$pathspecs = @(
    '.'
    ':!secrets'
    ':!tests'
    ':!docs'
    ':!watcher'
    ':!aggregator'
    ':!scratchpad'
    ':!.claude/worktrees'
)

$savedEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$lines = & $git -c core.quotepath=false -C $RepoRoot ls-files -- @pathspecs 2>$null
$gitRc = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
if ($gitRc -ne 0) {
    Stop-Unknown 'git ls-files failed'
}

$lines = @($lines | Where-Object { $_ -ne '' })
# An empty list would satisfy every "nothing forbidden is in the package"
# test perfectly, and it is not a package.
if ($lines.Count -eq 0) {
    Stop-Unknown "git ls-files returned nothing for $RepoRoot -- an empty package is not a safe default, refusing"
}

# Untracked and NOT gitignored -- a file simply nobody has `git add`ed yet.
# `sentinel/telegram/callback_sign.py`, 8 Sep 2026: new, untracked, imported
# by the SAME commit's modified `bot.py`, which WAS tracked and shipped --
# host crash-looped on import after a green build. `--yes`/-AssumeYes at the
# deploy.ps1 call site does not skip this: it is a correctness gate, not a
# confirmation prompt, and this function never even sees that flag.
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$untrackedLines = & $git -c core.quotepath=false -C $RepoRoot ls-files --others --exclude-standard -- @pathspecs 2>$null
$gitRc = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
if ($gitRc -ne 0) {
    Stop-Unknown 'git ls-files --others failed'
}
$untrackedLines = @($untrackedLines | Where-Object { $_ -ne '' })
if ($untrackedLines.Count -gt 0) {
    Stop-Untracked $untrackedLines
}

$listFile = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-pkg-list-" + [Guid]::NewGuid().ToString('n') + '.txt')
try {
    # No BOM: bsdtar would otherwise read three stray bytes as part of the
    # first file name and fail to find it on disk.
    [System.IO.File]::WriteAllLines($listFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    & $tarSource -cz -T $listFile -C $RepoRoot -f $Tarball 2>$null
    $tarRc = $LASTEXITCODE
    $ErrorActionPreference = $savedEAP
    if ($tarRc -ne 0) {
        Write-Host "error: tar exited $tarRc while building the package" -ForegroundColor Red
        exit $tarRc
    }
} finally {
    Remove-Item -LiteralPath $listFile -Force -ErrorAction SilentlyContinue
}

exit 0
