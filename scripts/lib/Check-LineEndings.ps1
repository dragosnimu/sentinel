#Requires -Version 5.1
<#
.SYNOPSIS
    Refuse a deploy package that carries CR bytes inside a text file.

.DESCRIPTION
    The PowerShell twin of scripts/lib/check-line-endings.sh. Same subject
    (the built .tar.gz, not the working tree), same criterion (every text file
    that ships must be LF), same three exit codes:

        0  every text file in the package is LF-only
        1  at least one text file carries CR -- every offender is named
        2  the package could not be inspected. "Unknown" is not "clean".

    The reasoning behind the criterion is written out once, in the bash twin.
    The short version: the guard these two replace looked for CR under deploy/
    in a handful of extensions and called that everything. It missed
    deploy/audit/sentinel.rules, where a trailing CR turns the audit key
    `sentinel_ssh` into `sentinel_ssh^M` -- auditd loads the rule, the collector
    matches nothing, and nothing anywhere reports a fault. It also missed
    sentinel/, scripts/ and executor/, which all ship, and executor/ runs as
    root.

    "Binary" is decided by content -- a NUL byte -- and not by extension, so a
    new binary format needs no new exception and raises no false alarm. *.ps1
    is exempt: it ships only because scripts/ ships, it runs on Windows alone,
    and .gitattributes keeps it CRLF on purpose.

.PARAMETER Package
    The .tar.gz that deploy.ps1 has just built.

.PARAMETER SourceRoot
    Optional. Prefixed to each reported path so the operator is shown the file
    to edit rather than a path inside a temporary extraction.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Package,
    [string]$SourceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Work = $null

function Complete-Check {
    param([int]$Code)
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit $Code
}

# Every "I could not look" path ends here, and it never returns 0. There is no
# way for this script to call a package clean on the strength of not having
# read it.
function Stop-Unknown {
    param([string]$Message)
    Write-Host "error: line-ending check could not run: $Message" -ForegroundColor Red
    Complete-Check 2
}

function Test-CarriesCr {
    <# True when the file is text AND contains a CR byte. Whole-file scan: a
       CR hidden past the first buffer still ships. #>
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { return $false }
    if ([Array]::IndexOf($bytes, [byte]0) -ge 0) { return $false }   # binary
    return ([Array]::IndexOf($bytes, [byte]13) -ge 0)
}

if (-not (Test-Path -LiteralPath $Package -PathType Leaf)) {
    Stop-Unknown "no such package: $Package"
}
# The bundled Windows tar (bsdtar) by preference, and by explicit path.
# `Get-Command tar.exe` finds Git for Windows' MSYS tar first on most developer
# machines, and that one reads "C:\Users\..." as a REMOTE HOST: it fails with
# "Cannot connect to C: resolve failed" and exit 2. Measured here, 2026-08-10.
$tarSource = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $tarSource -PathType Leaf)) {
    $tarCmd = Get-Command 'tar.exe' -ErrorAction SilentlyContinue
    if (-not $tarCmd) { Stop-Unknown 'tar.exe is not on PATH' }
    $tarSource = $tarCmd.Source
}

$script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-crlf-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

# ---------------------------------------------------------------------------
# Prove the detector detects, before trusting its silence.
#
# A detector that answers "no" to everything looks exactly like a clean tree,
# forever. Three files with known answers cost microseconds, and the bash twin
# was caught lying by its own probe on the first run.
$probe = Join-Path $script:Work 'probe'
New-Item -ItemType Directory -Path $probe -Force | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $probe 'crlf'),   [byte[]](97, 13, 10))
[System.IO.File]::WriteAllBytes((Join-Path $probe 'lf'),     [byte[]](97, 10))
[System.IO.File]::WriteAllBytes((Join-Path $probe 'binary'), [byte[]](97, 0, 98, 13, 10))

if (-not (Test-CarriesCr (Join-Path $probe 'crlf'))) {
    Stop-Unknown 'the detector did not flag a file known to contain CR; its silence proves nothing'
}
if (Test-CarriesCr (Join-Path $probe 'lf')) {
    Stop-Unknown 'the detector flagged a file known to be LF-only; its output cannot be used'
}
if (Test-CarriesCr (Join-Path $probe 'binary')) {
    Stop-Unknown 'the detector flagged a file known to be binary; binaries would raise false alarms'
}
Remove-Item -LiteralPath $probe -Recurse -Force

# ---------------------------------------------------------------------------
$tree = Join-Path $script:Work 'pkg'
New-Item -ItemType Directory -Path $tree -Force | Out-Null

$savedEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
& $tarSource -xzf $Package -C $tree 2>$null | Out-Null
$tarRc = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
if ($tarRc -ne 0) { Stop-Unknown "could not extract $Package (tar exit $tarRc)" }

$files = @(Get-ChildItem -LiteralPath $tree -Recurse -File -Force)
# An empty extraction satisfies "no CR found" perfectly. It is not a clean
# package, it is the absence of one.
if ($files.Count -eq 0) { Stop-Unknown "$Package extracted to no files at all" }

$prefix = $tree.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
$offenders = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    if ($f.Name -like '*.ps1') { continue }
    if (Test-CarriesCr $f.FullName) {
        $rel = $f.FullName.Substring($prefix.Length) -replace '\\', '/'
        $rel = $rel -replace '^\./', ''
        $offenders.Add($rel) | Out-Null
    }
}

if ($offenders.Count -gt 0) {
    Write-Host ("error: CR line endings in {0} file(s) inside the deploy package:" -f $offenders.Count) -ForegroundColor Red
    foreach ($rel in ($offenders | Sort-Object)) {
        $shown = if ($SourceRoot) { "$SourceRoot/$rel" } else { $rel }
        Write-Host "    $shown" -ForegroundColor Red
    }
    Write-Host @'

These would reach the server exactly as they are. A CR breaks a shebang
("bad interpreter: /bin/bash^M"), a systemd directive and an nginx value
loudly -- and an auditd key silently: the rule loads and then matches nothing.

Fix them in the working tree, then deploy again:

    sed -i 's/\r//g' <the files listed above>

If git reports those files unmodified afterwards, something rewrote them
between commit and deploy: .gitattributes normalises on commit, not on disk.
'@
    Complete-Check 1
}

Write-Host ("{0} file(s) in the package; no CR in any text file (binaries and *.ps1 exempt)" -f $files.Count)
Complete-Check 0
