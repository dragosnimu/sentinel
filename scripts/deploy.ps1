#Requires -Version 5.1

<#
.SYNOPSIS
    Deploy Sentinel to the server over SSH, from PowerShell.

.DESCRIPTION
    The PowerShell twin of deploy.sh, for when Git Bash is not open. Both are
    thin wrappers: every deployment decision lives in deploy/install.sh on the
    server, so there is one implementation to test and these two cannot drift
    apart in behaviour.

    Uses the OpenSSH client built into Windows 10/11 and the bundled tar.exe.

    Secrets travel over the SSH channel on stdin — never as an argument, where
    `ps` on the server would show them, and never as a file left in /tmp.

.PARAMETER HostName
    Server address. Aliases: -SshHost, -Server, -H. (Not -Host: PowerShell
    reserves $Host for the console object.)

.PARAMETER User
    SSH user with sudo.

.PARAMETER Key
    Path to the private key.

.PARAMETER Domain
    Domain for the dashboard. Without it, certbot is skipped and a self-signed
    certificate is used.

.PARAMETER NginxMode
    dedicated — Sentinel's own nginx listener on -WebPort. Touches nothing that
    already exists, but the URL carries the port.
    shared — Sentinel becomes a vhost on the nginx already serving 80/443,
    selected by server_name. Clean URL and straightforward certificates, but it
    writes into a config directory shared with your own sites.

.PARAMETER WebPort
    Public HTTPS port in dedicated mode. Default 8443, never 443 — binding that
    would displace whatever this host already serves there.

.PARAMETER CertMode
    How to obtain the certificate. certbot's HTTP-01 challenge needs :80, which
    Sentinel does not own, so `--nginx` is unavailable. See docs/DEPLOYMENT.md §2.1.

.PARAMETER DryRun
    Run preflight only. Changes nothing on the server.

.PARAMETER Rollback
    Undo a previous deployment.

.PARAMETER Purge
    With -Rollback, also drop the database. That database is the entire
    security history.

.EXAMPLE
    .\scripts\deploy.ps1 -HostName 203.0.113.10 -User deploy `
        -Key $HOME\.ssh\sentinel_deploy -Domain sentinel.exemplu.ro -DryRun
#>

[CmdletBinding()]
param(
    # -Host cannot be used: PowerShell reserves $Host. The aliases exist because
    # `-Host` and `-SshHost` are what everyone types first.
    [Parameter(Mandatory = $true)][Alias('SshHost','Server','H')][string]$HostName,
    [Parameter(Mandatory = $true)][string]$User,
    [string]$Key,
    [int]$Port = 22,
    [string]$Domain,
    # The dashboard's public HTTPS port. Not 443 — this host serves something
    # else there. Must also be open in the provider's firewall.
    [ValidateSet('dedicated','shared')]
    [string]$NginxMode = 'dedicated',
    [int]$WebPort = 8443,
    [ValidateSet('auto','webroot','dns','selfsigned','none')]
    [string]$CertMode = 'auto',
    [string]$Email,
    # The address to allowlist. Left empty, it is read from the server as the
    # address you connected from — which is what you want unless you administer
    # from a different address than you deploy from.
    [string]$AdminIp,
    [int]$FromStep,
    [switch]$DryRun,
    [switch]$Rollback,
    [switch]$Purge,
    [switch]$AssumeYes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$SecretsFile = Join-Path $RepoRoot 'secrets\.env.local'

function Write-Info { param($m) Write-Host "[.] $m" -ForegroundColor Blue }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Die        { param($m) Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------
# No `?.` here: that is PowerShell 7 syntax, and stock Windows ships 5.1 — the
# shell this script exists for. It would fail at PARSE time, so the error would
# point at a line the reader had no reason to suspect.
function Find-Tool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$ssh = Find-Tool 'ssh.exe'
$scp = Find-Tool 'scp.exe'
$tar = Find-Tool 'tar.exe'

if (-not $ssh -or -not $scp) {
    Die @"
OpenSSH client not found. Install it with:
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Or run scripts/deploy.sh from Git Bash instead.
"@
}
if (-not $tar) { Die "tar.exe not found. It ships with Windows 10 1803 and later." }

# ---------------------------------------------------------------------------
$sshArgs = @(
    '-o', 'StrictHostKeyChecking=accept-new'
    '-o', 'ConnectTimeout=15'
    '-o', 'ServerAliveInterval=30'
    '-p', "$Port"
)
$scpArgs = @(
    '-o', 'StrictHostKeyChecking=accept-new'
    '-o', 'ConnectTimeout=15'
    '-P', "$Port"          # scp spells it -P, ssh spells it -p
)

if ($Key) {
    $Key = [System.Environment]::ExpandEnvironmentVariables($Key)
    if (-not (Test-Path $Key)) { Die "SSH key not found: $Key" }
    # Windows ACLs, not chmod: OpenSSH refuses a key readable by anyone but the
    # owner, and the error it gives is not obvious.
    $acl = Get-Acl $Key
    $others = $acl.Access | Where-Object {
        $_.IdentityReference -notmatch [regex]::Escape($env:USERNAME) -and
        $_.IdentityReference -notmatch 'SYSTEM|Administrators'
    }
    if ($others) {
        Write-Warn "Key $Key is readable by other principals. OpenSSH may refuse it."
        Write-Warn "Fix: icacls `"$Key`" /inheritance:r /grant:r `"$($env:USERNAME):R`""
    }
    $sshArgs += @('-i', $Key)
    $scpArgs += @('-i', $Key)
}

$target = "$User@$HostName"

# Built once, because a string that interpolates a nested double-quoted
# subexpression does not parse on PowerShell 5.1.
$keyArg    = ''
if ($Key) { $keyArg = " -Key `"$Key`"" }
$resumeCmd = ".\scripts\deploy.ps1 -HostName $HostName -User $User$keyArg"

# Two helpers, not one, because "return the exit code" and "let the operator
# watch and type a password" cannot both be done by the same function.
#
# A PowerShell function returns EVERYTHING written to its output stream. A
# single helper that ran ssh and then `return $LASTEXITCODE` returned an ARRAY
# of the remote stdout plus the code, so `(Invoke-Ssh ...) -ne 0` compared an
# array and was truthy whenever the remote command printed anything. The
# connectivity probe failed precisely because `echo connected` had worked.

function Test-Ssh {
    <# Runs a command for its exit code only. Output is discarded, so the return
       value is a plain int and safe to capture.

       stderr is sent to $null at the OS level, NOT merged with 2>&1. Under the
       script's $ErrorActionPreference='Stop', a native command that writes to
       stderr has its output promoted to a terminating error — and this helper's
       whole job is to run probes that are SUPPOSED to fail, like `sudo -n true`
       when credentials are not cached. Merging stderr would kill the run before
       the caller could read the exit code it asked for. #>
    [OutputType([int])]
    param([string]$Command, [switch]$Tty)
    $a = $sshArgs.Clone()
    if ($Tty) { $a += '-t' }
    # 2>$null alone is not enough on PowerShell 5.1: under $ErrorActionPreference
    # 'Stop' a native command that writes to stderr still throws a terminating
    # NativeCommandError. Lower the preference for the duration of the call so an
    # expected probe failure (e.g. `sudo -n true` with no cached creds) returns
    # its exit code instead of aborting the whole deploy.
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try   { & $ssh @a $target $Command 2>$null | Out-Null }
    finally { $ErrorActionPreference = $savedEAP }
    return $LASTEXITCODE
}

function Invoke-SshLive {
    <# Runs a command with nothing captured, so ssh inherits the console: sudo
       can prompt for a password and output appears as it happens rather than
       being buffered into lines. Returns nothing on purpose — capturing a
       return value is what would force PowerShell to redirect the output and
       destroy both properties. Read $LASTEXITCODE after the call. #>
    param([string]$Command, [switch]$Tty)
    $a = $sshArgs.Clone()
    if ($Tty) { $a += '-t' }
    & $ssh @a $target $Command
}

function Get-SshOutput {
    <# Runs a command and RETURNS its stdout as a single trimmed string. Distinct
       from Test-Ssh (which discards output for the exit code) — here the output
       is the point. #>
    param([string]$Command)
    $out = & $ssh @sshArgs $target $Command 2>$null
    return ($out | Out-String).Trim()
}

# ---------------------------------------------------------------------------
Write-Info "connecting to ${target}:$Port"
if ((Test-Ssh -Command 'echo connected') -ne 0) {
    Die "cannot reach $HostName. Check the address, the key, and whether your address is allowed by the provider firewall."
}
Write-Ok "SSH working"

# The address we connect FROM, as the server sees it. It must land in the
# nftables allowlist before any drop rule exists, or the first auto-block could
# shut you out. Read here over plain SSH: preflight and install run under sudo,
# which scrubs SSH_CLIENT, so the server cannot work it out on its own.
if (-not $AdminIp) {
    # Two statements, not one: `(Get-SshOutput '...' -split '\s+')` reads `-split`
    # as an argument to Get-SshOutput, so the split never happens and `[0]`
    # indexes the first CHARACTER of the string — "198.51.100.25" became "8".
    $sshConn = Get-SshOutput 'echo $SSH_CONNECTION'
    $AdminIp = ($sshConn -split '\s+')[0]
}
# Never allowlist something that is not an address: a malformed capture that slips
# through would put garbage in the nftables set, and the real address would be
# left out — the exact lockout the allowlist exists to prevent.
if ($AdminIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    Write-Warn "captured admin address '$AdminIp' is not an IPv4 address; ignoring it."
    $AdminIp = ''
}
if ($AdminIp) {
    Write-Ok "admin address (for the allowlist): $AdminIp"
} else {
    Write-Warn 'could not determine your address; the allowlist may end up empty. Pass -AdminIp <your-ip>.'
}

# ---------------------------------------------------------------------------
# Rollback — no packaging, no secrets
# ---------------------------------------------------------------------------
if ($Rollback) {
    Write-Warn "This stops Sentinel, deletes its nftables table (removing every block) and restores the pre-deploy configuration."
    if ($Purge) {
        Write-Warn "-Purge: the database WILL be dropped. Incidents, blocklist history, vulnerability findings and the patch audit trail are all in it."
    }
    if (-not $AssumeYes) {
        if ((Read-Host "Continui? [da/NU]") -ne 'da') { Die 'aborted' }
    }
    $flags = if ($Purge) { '--purge --yes' } else { '--yes' }
    Invoke-SshLive -Tty -Command "sudo /opt/sentinel/deploy/rollback.sh $flags"
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { Die "rollback reported errors — read the output above before retrying" }
    Write-Ok 'rollback complete'
    exit 0
}

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
if (-not $DryRun) {
    if (-not (Test-Path $SecretsFile)) {
        Die @"
No $SecretsFile.

Create it from Git Bash:
    ./scripts/secrets-init.sh

(That script uses masked terminal input, which PowerShell's Read-Host -AsSecureString
cannot reproduce without briefly materialising the value in memory as plain text.
Rather than do a worse job of it here, use the bash one — it is a one-off.)
"@
    }
    $content = Get-Content $SecretsFile -Raw
    foreach ($k in @('SENTINEL_DB_PASSWORD', 'ANTHROPIC_API_KEY', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID')) {
        if ($content -notmatch "(?m)^$k=.+") {
            Write-Warn "$k is missing or empty in $SecretsFile — the matching feature will be inert."
        }
    }
}

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------
$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$remoteDir = "/tmp/sentinel-deploy-$stamp"
$tarball   = Join-Path $env:TEMP "sentinel-$stamp.tar.gz"

# Source, vendored dashboard assets and the deploy tree compress to roughly
# 1 MB. Twenty is not a budget, it is a tripwire: nothing legitimate grows
# twentyfold between releases. Must match PACKAGE_MAX_KB in deploy.sh.
$PackageMaxKb = 20480

Write-Info 'packaging the repository'
Push-Location $RepoRoot
try {
    # secrets/ is excluded. Secrets go over stdin; a tarball lands in /tmp on
    # the server and lingers there.
    #
    # watcher/ is excluded on purpose, not to save bytes. It is the external
    # witness, and its whole value is running somewhere the monitored host
    # cannot reach. Shipping a copy here would put the thing that reports
    # Sentinel's death on the machine whose death it reports.
    & $tar --exclude='./secrets' --exclude='./.git' --exclude='./tests' `
           --exclude='./docs' --exclude='./watcher' --exclude='./dist' `
           --exclude='node_modules' --exclude='.next' `
           --exclude='__pycache__' --exclude='*.pyc' `
           --exclude='.venv' --exclude='.pytest_cache' --exclude='.mypy_cache' `
           --exclude='.ruff_cache' `
           -czf $tarball .
    if ($LASTEXITCODE -ne 0) { Die 'packaging failed' }
} finally { Pop-Location }

$sizeKb = [math]::Round((Get-Item $tarball).Length / 1KB)
Write-Ok "package built ($sizeKb KB)"

# The exclude list above was written before watcher/ existed, and for a while
# every deploy quietly compressed 400 MB of node_modules. It did not fail; it
# just appeared to hang. A ceiling turns the next such omission into one clear
# line instead of a wait long enough to reach for Ctrl+C.
if ($sizeKb -gt $PackageMaxKb) {
    Remove-Item $tarball -Force -ErrorAction SilentlyContinue
    Die "package is $sizeKb KB, over the $PackageMaxKb KB ceiling. Something large is being shipped that should not be. Add it to the exclude list in this script."
}

# A CRLF in a .sh or .service file fails on Linux as `bad interpreter:
# /bin/bash^M`. .gitattributes covers a git checkout; this catches a zip
# download, a copy through an editor, or a merge that lost the attributes.
$crlf = Get-ChildItem (Join-Path $RepoRoot 'deploy') -Recurse -File -Include *.sh, *.service, *.timer, *.nft |
    Where-Object { (Get-Content $_.FullName -Raw) -match "`r`n" }
if ($crlf) {
    Write-Host "error: CRLF line endings found — these will not execute on Linux:" -ForegroundColor Red
    $crlf | ForEach-Object { Write-Host "    $($_.FullName)" -ForegroundColor Red }
    Die "Re-clone with .gitattributes applied, or convert them before deploying."
}

Write-Info "transferring to ${HostName}:$remoteDir"
if ((Test-Ssh -Command "mkdir -p '$remoteDir'") -ne 0) { Die "cannot create $remoteDir on the server" }
& $scp @scpArgs -q $tarball "${target}:$remoteDir/sentinel.tar.gz"
if ($LASTEXITCODE -ne 0) { Die 'transfer failed' }
Remove-Item $tarball -Force

if ((Test-Ssh -Command "cd '$remoteDir' && tar -xzf sentinel.tar.gz && rm -f sentinel.tar.gz && chmod +x deploy/*.sh deploy/lib/*.sh 2>/dev/null || true") -ne 0) {
    Die 'extracting the package on the server failed'
}
Write-Ok 'package extracted'

# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------
if ($DryRun) {
    Write-Host ''
    Write-Info 'preflight only — nothing on the server will be changed'
    $domainArg = if ($Domain) { "--domain '$Domain'" } else { '' }
    $adminArg  = if ($AdminIp) { "--admin-ip '$AdminIp'" } else { '' }
    Invoke-SshLive -Tty -Command "sudo '$remoteDir/deploy/preflight.sh' $domainArg --web-port $WebPort --nginx-mode $NginxMode $adminArg"
    $rc = $LASTEXITCODE
    Test-Ssh -Command "rm -rf '$remoteDir'" | Out-Null
    exit $rc
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
Write-Host @'

  +--------------------------------------------------------------------+
  |  INAINTE DE A CONTINUA                                             |
  |                                                                    |
  |  1. Deschide o A DOUA sesiune SSH acum si las-o deschisa.          |
  |  2. Verifica accesul la consola VPS-ului de la provider --         |
  |     testeaza-l, nu presupune ca functioneaza.                      |
  |  3. Iesiri de urgenta, daca ceva merge prost:                      |
  |       touch /etc/sentinel/PANIC   -> blocklist golit in <=60s      |
  |       reboot                      -> blocurile nu se persista      |
  +--------------------------------------------------------------------+

'@ -ForegroundColor Yellow

if (-not $AssumeYes) {
    if ((Read-Host 'Ai facut cele de mai sus? [da/NU]') -ne 'da') {
        Die 'aborted — do the above first'
    }
}

# stdin carries the secrets, so it cannot also be a TTY and sudo must not
# prompt. Prime the credential cache over a separate interactive connection.
if ((Test-Ssh -Command 'sudo -n true') -ne 0) {
    Write-Info 'caching sudo credentials (you will be asked once)'
    Invoke-SshLive -Tty -Command 'sudo -v'
    if ($LASTEXITCODE -ne 0) {
        Die "sudo is not usable non-interactively. Add a NOPASSWD rule for $User, or run 'sudo -v' in your second SSH session and retry within the timeout."
    }
}

$installArgs = @("--nginx-mode $NginxMode", "--web-port $WebPort", "--cert-mode $CertMode")
if ($AdminIp)  { $installArgs += "--admin-ip '$AdminIp'" }
if ($Domain)   { $installArgs += "--domain '$Domain'" }
if ($Email)    { $installArgs += "--email '$Email'" }
if ($FromStep) { $installArgs += "--from-step $FromStep" }

Write-Info 'installing (secrets go over stdin, never argv)'

# install.sh is run as a file that already exists on the server. Piping it in
# as a script would consume stdin and the secrets would never arrive: the file
# is the script, stdin is the data.
$remoteCmd = "sudo -n '$remoteDir/deploy/install.sh' $($installArgs -join ' ')"
Get-Content $SecretsFile -Raw | & $ssh @sshArgs $target $remoteCmd
$installRc = $LASTEXITCODE

if ($installRc -ne 0) {
    Write-Host ''
    Write-Warn 'installation failed'
    Write-Warn 'The installer is step-numbered and idempotent. Fix the cause, then resume:'
    Write-Warn "    $resumeCmd -FromStep <N>"
    Write-Warn 'Or undo everything:'
    Write-Warn "    $resumeCmd -Rollback"
    exit 1
}

Write-Ok 'installation finished'

# Keep the extracted tree: rollback.sh lives in it, and it is what a resume uses.
Test-Ssh -Tty -Command "sudo mkdir -p /opt/sentinel && sudo cp -r '$remoteDir/deploy' /opt/sentinel/deploy" | Out-Null
Test-Ssh -Command "rm -rf '$remoteDir'" | Out-Null

$dash = if ($Domain) { $Domain } else { $HostName }
if ($NginxMode -eq 'shared') {
    $dashLine = "https://$dash"
} else {
    $dashLine = "https://${dash}:${WebPort}`n              (portul $WebPort trebuie deschis in firewall-ul providerului)"
}
Write-Host ''
Write-Ok "Sentinel deployed to $HostName"
Write-Host @"

  Dashboard : $dashLine
  Mod nginx : $NginxMode
  Rollback  : $resumeCmd -Rollback

  Urmatorii pasi:
    1. Verifica Telegram — ar trebui sa fi primit un mesaj de confirmare.
       Primirea lui dovedeste tot lantul: config, secrete, retea, token, chat id.
    2. Revizuieste /etc/sentinel/inventory.yaml.
    3. Lasa auto-block DEZACTIVAT 72h. Vei primi pe Telegram ce AR FI blocat.
    4. Dupa 72h fara fals-pozitive, activeaza-l.

"@
