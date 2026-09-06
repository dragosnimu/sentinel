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
    SSH account to deploy as. Defaults to sentinel-deploy, the account
    deploy/install.sh creates with NOPASSWD sudo, and the account named in
    history.skip_command_accounts.

    That pairing is the whole point of the default. auid is the LOGIN uid and
    survives sudo, so deploying under a human account files all 405 777
    terminal-less commands of a run under that human's name — a name the filter
    does not know, and must not, because the same operator's remote diagnostics
    run under it and are worth keeping. Override only if you installed with a
    different DEPLOY_ACCOUNT, and change the config to match.

.PARAMETER Key
    Path to the private key. Defaults to $HOME\.ssh\sentinel_deploy, the key
    authorized on the sentinel-deploy account -User also defaults to.

    The two are one decision. sentinel-deploy authorizes that key and no other,
    so keeping the new -User with an older key ends the run at the first ssh with
    "Permission denied (publickey)" — and the way out of that is to put -User
    back, which makes the history filter inert again.

    Only a default: a -Key you pass is used as given and must exist, and a
    missing default is a warning, not an error, because an agent or an
    IdentityFile in ~/.ssh/config are legitimate and this script cannot see them.

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

.PARAMETER DbPort
    Pin PostgreSQL's own port instead of letting step 22 read whatever the
    cluster actually ended up on. See deploy/install.sh's own --db-port for why
    5432 is never assumed. Forwarded to install.sh as-is; unset means no
    override, same as running install.sh without the flag.

.PARAMETER FromStep
    Resume an interrupted install: every step BELOW N is skipped. At or above N
    a completion marker still wins, so this does NOT re-run anything already
    done. To re-run a step, use -ForceStep.

.PARAMETER ForceStep
    Clear the completion markers of the listed steps so their bodies run again.
    One number, or a comma-separated list: -ForceStep 22,27 re-runs both in the
    same pass, which is what rotating a secret requires — step 22 changes the
    password in PostgreSQL and step 27 writes it into /etc/sentinel/secrets.env,
    and the services are restarted at the end of that same run. See
    docs/OPERARE.md §11.

.PARAMETER Secrets
    Path to the secrets file. Omitted, this is exactly today's behaviour:
    secrets\.env.local — including that a missing default file is a hard stop
    telling the operator to run scripts/secrets-init.sh from Git Bash, not a
    fallback that generates one here.

    Given and missing, it is still a hard stop, but for a different reason: a
    path the operator named on purpose does not get replaced by a freshly
    generated file under that name. That substitution is exactly how a
    database password and a beacon secret got rotated by accident — see
    secrets/.gitkeep.

    Checked on -DryRun too: a misspelled path must fail the rehearsal, not
    "pass" it and only die on the real run that follows.

.PARAMETER AllowRotation
    Explicit consent to send a secret that Compare-SecretsWithHost found would
    change an existing value on the host. Allows all of them. -AssumeYes does
    NOT imply this — it answers the OTHER prompts this script already asked
    before this flag existed; a rotation needs its own, because "answer every
    prompt" was exactly how a stale fallback file would have rotated
    SENTINEL_BEACON_SECRET without anyone reading the warning.

.PARAMETER AllowRotationKeys
    Like -AllowRotation but for only the named keys (comma-separated, same
    four forms -ForceStep accepts). Any changed key not in the list is still
    gated — interactively, or refused outright under -AssumeYes.

.EXAMPLE
    .\scripts\deploy.ps1 -HostName 203.0.113.10 `
        -Domain sentinel.exemplu.ro -DryRun
#>

[CmdletBinding()]
param(
    # -Host cannot be used: PowerShell reserves $Host. The aliases exist because
    # `-Host` and `-SshHost` are what everyone types first.
    [Parameter(Mandatory = $true)][Alias('SshHost','Server','H')][string]$HostName,
    # Not Mandatory, and hardcoded rather than read from the environment: on
    # Windows $env:USERNAME is always set, so a default derived from it would
    # silently be the old behaviour on the exact machine this fixes.
    [string]$User = 'sentinel-deploy',
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
    [int]$DbPort,
    [int]$FromStep,
    # [string[]], not [string], and that is not a style choice. In argument mode
    # PowerShell reads a bare comma as an ARRAY constructor, so `-ForceStep 22,27`
    # binds @('22','27'). Declared [string] it is then coerced back with $OFS —
    # arriving as "22 27", two arguments on the remote command line, and the
    # installer dies on the second. Declared [string[]] and joined with a comma,
    # all four forms the operator might type (22,27 / '22,27' / 22, 27 /
    # '22, 27') produce the same 22,27. Measured on Windows PowerShell 5.1.
    [string[]]$ForceStep,
    [string]$Secrets,
    [switch]$AllowRotation,
    [string[]]$AllowRotationKeys,
    [switch]$DryRun,
    [switch]$Rollback,
    [switch]$Purge,
    [switch]$AssumeYes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot    = Split-Path -Parent $PSScriptRoot
# -Secrets replaces the default path outright. Kept as a check on $Secrets
# further down (not folded away here) because what matters there is not just
# which path is in use, but whether the OPERATOR named it — that is what
# decides whether a missing file just dies, or dies with a different message.
$SecretsFile = if ($Secrets) { $Secrets } else { Join-Path $RepoRoot 'secrets\.env.local' }

function Write-Info { param($m) Write-Host "[.] $m" -ForegroundColor Blue }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Die        { param($m) Write-Host "error: $m" -ForegroundColor Red; exit 1 }

function Get-StepList {
    <# Normalise a step list into what install.sh expects: 22 or 22,27.

       The value ends up inside the remote command STRING, where a space would
       split it into two arguments. So the spaces go — but only after the shape
       has been checked, because "22 27" (a list typed without commas) must be
       refused rather than squeezed into 2227, a number that means nothing and
       would be obeyed in silence. Refusing the whole list is the point: a run
       that forces half of a rotation is worse than one that forces none of it. #>
    param([string[]]$Value, [string]$Flag)
    $raw = $Value -join ','
    if ($raw -notmatch '^\s*\d+(\s*,\s*\d+)*\s*$') {
        Die "${Flag}: '$raw' is not a step number or a comma-separated list of them (e.g. 22 or 22,27)"
    }
    return ($raw -replace '\s', '')
}

function Get-KeyList {
    <# Same shape check as Get-StepList, for -AllowRotationKeys: refuse a
       malformed list rather than silently matching nothing, which would look
       identical to "no key allowed" and refuse a rotation the operator
       thought they had just authorised. #>
    param([string[]]$Value, [string]$Flag)
    $raw = $Value -join ','
    if ($raw -notmatch '^\s*[A-Za-z_][A-Za-z0-9_]*(\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s*$') {
        Die "${Flag}: '$raw' is not a KEY_NAME or a comma-separated list of them (e.g. SENTINEL_DB_PASSWORD or SENTINEL_DB_PASSWORD,TELEGRAM_BOT_TOKEN)"
    }
    return ($raw -replace '\s', '')
}

# Resolved before anything is packaged or transferred: a typo should cost a
# second, not a round trip. install.sh checks it again on the server, where it
# remains the authority on which numbers are real steps.
$forceStepList = ''
if ($ForceStep) { $forceStepList = Get-StepList -Value $ForceStep -Flag '-ForceStep' }

$allowRotationKeysList = ''
if ($AllowRotationKeys) { $allowRotationKeysList = Get-KeyList -Value $AllowRotationKeys -Flag '-AllowRotationKeys' }

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

# Paired with $User above: sentinel-deploy authorizes this key and no other, so
# the account default is only usable together with the key default. Applied only
# when the file is really there — substituting a path that does not exist would
# turn "ssh, choose an identity" into a hard error on machines that worked.
$DeployKeyDefault = Join-Path $HOME '.ssh\sentinel_deploy'
if (-not $Key) {
    if (Test-Path $DeployKeyDefault) {
        $Key = $DeployKeyDefault
        Write-Info "using default key $Key (pairs with -User $User)"
    } else {
        Write-Warn "no -Key and $DeployKeyDefault does not exist; ssh will choose an identity."
        Write-Warn "If it picks the one for your own login, $User@$HostName refuses it with"
        Write-Warn "'Permission denied (publickey)' — that account authorizes sentinel_deploy."
    }
}

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

# Three helpers, not one, because "return the exit code", "let the operator
# watch and type a password" and "return the output" cannot all be done by
# the same function.
#
# A PowerShell function returns EVERYTHING written to its output stream. A
# single helper that ran ssh and then `return $LASTEXITCODE` returned an ARRAY
# of the remote stdout plus the code, so `(Invoke-Ssh ...) -ne 0` compared an
# array and was truthy whenever the remote command printed anything. The
# connectivity probe failed precisely because `echo connected` had worked.

function Invoke-SshCapture {
    <# The ONE place in this file that redirects ssh's stderr, and therefore
       the one place that has to fight a Windows PowerShell 5.1 bug: under
       this script's own $ErrorActionPreference = 'Stop', a native command
       whose stderr is redirected — even `2>$null`, with nothing merged into
       the success stream — has each stderr line promoted to a terminating
       NativeCommandError. `2>$null` alone is not enough; the preference has
       to be lowered around the call too.

       This is not theoretical against this host: production's sshd
       (openssh-server-9.9p1-9.el9_8, no post-quantum key exchange) writes
       three such lines to stderr on EVERY connection from this machine's
       client (OpenSSH 10.2p1, which warns about exactly that). Measured
       directly: a nested powershell.exe that writes those three lines throws
       out of a bare `2>$null` call, in both -Command and -File invocation,
       and stops doing so once wrapped exactly as below.

       Test-Ssh and Get-SshOutput used to each carry their OWN copy of
       `& $ssh ... 2>$null` plus their own lowered-preference guard — Test-Ssh
       had it, Get-SshOutput did not, which is exactly the shape CLAUDE.md
       warns about: a guard copied into one call site and missing from the
       next one added later. This is now the only function that touches `2>`,
       so there is nothing left to copy or to forget.

       Returns a PSCustomObject: Output (whatever the native call produced —
       $null, a scalar string, or a string[], unchanged from what `& $ssh`
       would have handed either caller directly) and ExitCode (read from
       $LASTEXITCODE immediately after the call, before anything else here
       can reset it). #>
    param([string[]]$Arguments, [string]$Target, [string]$Command)
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try   { $out = & $ssh @Arguments $Target $Command 2>$null }
    finally { $ErrorActionPreference = $savedEAP }
    return [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
}

function Test-Ssh {
    <# Runs a command for its exit code only. Output is discarded, so the return
       value is a plain int and safe to capture. See Invoke-SshCapture for why
       stderr has to be handled the way it is — this helper's whole job is to
       run probes that are SUPPOSED to fail, like `sudo -n true` when
       credentials are not cached, and a promoted NativeCommandError would
       kill the run before the caller could read the exit code it asked for. #>
    [OutputType([int])]
    param([string]$Command, [switch]$Tty)
    $a = $sshArgs.Clone()
    if ($Tty) { $a += '-t' }
    return (Invoke-SshCapture -Arguments $a -Target $target -Command $Command).ExitCode
}

function Invoke-SshLive {
    <# Runs a command with nothing captured, so ssh inherits the console: sudo
       can prompt for a password and output appears as it happens rather than
       being buffered into lines. Returns nothing on purpose — capturing a
       return value is what would force PowerShell to redirect the output and
       destroy both properties. Read $LASTEXITCODE after the call.

       Deliberately does NOT go through Invoke-SshCapture: that helper exists
       to survive a REDIRECTED stderr, and this call has no redirection at
       all — stderr goes straight to the inherited console, same as stdout.
       Measured: a bare `& $ssh ...` with no `2>` and no capture does not
       throw under $ErrorActionPreference = 'Stop' even when the child writes
       to stderr, on this same PowerShell 5.1. Routing it through the other
       helper would add a redirection that is not wanted here — it would
       swallow the very prompt this function exists to show. #>
    param([string]$Command, [switch]$Tty)
    $a = $sshArgs.Clone()
    if ($Tty) { $a += '-t' }
    & $ssh @a $target $Command
}

function Get-SshOutput {
    <# Runs a command and RETURNS its stdout as a single trimmed string. Distinct
       from Test-Ssh (which discards output for the exit code) — here the output
       is the point. See Invoke-SshCapture for the stderr handling shared with
       Test-Ssh.

       The captured output is an ARRAY of already-clean lines (native-command
       capture handles both LF and CRLF transports without leaving a residual
       `\r` per line). Joined with "`n" explicitly here — NOT with
       `Out-String`, which on Windows PowerShell 5.1 inserts
       [Environment]::NewLine, i.e. CRLF. That CR then rides along inside every
       line but the last once a caller (Compare-SecretsWithHost) splits the
       result back apart on "`n" alone, so a value that was identical on both
       sides compared unequal for every key except the last. Measured: a
       four-key remote reply where only the last line's hash matched. #>
    param([string]$Command)
    $result = Invoke-SshCapture -Arguments $sshArgs -Target $target -Command $Command
    $out = $result.Output
    if ($null -eq $out) { return '' }
    return (($out -join "`n")).Trim()
}

function Confirm-SudoCached {
    <# Shared by Compare-SecretsWithHost and by the install step further down:
       both feed the connection with something that cannot also be a human
       typing a password — structured output here, the secrets file on stdin
       there. Idempotent: once credentials are cached, a second call is a
       single `sudo -n true` and nothing more, so calling it twice in one run
       costs a cheap round trip, not a second prompt. #>
    if ((Test-Ssh -Command 'sudo -n true') -ne 0) {
        Write-Info 'caching sudo credentials (you will be asked once)'
        Invoke-SshLive -Tty -Command 'sudo -v'
        if ($LASTEXITCODE -ne 0) {
            Die "sudo is not usable non-interactively. Add a NOPASSWD rule for $User, or run 'sudo -v' in your second SSH session and retry within the timeout."
        }
    }
}

function Get-ValueHash {
    <# SHA-256 of the value's raw UTF-8 bytes, no added newline — matching
       `printf '%s' "$value" | sha256sum` on the host side of every comparison
       Compare-SecretsWithHost makes. First 16 hex characters: enough to tell
       two values apart, never enough to be the value. #>
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').Substring(0, 16).ToLower()
}

# Runs ON THE HOST under `sudo -n bash`, fed by a base64 pipe rather than an
# interpolated command string — same technique, same reason, as the identical
# script in deploy.sh's $REMOTE_SECRETS_SCRIPT: it reads /etc/sentinel/
# secrets.env itself, hashes each value with sha256sum ON THAT MACHINE, and
# prints only a key and a hash. The value that produced the hash never leaves
# the process that read it. Kept as the same shell text as deploy.sh's copy —
# tests/unit/test_deploy_secrets_flag.py checks the two have not drifted.
$RemoteSecretsScript = (@'
F=/etc/sentinel/secrets.env
if [ ! -e "$F" ]; then
    printf 'ABSENT'
    exit 0
fi
CR=$(printf '\r')
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$CR}"
    stripped="${line#"${line%%[![:space:]]*}"}"
    case "$stripped" in
        ''|'#'*) continue ;;
    esac
    case "$stripped" in
        [A-Za-z_]*=*) ;;
        *) continue ;;
    esac
    key="${stripped%%=*}"
    value="${stripped#*=}"
    # Same single trailing-then-leading double-quote strip as the LOCAL side
    # of this comparison (compare_secrets_with_host / Compare-SecretsWithHost)
    # and install.sh's stdin reader (read_stdin_secrets). Skipped, a value
    # install.sh once wrote with quotes and now carries forward VERBATIM
    # (existing_secret, deploy/install.sh, never strips) would hash
    # differently here than the same value typed unquoted into
    # secrets/.env.local — a secret that never actually changed would report
    # as "changed" forever.
    value="${value%\"}"; value="${value#\"}"
    hash="$(printf '%s' "$value" | sha256sum | cut -c1-16)"
    printf '%s %s\n' "$key" "$hash"
done < "$F"
'@) -replace "`r`n", "`n"

function Test-RotationAllowed {
    <# Twin of rotation_allowed in deploy.sh. Consent to actually SEND a
       rotation is decided by -AllowRotation / -AllowRotationKeys, never by
       -AssumeYes — see the -AssumeYes note in Compare-SecretsWithHost. #>
    param([string]$Key)
    if ($AllowRotation) { return $true }
    if (-not $allowRotationKeysList) { return $false }
    return ($allowRotationKeysList -split ',') -contains $Key
}

function Compare-SecretsWithHost {
    <# The half that matters: refuse to rotate a secret without saying so.
       Compares by KEY NAME plus the hash above — never a value, on either
       side — and reports three groups: what would CHANGE (a real rotation
       risk), what exists only locally (about to be added), what exists only
       on the host (untouched by this run; step 27 on the server carries
       forward any key not supplied on stdin).

       A host with no secrets.env yet is a first install: nothing to compare,
       and nothing here says otherwise. On -DryRun this reports only and
       never gates — nothing is sent to gate. Twin of compare_secrets_with_host
       in deploy.sh — read the reasoning there; this follows it exactly. #>
    $localHash = @{}
    foreach ($rawLine in (Get-Content -LiteralPath $SecretsFile)) {
        $stripped = $rawLine.TrimStart()
        if (-not $stripped -or $stripped.StartsWith('#')) { continue }
        if ($stripped -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { continue }
        $k = $Matches[1]; $v = $Matches[2]
        # Same single trailing-then-leading quote strip as deploy.sh and as
        # install.sh's own stdin reader (read_stdin_secrets). Skipped, a
        # hand-quoted value in secrets\.env.local would hash differently here
        # than the unquoted value the installer actually writes to the host.
        if ($v.EndsWith('"'))   { $v = $v.Substring(0, $v.Length - 1) }
        if ($v.StartsWith('"')) { $v = $v.Substring(1) }
        $localHash[$k] = Get-ValueHash $v
    }

    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RemoteSecretsScript))
    $remoteOut = Get-SshOutput "printf '%s' '$b64' | base64 -d | sudo -n bash 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Die "could not read /etc/sentinel/secrets.env on $HostName to compare secrets (sudo -n failed: $remoteOut). This refuses rather than deploying unchecked — cache sudo credentials (sudo -v in your second SSH session) and retry."
    }

    if ($remoteOut -eq 'ABSENT') {
        Write-Info "$HostName has no /etc/sentinel/secrets.env yet — first install, nothing to compare."
        return
    }

    $remoteHash = @{}
    foreach ($line in ($remoteOut -split "`n")) {
        if (-not $line) { continue }
        $parts = $line -split ' ', 2
        if ($parts.Count -eq 2) { $remoteHash[$parts[0]] = $parts[1] }
    }

    $changed = @(); $localOnly = @(); $hostOnly = @()
    foreach ($k in $localHash.Keys) {
        if ($remoteHash.ContainsKey($k)) {
            if ($localHash[$k] -ne $remoteHash[$k]) { $changed += $k }
        } else {
            $localOnly += $k
        }
    }
    foreach ($k in $remoteHash.Keys) {
        if (-not $localHash.ContainsKey($k)) { $hostOnly += $k }
    }
    $changed = @($changed | Sort-Object)
    $localOnly = @($localOnly | Sort-Object)
    $hostOnly = @($hostOnly | Sort-Object)

    if ($localOnly) { Write-Info ("only in the local file (will be added): " + ($localOnly -join ' ')) }
    if ($hostOnly)  { Write-Info ("only on the host (not sent, left untouched): " + ($hostOnly -join ' ')) }

    if (-not $changed) {
        Write-Ok 'secrets: no existing key would change value'
        return
    }

    Write-Warn ("these EXISTING keys on the host would get a NEW value: " + ($changed -join ' '))
    foreach ($k in $changed) {
        if ($k -eq 'SENTINEL_BEACON_SECRET') {
            Write-Warn "SENTINEL_BEACON_SECRET is the key shared with the external watcher — a new value here alone means the watcher rejects every signal as a bad signature, which looks exactly like a host that has gone silent. Only rotate it together with the watcher's copy (docs/OPERARE.md §11)."
        }
    }

    # A dry run reports and stops here — it sends nothing, so there is
    # nothing left to gate. This is the rehearsal the incident this check
    # closes never got: -DryRun used to skip this whole comparison.
    if ($DryRun) {
        Write-Warn "dry run: reporting only. A real run either asks interactively or needs -AllowRotation for these keys — see docs/OPERARE.md §11."
        return
    }

    Write-Warn "if this is a rotation you meant to run (docs/OPERARE.md §11), continue. If you did not expect any of these to change, stop — the local file may be the wrong one."

    $unallowed = @($changed | Where-Object { -not (Test-RotationAllowed $_) })
    if (-not $unallowed) {
        Write-Ok ("secrets: rotation of " + ($changed -join ' ') + " explicitly allowed by -AllowRotation")
        return
    }

    # -AssumeYes does NOT reach here as consent. It answers the OTHER prompts
    # this script asks; a secret rotation needs its own explicit flag, because
    # "answer every prompt so the run doesn't stop" was exactly how a stale
    # fallback file would have rotated SENTINEL_BEACON_SECRET without anyone
    # reading a word of this warning.
    if ($AssumeYes) {
        Die "-AssumeYes does not authorise a secret rotation by itself: $($unallowed -join ' ') would change and -AllowRotation was not given for them. Re-run with -AllowRotation (or -AllowRotationKeys $($unallowed -join ',')) once you have confirmed this is the rotation you meant, or without -AssumeYes to be asked interactively."
    }

    if ((Read-Host "Continui rotirea? [da/NU]") -ne 'da') { Die 'aborted — nothing was sent to the host' }
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
# The -Secrets existence check runs whether or not this is a dry run: a
# misspelled path must fail preflight, not "pass" it and only die on the real
# run that follows — the exact gap a -DryRun rehearsal exists to close.
if ($Secrets -and -not (Test-Path $SecretsFile)) {
    # Named explicitly: the operator meant THIS file. No suggestion to run
    # secrets-init.sh here — that would write a DIFFERENT file
    # (secrets\.env.local) and leave the one just asked for still missing,
    # which is not the fix it would look like.
    Die "-Secrets $SecretsFile`: file not found. Not treating this as the default-missing case — a path you named does not get replaced by a freshly generated file under that name."
}

if (-not (Test-Path $SecretsFile)) {
    if ($DryRun) {
        # No name was given (checked above) — the ordinary default-missing
        # case. Tolerated here so a first install can still rehearse: there
        # is nothing to compare yet.
        Write-Warn "no $SecretsFile — dry run continues without a secrets comparison; a real run will need it (scripts/secrets-init.sh) or the path you pass with -Secrets."
    } else {
        Die @"
No $SecretsFile.

Create it from Git Bash:
    ./scripts/secrets-init.sh

(That script uses masked terminal input, which PowerShell's Read-Host -AsSecureString
cannot reproduce without briefly materialising the value in memory as plain text.
Rather than do a worse job of it here, use the bash one — it is a one-off.)
"@
    }
}

if (Test-Path $SecretsFile) {
    $content = Get-Content $SecretsFile -Raw
    $missingKeys = @()
    foreach ($k in @('SENTINEL_DB_PASSWORD', 'ANTHROPIC_API_KEY', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID')) {
        if ($content -notmatch "(?m)^$k=.+") { $missingKeys += $k }
    }
    if ($missingKeys.Count -gt 0) {
        Write-Warn "missing or empty in $SecretsFile`: $($missingKeys -join ' ')"
        Write-Warn "Sentinel will install but the corresponding feature will be inert."
        # Twin of deploy.sh's `(( ! DRY_RUN )) && (( ! ASSUME_YES ))` gate: a
        # dry run must never block on stdin (an unattended rehearsal has
        # none to give), and -AssumeYes answers this prompt exactly as it
        # answers deploy.sh's --yes. Without this, the two wrappers this
        # file's own .DESCRIPTION says "cannot drift apart in behaviour" did
        # exactly that — deploy.sh stopped for confirmation here and this
        # script silently proceeded with an inert feature nobody agreed to.
        if (-not $DryRun -and -not $AssumeYes) {
            if ((Read-Host "Continui oricum? [da/NU]") -ne 'da') {
                Die 'aborted; run scripts/secrets-init.sh'
            }
        }
    }

    # Runs on a dry run too — report-only, see Compare-SecretsWithHost.
    Confirm-SudoCached
    Compare-SecretsWithHost
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
    #
    # aggregator/ is excluded for the same reason and one more. It runs on the
    # same external hosting as the witness, and it is the archive of what left
    # this machine — "what left cannot be deleted from here" stops being true
    # the moment a copy of the archive's schema and credentials-handling code
    # sits on the host being archived. Nothing under deploy/ or sentinel/ reads
    # it.
    #
    # scratchpad/ holds verification harnesses and their `.bak` copies of
    # install.sh, config.py and the signing module — source nothing on the host
    # runs, second copies of files whose single-copy-ness is the point, and a
    # stale harness that can be run against a newer tree. The size ceiling below
    # sees none of that. This list must stay identical to the one in deploy.sh;
    # tests/security/test_package_contents.py compares them, because a Windows
    # deploy that ships what a Linux deploy excludes is the same hole.
    #
    # .claude/worktrees/ is excluded; the REST of .claude/ must ship.
    # `deploy/install.sh` step 25 copies ${SRC_ROOT}/.claude/skills and
    # ${SRC_ROOT}/.claude/agents out of this archive into the workspace the
    # headless CLI runs in. Excluding all of .claude/ deletes the source of
    # that cp and kills the install at step 25; making the cp tolerant would be
    # worse, because the CLI would then lose the skill and the agents silently.
    # worktrees/ is the part that grows — 6.6 MB against 228 KB of skills — and
    # the only part that would push the archive over $PackageMaxKb.
    & $tar --exclude='./secrets' --exclude='./.git' `
           --exclude='./.claude/worktrees' `
           --exclude='./tests' `
           --exclude='./docs' --exclude='./watcher' --exclude='./aggregator' `
           --exclude='./scratchpad' `
           --exclude='./dist' `
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
# /bin/bash^M`. A CRLF in deploy/audit/sentinel.rules is worse, because it is
# quiet: the key becomes `sentinel_ssh^M`, auditd accepts the rule, and the
# collector matches nothing until somebody notices.
#
# The check is on the PACKAGE, after tar and before the transfer, so it reads
# the exact bytes that are about to leave this machine. .gitattributes
# normalises on commit; this is what catches a file a tool rewrote between
# commit and deploy. Criterion and exemptions are argued in the script itself,
# which is the twin of the one deploy.sh calls.
#
# Any non-zero exit stops the deploy, including exit 2 — "I could not inspect
# the package" is not permission to send it.
& (Join-Path $PSScriptRoot 'lib\Check-LineEndings.ps1') -Package $tarball -SourceRoot $RepoRoot
if ($LASTEXITCODE -ne 0) {
    Remove-Item $tarball -Force -ErrorAction SilentlyContinue
    Die 'refusing to deploy this package — see above.'
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
# prompt. Credentials were already primed once for Compare-SecretsWithHost
# above; called again because packaging and the line-ending check run in
# between, and a slow one of those is exactly the gap a cached credential can
# expire in.
Confirm-SudoCached

$installArgs = @("--nginx-mode $NginxMode", "--web-port $WebPort", "--cert-mode $CertMode")
if ($AdminIp)  { $installArgs += "--admin-ip '$AdminIp'" }
if ($Domain)   { $installArgs += "--domain '$Domain'" }
if ($Email)    { $installArgs += "--email '$Email'" }
if ($DbPort)   { $installArgs += "--db-port $DbPort" }
if ($FromStep) { $installArgs += "--from-step $FromStep" }
if ($forceStepList) { $installArgs += "--force-step $forceStepList" }

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
