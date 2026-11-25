# Windows counterpart of run-dev.sh: builds the core and runs, for development, the stub parrot
# and the daemon (unprivileged, its state under $env:RIOT_DEV_DIR), until Ctrl-C. No tray app yet.
#   dev\run-dev.ps1           then, in another shell:
#   $env:RIOT_SOCKET='\\.\pipe\riot-dev'; core\target\release\riotctl.exe status
# RIOT_DEV_BUILD=0 runs the last build as it is.
# The gateway (127.0.0.1:7591) is also an HTTPS_PROXY here (RIOT_DEV_PROXY=0 turns it off); its
# certificates chain to the stub's root, $env:RIOT_DEV_DIR\stub-root.pem: trust that one
# (Import-Certificate -CertStoreLocation Cert:\CurrentUser\Root). See docs/network-interception.md.
# Where the agent is installed (the RiotAgent service), it is paused for the run (a UAC prompt)
# and resumes when the run ends; its daemon still holds 7591, and the dev gateway listens on 7601.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'core\target\release'

# Process-wide variables, inherited by the children; put back as they were when the run ends.
$saved = @{}
function Set-DevVariable([string]$name, [string]$value) {
  if (-not $saved.ContainsKey($name)) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
  [Environment]::SetEnvironmentVariable($name, $value)
}
function Get-DevVariable([string]$name, [string]$default) {
  $value = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrEmpty($value)) { $default } else { $value }
}

$devDir = Get-DevVariable 'RIOT_DEV_DIR' (Join-Path $env:TEMP 'riot-dev')
New-Item -ItemType Directory -Force $devDir | Out-Null
$socket = Get-DevVariable 'RIOT_SOCKET' '\\.\pipe\riot-dev'

if ((Get-DevVariable 'RIOT_DEV_BUILD' '1') -eq '1') {
  Write-Host 'building the core...'
  # Cargo reports progress on stderr, which PowerShell 5.1 turns into errors once redirected.
  $ErrorActionPreference = 'Continue'
  cargo build --release --manifest-path (Join-Path $root 'core\Cargo.toml') -p riot-daemon 2>&1 | ForEach-Object { "$_" }
  $ErrorActionPreference = 'Stop'
  if ($LASTEXITCODE -ne 0) { exit 1 }
} elseif (-not (Test-Path (Join-Path $bin 'riot-daemon.exe'))) {
  Write-Error 'no build in core\target\release: run without RIOT_DEV_BUILD=0 once'
}

function Test-Port([int]$port) {
  $client = New-Object System.Net.Sockets.TcpClient
  try { $client.ConnectAsync('127.0.0.1', $port).Wait(300) } catch { $false } finally { $client.Dispose() }
}

$gatewayAddr = Get-DevVariable 'RIOT_GATEWAY_ADDR' ''
if (-not $gatewayAddr -and (Test-Port 7591)) {
  $gatewayAddr = '127.0.0.1:7601'
  Write-Host "127.0.0.1:7591 is taken (the installed agent?): the dev gateway listens on $gatewayAddr"
}

# The installed agent, paused for as long as this PowerShell runs: it resumes once this process
# is gone, however the run ends. Pausing needs an elevated client: one UAC prompt.
$paused = $false
if (Test-Path '\\.\pipe\com.tryriot.agent') {
  Write-Host 'pausing the installed agent for this run (UAC)'
  $riotctl = Join-Path $bin 'riotctl.exe'
  try {
    $pause = Start-Process -FilePath $riotctl -ArgumentList 'pause', $PID -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    $paused = $pause.ExitCode -eq 0
  } catch {}
  if (-not $paused) { Write-Warning 'could not pause the installed agent: it keeps guarding the clipboard and the AI apps' }
}

$processes = @()
try {
  Set-DevVariable 'STUB_CA_DIR' $devDir
  $processes += Start-Process -FilePath (Join-Path $bin 'riot-stub-parrot.exe') -ArgumentList '8787', '--dev' -NoNewWindow -PassThru

  Set-DevVariable 'RIOT_SETTINGS' (Join-Path $root 'dev\settings.json')
  Set-DevVariable 'RIOT_DATA_DIR' $devDir
  Set-DevVariable 'RIOT_SOCKET' $socket
  Set-DevVariable 'RIOT_DEV_ALLOW_SCAN' '1'
  Set-DevVariable 'RIOT_DEV_PROXY' (Get-DevVariable 'RIOT_DEV_PROXY' '1')
  if ($gatewayAddr) { Set-DevVariable 'RIOT_GATEWAY_ADDR' $gatewayAddr }
  $daemon = Start-Process -FilePath (Join-Path $bin 'riot-daemon.exe') -NoNewWindow -PassThru
  $processes += $daemon
  Write-Host "daemon on $socket; Ctrl-C stops the run"
  $daemon.WaitForExit()
} finally {
  foreach ($process in $processes) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
  }
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
  if ($paused) { Write-Host 'the installed agent resumes' }
}
