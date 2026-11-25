<#
.SYNOPSIS
    Insider Threat Agent - Windows Service Installer
    Installs agent.py as a background Windows Service that auto-starts on reboot.
    Also enables all required Windows Audit Policies automatically.

.USAGE
    Run as Administrator:
        .\install_service.ps1 -ServerURL "http://192.168.1.100:5000/ingest"

.PARAMETERS
    -ServerURL    : IP of the machine running central_server.py (required)
    -AgentFolder  : Path to agent files (default: auto-detected)
    -Uninstall    : Remove the service instead of installing
#>

param(
    [string]$ServerURL = "",
    [string]$AgentFolder = "",
    [switch]$Uninstall = $false
)

$ServiceName = "InsiderThreatAgent"
$ServiceDisplayName = "Insider Threat Monitoring Agent"
$ServiceDescription = "Monitors user behavior and sends security events to the central analysis server."

# -- Helper -------------------------------------------------------------------
function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red; exit 1 }

# -- Check Admin --------------------------------------------------------------
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Fail "Please run this script as Administrator (Right-click -> Run as Administrator)"
}

# -- Uninstall mode -----------------------------------------------------------
if ($Uninstall) {
    Write-Step "Removing $ServiceName service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName
    Write-OK "Service removed."
    exit 0
}

# =============================================================================
# STEP 0: Enable Windows Audit Policies (REQUIRED for agent to collect logs)
# =============================================================================
Write-Step "Enabling Windows Audit Policies..."

# Login / Logout tracking (Event ID 4624, 4634, 4625)
auditpol /set /subcategory:"Logon"              /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff"             /success:enable /failure:enable | Out-Null
Write-OK "Login/Logout auditing enabled (Event 4624, 4634, 4625)"

# File System access (Event ID 4656, 4663) - required for cross-dept file monitoring
auditpol /set /subcategory:"File System"        /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Handle Manipulation" /success:enable                 | Out-Null
Write-OK "File access auditing enabled (Event 4656, 4663)"

# Process / CMD / PowerShell tracking (Event ID 4688)
auditpol /set /subcategory:"Process Creation"   /success:enable                 | Out-Null
Write-OK "Process creation auditing enabled (Event 4688)"

# Privilege use - detects privilege escalation (Event ID 4672)
auditpol /set /subcategory:"Special Logon"      /success:enable                 | Out-Null
Write-OK "Special logon auditing enabled (Event 4672)"

# PowerShell Script Block Logging (detects encoded/hidden PS commands)
$psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (-not (Test-Path $psLoggingPath)) { New-Item -Path $psLoggingPath -Force | Out-Null }
Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-OK "PowerShell Script Block Logging enabled (Event 4104)"

# Command line arguments in process creation (shows full command, not just exe name)
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
If (-not (Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-OK "Full command-line logging enabled"

Write-Host "`n    All audit policies configured successfully!" -ForegroundColor Green
# =============================================================================


# -- System-wide install path (Program Files - accessible to ALL users) -------
$InstallDir   = "C:\Program Files\InsiderThreatAgent"
$AgentSrcDir  = if ($AgentFolder) { $AgentFolder } else {
    Join-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)) "vm_agent"
}
$ConfigSrcDir = Join-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)) "config"

Write-Step "Insider Threat Agent - Windows Service Installer"
Write-Host "    Source folder  : $AgentSrcDir"
Write-Host "    Install folder : $InstallDir"
Write-Host "    Service name   : $ServiceName"

# -- Check Python (system-wide, not user-specific) ----------------------------
Write-Step "Checking Python installation..."
try {
    $pythonPath = (Get-Command python -ErrorAction Stop).Source
    # Reject Windows Store stub (WindowsApps path)
    if ($pythonPath -like "*WindowsApps*") {
        Write-Fail "Python found but it is the Windows Store stub. Please install real Python 3.8+ from python.org"
    }
    $pythonVersion = python --version 2>&1
    Write-OK "Found: $pythonVersion at $pythonPath"
} catch {
    # Try to auto-download Python silently
    Write-Host "    Python not found. Downloading Python 3.11..." -ForegroundColor Yellow
    $pyInstaller = "$env:TEMP\python_installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $pyInstaller -UseBasicParsing
    Start-Process -FilePath $pyInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonPath) { Write-Fail "Python installation failed. Install manually from python.org" }
    Write-OK "Python installed successfully at $pythonPath"
}

# -- Copy agent files to C:\Program Files\InsiderThreatAgent\ -----------------
Write-Step "Copying agent files to Program Files (system-wide)..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\config" | Out-Null

Copy-Item -Path "$AgentSrcDir\*" -Destination $InstallDir -Recurse -Force
Write-OK "Agent files copied to $InstallDir"

if (Test-Path $ConfigSrcDir) {
    Copy-Item -Path "$ConfigSrcDir\*" -Destination "$InstallDir\config" -Force
    Write-OK "Config files copied to $InstallDir\config"
}

$agentScript = "$InstallDir\agent.py"
if (-not (Test-Path $agentScript)) {
    Write-Fail "agent.py not found after copy. Check source path: $AgentSrcDir"
}

# -- Install Python dependencies (system-wide) --------------------------------
Write-Step "Installing required Python packages..."
$requirementsPath = "$InstallDir\requirements.txt"
if (-not (Test-Path $requirementsPath)) {
    $requirementsPath = Join-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)) "requirements.txt"
}
if (Test-Path $requirementsPath) {
    pip install -r $requirementsPath -q
    Write-OK "Dependencies installed from requirements.txt"
} else {
    pip install pywin32 requests psutil -q
    Write-OK "Core dependencies installed"
}

# -- Update agent_config.json with server URL ---------------------------------
$configPath = "$InstallDir\config\agent_config.json"
if ($ServerURL -and (Test-Path $configPath)) {
    Write-Step "Updating server URL in agent_config.json..."
    $config = Get-Content $configPath | ConvertFrom-Json
    $config.server_url = $ServerURL
    $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
    Write-OK "server_url set to: $ServerURL"
} elseif ($ServerURL) {
    Write-Host "    [WARN] agent_config.json not found at $configPath" -ForegroundColor Yellow
}


# ── Install NSSM (Non-Sucking Service Manager) ────────────────────────────────
Write-Step "Checking for NSSM (service wrapper)..."
$nssmPath = "$env:TEMP\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Write-Host "    Downloading NSSM..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\nssm.zip" -UseBasicParsing
        Expand-Archive "$env:TEMP\nssm.zip" -DestinationPath "$env:TEMP\nssm" -Force
        Copy-Item "$env:TEMP\nssm\nssm-2.24\win64\nssm.exe" $nssmPath
        Write-OK "NSSM downloaded"
    } catch {
        Write-Fail "Could not download NSSM. Install manually from https://nssm.cc"
    }
} else {
    Write-OK "NSSM already available"
}

# ── Remove existing service if present ───────────────────────────────────────
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Removing existing service installation..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & $nssmPath remove $ServiceName confirm
    Write-OK "Old service removed"
}

# ── Install as Windows Service ────────────────────────────────────────────────
Write-Step "Installing Windows Service..."
$logFile = Join-Path $AgentFolder "agent_service.log"

& $nssmPath install $ServiceName $pythonPath
& $nssmPath set $ServiceName AppParameters "$agentScript"
& $nssmPath set $ServiceName AppDirectory $AgentFolder
& $nssmPath set $ServiceName DisplayName $ServiceDisplayName
& $nssmPath set $ServiceName Description $ServiceDescription
& $nssmPath set $ServiceName Start SERVICE_AUTO_START
& $nssmPath set $ServiceName AppStdout $logFile
& $nssmPath set $ServiceName AppStderr $logFile
& $nssmPath set $ServiceName AppRestartDelay 5000   # Restart after 5s if crashes
& $nssmPath set $ServiceName AppRotateFiles 1
& $nssmPath set $ServiceName AppRotateBytes 10485760  # 10MB log rotation

Write-OK "Service installed"

# ── Start the service ─────────────────────────────────────────────────────────
Write-Step "Starting service..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-OK "Service is RUNNING!"
} else {
    Write-Host "    [WARN] Service status: $($svc.Status). Check log: $logFile" -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Service : $ServiceName"
Write-Host "  Status  : $($svc.Status)"
Write-Host "  Server  : $ServerURL"
Write-Host "  Log     : $logFile"
Write-Host ""
Write-Host "  Commands:" -ForegroundColor Yellow
Write-Host "    Start   : Start-Service $ServiceName"
Write-Host "    Stop    : Stop-Service $ServiceName"
Write-Host "    Remove  : .\install_service.ps1 -Uninstall"
Write-Host "================================================" -ForegroundColor Green
