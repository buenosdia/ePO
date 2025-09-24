[CmdletBinding()] param(
  [Parameter(Mandatory)] [string]$AgentName,
  [Parameter(Mandatory)] [string]$ServiceUser,
  [Parameter(Mandatory)] [securestring]$ServicePassword,
  [string]$InstallPath = 'C:\ProgramData\EPO-Agent',
  [string]$ScriptPath = (Join-Path $PSScriptRoot 'EpoAgent.ps1')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InstallPath)) {
  New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}
Copy-Item -Path $ScriptPath -Destination (Join-Path $InstallPath 'EpoAgent.ps1') -Force

$principal = New-ScheduledTaskPrincipal -UserId $ServiceUser -LogonType Password -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument "-NoLogo -NoProfile -File `"$InstallPath\EpoAgent.ps1`""
$settings = New-ScheduledTaskSettingsSet -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3 -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew

try {
  Unregister-ScheduledTask -TaskName $AgentName -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $AgentName -Action $action -Principal $principal -Settings $settings -Description 'Enterprise PowerShell Orchestrator Agent' -Password $ServicePassword
  Write-Host "Registered scheduled task '$AgentName'. Ensure config.json and private key exist at $InstallPath."
} catch {
  throw "Failed to register scheduled task: $_"
}
