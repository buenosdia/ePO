#requires -Version 7.4
param(
  [string]$ConfigPath = 'C:\ProgramData\EPO-Agent\config.json',
  [switch]$Once
)

$ErrorActionPreference = 'Stop'

function Read-AgentConfig([string]$Path) {
  if (-not (Test-Path $Path)) { throw "Config not found at $Path" }
  try {
    (Get-Content $Path -Raw | ConvertFrom-Json)
  } catch {
    throw "Invalid config JSON: $_"
  }
}

$config = Read-AgentConfig $ConfigPath

foreach ($key in 'TenantSlug','PostgrestUrl','AuthUrl','AgentId','BootstrapToken','PrivateKeyPath') {
  if (-not $config.$key) { throw "Config missing required key '$key'" }
}

$global:TokenCache = [ordered]@{ Token = $null; ExpiresAt = [DateTime]::MinValue }
$global:RsaProvider = $null
$global:Sha256 = [System.Security.Cryptography.SHA256]::Create()

function Get-JwtExpiry([string]$Token) {
  $parts = $Token.Split('.')
  if ($parts.Count -ne 3) { return (Get-Date).AddMinutes(-1) }
  $payload = $parts[1].PadRight((([math]::Ceiling($parts[1].Length / 4.0)) * 4), '=')
  $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
  $obj = $json | ConvertFrom-Json
  if (-not $obj.exp) { return (Get-Date).AddMinutes(-1) }
  return [DateTimeOffset]::FromUnixTimeSeconds([long]$obj.exp).UtcDateTime
}

function Get-AgentToken {
  $now = (Get-Date).ToUniversalTime()
  if ($TokenCache.Token -and $TokenCache.ExpiresAt -gt $now.AddSeconds(30)) {
    return $TokenCache.Token
  }
  $uri = "{0}/agents/{1}/token" -f $config.AuthUrl.TrimEnd('/'), $config.AgentId
  $headers = @{ Authorization = "Bearer $($config.BootstrapToken)" }
  $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ErrorAction Stop
  if (-not $resp.token) { throw 'Auth gateway did not return token' }
  $TokenCache.Token = $resp.token
  $TokenCache.ExpiresAt = Get-JwtExpiry $resp.token
  return $TokenCache.Token
}

function Get-AuthHeader {
  @{ Authorization = "Bearer $(Get-AgentToken)" }
}

function Invoke-EpoApi {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [object]$Body,
    [switch]$Raw
  )
  $uri = if ($Path.StartsWith('http')) { $Path } else { "{0}{1}" -f $config.PostgrestUrl.TrimEnd('/'), $Path }
  $headers = Get-AuthHeader
  $json = $null
  if ($PSBoundParameters.ContainsKey('Body')) {
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 6 }
  }
  try {
    Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json
  } catch [System.Net.WebException] {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
      $TokenCache.Token = $null
      $headers = Get-AuthHeader
      return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json
    }
    throw
  }
}

function Convert-HexToBytes([string]$Hex) {
  if (-not $Hex) { return [byte[]]@() }
  $clean = $Hex -replace '^\\x',''
  $bytes = New-Object byte[] ($clean.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [Convert]::ToByte($clean.Substring($i*2, 2), 16)
  }
  return $bytes
}

function Get-Rsa {
  if ($null -ne $RsaProvider) { return $RsaProvider }
  if (-not (Test-Path $config.PrivateKeyPath)) { throw "Agent private key not found at $($config.PrivateKeyPath)" }
  $pem = Get-Content $config.PrivateKeyPath -Raw
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($pem)
  $global:RsaProvider = $rsa
  return $rsa
}

function Decrypt-Secret([string]$HexCipher) {
  $cipherBytes = Convert-HexToBytes $HexCipher
  $rsa = Get-Rsa
  $plain = $rsa.Decrypt($cipherBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  [System.Text.Encoding]::UTF8.GetString($plain)
}

function Write-RunLog {
  param(
    [guid]$TargetId,
    [ValidateSet('stdout','stderr','progress','diagnostic')][string]$Stream,
    [string]$Message
  )
  $chunks = $Message -split "(?<=\G.{1500})"
  $seq = 0
  foreach ($chunk in $chunks) {
    Invoke-EpoApi -Method Post -Path '/rpc/sp_append_job_log' -Body @{ p_job_run_target_id = $TargetId; p_stream = $Stream; p_message = $chunk; p_seq = $seq }
    $seq++
  }
}
