#Requires -Version 7.2
# Shared helpers for Get-ApimCredentials.ps1 and Invoke-ApimCredentialRotation.ps1.
# Secret-safety rules: raw ARM responses, stderr and exception messages are never persisted or printed;
# callers project an explicit allow-list of non-secret fields into their output.

Set-StrictMode -Version Latest

$script:ApiVersion = '2024-05-01'
$script:AzExe = $null
$script:AzPrefix = @()

function Initialize-AzCli {
    $cmd = Get-Command az -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { throw 'Azure CLI (az) not found in PATH.' }
    $script:AzExe = $cmd.Source
    $script:AzPrefix = @()
    # On Windows az is az.cmd: cmd.exe mangles '&', '(' and ')' in arguments (URLs with several query
    # parameters, nextLink pagination). Call the bundled Python directly to bypass cmd.exe.
    if ($cmd.Source -like '*.cmd') {
        $py = Join-Path (Split-Path $cmd.Source) '..\python.exe'
        if (Test-Path $py) {
            $script:AzExe = (Resolve-Path $py).Path
            $script:AzPrefix = @('-IBm', 'azure.cli')
        }
    }
    $env:PYTHONIOENCODING = 'utf-8'
    $env:AZURE_CORE_ONLY_SHOW_ERRORS = 'true'
    $r = Invoke-AzCli -Arguments @('account', 'show', '-o', 'json')
    if ($r.ExitCode -ne 0) { throw 'Not logged in to Azure CLI. Run: az login' }
    return ($r.Stdout | ConvertFrom-Json)
}

function Get-SanitizedAzError {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return 'UnknownError' }
    $status = $null; $code = $null
    if ($Text -match 'ERROR:\s*([A-Za-z][A-Za-z ]{2,40})\(') { $status = $Matches[1].Trim() }
    if ($Text -match '"code"\s*:\s*"([A-Za-z0-9\.\-_]{1,80})"') { $code = $Matches[1] }
    if (-not $status -and -not $code) { return 'AzCliError' }
    return (@($status, $code) | Where-Object { $_ }) -join ': '
}

function Invoke-AzCli {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $all = & $script:AzExe @script:AzPrefix @Arguments '--only-show-errors' 2>&1
    $exit = $LASTEXITCODE
    $out = ($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    $err = ($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
    [pscustomobject]@{
        ExitCode = $exit
        Stdout   = $out
        Error    = if ($exit -ne 0) { Get-SanitizedAzError $err } else { $null }
    }
}

function Get-ApimBaseUrl {
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$Name)
    "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ApiManagement/service/$Name"
}

function Add-ApiVersion {
    param([string]$Url)
    if ($Url -match '[?&]api-version=') { return $Url }
    $sep = if ($Url.Contains('?')) { '&' } else { '?' }
    "$Url${sep}api-version=$script:ApiVersion"
}

# Returns @{ Ok; Data; Error; NotFound }. Data is the parsed JSON (or $null for empty 2xx bodies such as 204).
function Invoke-Arm {
    param(
        [ValidateSet('get', 'post', 'patch', 'put', 'delete')][string]$Method = 'get',
        [Parameter(Mandatory)][string]$Url,
        [string]$BodyFile,
        [string[]]$Headers
    )
    $a = @('rest', '--method', $Method, '--url', (Add-ApiVersion $Url), '-o', 'json')
    if ($BodyFile) { $a += @('--body', "@$BodyFile") }
    if ($Headers) { $a += '--headers'; $a += $Headers }
    # Retry transient failures for reads only. Mutations are never retried: a timed-out regenerate may
    # already have rotated the key, and retrying would rotate it again.
    $attempt = 0
    while ($true) {
        $r = Invoke-AzCli -Arguments $a
        $transient = $r.ExitCode -ne 0 -and $r.Error -match 'Unprocessable Entity|ManagementApiRequestFailed|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout'
        if ($Method -ne 'get' -or -not $transient -or ++$attempt -ge 4) { break }
        Start-Sleep -Seconds ([Math]::Pow(2, $attempt) * 3)
    }
    if ($r.ExitCode -ne 0) {
        return [pscustomobject]@{ Ok = $false; Data = $null; Error = $r.Error; NotFound = ($r.Error -match 'Not Found|NotFound') }
    }
    $data = $null
    if (-not [string]::IsNullOrWhiteSpace($r.Stdout)) {
        try { $data = $r.Stdout | ConvertFrom-Json -Depth 64 }
        catch { return [pscustomobject]@{ Ok = $false; Data = $null; Error = 'NonJsonResponse'; NotFound = $false } }
    }
    [pscustomobject]@{ Ok = $true; Data = $data; Error = $null; NotFound = $false }
}

# GET a collection following nextLink. Returns @{ Ok; Items; Error; NotFound }.
function Get-ArmCollection {
    param([Parameter(Mandatory)][string]$Url)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Url
    $guard = 0
    while ($next) {
        if (++$guard -gt 500) { return [pscustomobject]@{ Ok = $false; Items = $items; Error = 'PaginationLimit'; NotFound = $false } }
        $r = Invoke-Arm -Url $next
        if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Items = $items; Error = $r.Error; NotFound = $r.NotFound } }
        if ($r.Data -and $r.Data.PSObject.Properties['value']) { foreach ($v in @($r.Data.value)) { $items.Add($v) } }
        $next = if ($r.Data -and $r.Data.PSObject.Properties['nextLink']) { $r.Data.nextLink } else { $null }
    }
    [pscustomobject]@{ Ok = $true; Items = $items; Error = $null; NotFound = $false }
}

# Creates an unpredictable temp file readable only by the current user BEFORE any content is written.
function New-PrivateTempFile {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('apimcred-' + [guid]::NewGuid().ToString('N') + '.json')
    $fs = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $fs.Dispose()
    if ($IsWindows) {
        $acl = Get-Acl -LiteralPath $path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($me, 'FullControl', 'Allow'))
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    else {
        & chmod 600 $path
    }
    return $path
}

function Remove-PrivateTempFile {
    param([string]$Path)
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        try {
            $len = (Get-Item -LiteralPath $Path).Length
            if ($len -gt 0) { [IO.File]::WriteAllBytes($Path, [byte[]]::new($len)) }
        }
        catch { }
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Get-StringSha256 {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) } finally { $sha.Dispose() }
}

# One row per inventory item stating whether it was changed. Never contains secret values.
function Get-RotationFeedback {
    param([object[]]$Items, [object[]]$Results, [object[]]$Unremediated, [bool]$Applied, [bool]$Verify)
    $done = @('rotated', 'refreshed', 'updated')
    foreach ($it in $Items) {
        $r = $Results | Where-Object { $_.instance -eq $it.instance -and $_.type -eq $it.type -and $_.id -eq $it.id } | Select-Object -First 1
        $u = $Unremediated | Where-Object { $_.instance -eq $it.instance -and $_.type -eq $it.type -and $_.id -eq $it.id } | Select-Object -First 1
        $keysChanged = @(if ($r -and $r.PSObject.Properties['keys']) { $r.keys | Where-Object status -EQ 'regenerated' | ForEach-Object key })
        $isKeyed = $it.type -in 'subscription-key', 'tenant-access', 'gateway-key'
        $changed =
            if ($it.type -eq 'policy-review') { 'No' }
            elseif (-not $Applied) { 'No (dry-run)' }
            elseif (-not $r) { 'No' }
            elseif ($r.status -eq 'partially-rotated' -or ($r.status -in $done -and $isKeyed -and $keysChanged.Count -lt 2)) { 'Partial' }
            elseif ($r.status -in $done -and $Verify -and $r.verified -ne $true) { 'Unverified' }
            elseif ($r.status -in $done) { 'Yes' }
            else { 'No' }
        $detail =
            if ($it.type -eq 'policy-review') { 'Review policy manually (possible hard-coded credential).' }
            elseif ($u) { $u.reason.TrimEnd(' ', ':') }
            elseif ($r -and $r.reason) { $r.reason }
            elseif ($r) { 'OK' }
            else { 'not processed' }
        [pscustomobject][ordered]@{
            instance    = $it.instance
            type        = $it.type
            id          = $it.id
            changed     = $changed
            status      = if ($r) { $r.status } elseif ($it.action -eq 'manual' -or $it.type -eq 'policy-review') { 'manual' } else { 'not-selected' }
            keysChanged = $keysChanged -join '+'
            verified    = if ($r -and $null -ne $r.verified) { [bool]$r.verified } else { $null }
            detail      = $detail
        }
    }
}

Export-ModuleMember -Function Initialize-AzCli, Invoke-AzCli, Invoke-Arm, Get-ArmCollection, Get-ApimBaseUrl,
    Add-ApiVersion, New-PrivateTempFile, Remove-PrivateTempFile, Get-StringSha256, Get-RotationFeedback -Variable ApiVersion
