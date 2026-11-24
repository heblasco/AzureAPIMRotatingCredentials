#Requires -Version 7.2
# Shared helpers for Get-ApimCredentials.ps1 and Invoke-ApimCredentialRotation.ps1.
# Secret-safety rules: raw ARM responses, stderr, tokens and exception messages are never persisted or
# printed; callers project an explicit allow-list of non-secret fields into their output.
#
# Performance: Azure CLI is used only to read the signed-in account and obtain an ARM access token.
# All ARM calls go through one reused HttpClient (connection pooling, ~100-300 ms per call instead of
# ~3-5 s per 'az rest' process), and read-only GETs can be issued concurrently (Invoke-ArmParallel).

Set-StrictMode -Version Latest

$script:ApiVersion = '2024-05-01'
$script:ArmResource = 'https://management.azure.com/'
$script:Token = $null
$script:TokenExpiresUtc = [datetime]::MinValue
$script:Http = $null
$script:TransientStatus = @(408, 422, 429, 500, 502, 503, 504)

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
    $all = & az @Arguments '--only-show-errors' 2>&1
    $exit = $LASTEXITCODE
    $out = ($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    $err = ($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
    [pscustomobject]@{
        ExitCode = $exit
        Stdout   = $out
        Error    = if ($exit -ne 0) { Get-SanitizedAzError $err } else { $null }
    }
}

# Obtains (or refreshes, 5 minutes before expiry) the ARM token from the Azure CLI login. Never output.
function Get-ArmToken {
    if ($script:Token -and (Get-Date).ToUniversalTime() -lt $script:TokenExpiresUtc.AddMinutes(-5)) { return $script:Token }
    $r = Invoke-AzCli -Arguments @('account', 'get-access-token', '--resource', $script:ArmResource, '-o', 'json')
    if ($r.ExitCode -ne 0) { throw "Could not obtain an ARM access token from Azure CLI ($($r.Error)). Run: az login" }
    $t = $r.Stdout | ConvertFrom-Json
    $script:Token = $t.accessToken
    $script:TokenExpiresUtc = if ($t.PSObject.Properties['expires_on'] -and $t.expires_on) {
        [DateTimeOffset]::FromUnixTimeSeconds([long]$t.expires_on).UtcDateTime
    }
    else { ([datetime]$t.expiresOn).ToUniversalTime() }
    return $script:Token
}

function Initialize-AzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) not found in PATH.' }
    $env:AZURE_CORE_ONLY_SHOW_ERRORS = 'true'
    $r = Invoke-AzCli -Arguments @('account', 'show', '-o', 'json')
    if ($r.ExitCode -ne 0) { throw 'Not logged in to Azure CLI. Run: az login' }
    if (-not $script:Http) {
        $handler = [System.Net.Http.SocketsHttpHandler]::new()
        $handler.MaxConnectionsPerServer = 32
        $handler.PooledConnectionLifetime = [TimeSpan]::FromMinutes(5)
        $script:Http = [System.Net.Http.HttpClient]::new($handler)
        $script:Http.Timeout = [TimeSpan]::FromSeconds(120)
    }
    [void](Get-ArmToken)
    return ($r.Stdout | ConvertFrom-Json)
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

function New-ArmRequest {
    param([string]$Method, [string]$Url, $Body, [string[]]$Headers)
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant()), (Add-ApiVersion $Url))
    $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', (Get-ArmToken))
    foreach ($h in @($Headers | Where-Object { $_ })) {
        $k, $v = $h -split '=', 2
        [void]$req.Headers.TryAddWithoutValidation($k.Trim(), $v)
    }
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
        $req.Content = [System.Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
    }
    elseif ($Method -ne 'get') {
        $req.Content = [System.Net.Http.StringContent]::new('', [Text.Encoding]::UTF8, 'application/json')
    }
    return $req
}

# Turns an HttpResponseMessage (or a failed task) into @{ Ok; Data; Error; NotFound; StatusCode; Transient; RetryAfter; Headers }.
# Error is "<Reason>: <ARM error code>" only; response bodies are never surfaced.
function ConvertFrom-ArmResponse {
    param([System.Threading.Tasks.Task]$Task)
    $resp = $null
    try { $resp = $Task.GetAwaiter().GetResult() }
    catch {
        return [pscustomobject]@{ Ok = $false; Data = $null; Error = 'NetworkError'; NotFound = $false; StatusCode = 0; Transient = $true; RetryAfter = $null; Headers = @{} }
    }
    try {
        $code = [int]$resp.StatusCode
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($text) { $text = $text.TrimStart([char]0xFEFF) }
        $hdr = @{}
        foreach ($n in 'Location', 'Azure-AsyncOperation', 'Retry-After', 'ETag') {
            $vals = $null
            if ($resp.Headers.TryGetValues($n, [ref]$vals)) { $hdr[$n] = @($vals)[0] }
        }
        $retryAfter = if ($hdr['Retry-After'] -match '^\d+$') { [int]$hdr['Retry-After'] } else { $null }
        if ($resp.IsSuccessStatusCode) {
            $data = $null
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                try { $data = $text | ConvertFrom-Json -Depth 64 }
                catch { return [pscustomobject]@{ Ok = $false; Data = $null; Error = 'NonJsonResponse'; NotFound = $false; StatusCode = $code; Transient = $false; RetryAfter = $null; Headers = $hdr } }
            }
            return [pscustomobject]@{ Ok = $true; Data = $data; Error = $null; NotFound = $false; StatusCode = $code; Transient = $false; RetryAfter = $null; Headers = $hdr }
        }
        $reason = if ($resp.ReasonPhrase) { $resp.ReasonPhrase } else { [string]$resp.StatusCode }
        $armCode = $null
        if ($text -match '"code"\s*:\s*"([A-Za-z0-9\.\-_]{1,80})"') { $armCode = $Matches[1] }
        [pscustomobject]@{
            Ok = $false; Data = $null; Error = (@($reason, $armCode) | Where-Object { $_ }) -join ': '
            NotFound = ($code -eq 404); StatusCode = $code; Transient = ($code -in $script:TransientStatus); RetryAfter = $retryAfter; Headers = $hdr
        }
    }
    finally { $resp.Dispose() }
}

# Single ARM call. Transient failures are retried for GET only: a timed-out regenerate may already have
# rotated the key, and retrying a mutation would rotate it again.
function Invoke-Arm {
    param(
        [ValidateSet('get', 'post', 'patch', 'put', 'delete')][string]$Method = 'get',
        [Parameter(Mandatory)][string]$Url,
        $Body,
        [string[]]$Headers
    )
    $attempt = 0
    while ($true) {
        $req = New-ArmRequest -Method $Method -Url $Url -Body $Body -Headers $Headers
        try { $r = ConvertFrom-ArmResponse $script:Http.SendAsync($req) } finally { $req.Dispose() }
        if ($Method -ne 'get' -or -not $r.Transient -or ++$attempt -ge 5) { return $r }
        Start-Sleep -Seconds $(if ($r.RetryAfter) { [Math]::Min($r.RetryAfter, 60) } else { [Math]::Pow(2, $attempt) * 2 })
    }
}

# Concurrent read-only GETs (at most -ThrottleLimit in flight). Results keep the order of -Urls.
# Transient failures are retried sequentially through Invoke-Arm.
function Invoke-ArmParallel {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Urls, [int]$ThrottleLimit = 16)
    $results = [object[]]::new($Urls.Count)
    for ($i = 0; $i -lt $Urls.Count; $i += $ThrottleLimit) {
        $last = [Math]::Min($i + $ThrottleLimit, $Urls.Count) - 1
        $batch = foreach ($j in $i..$last) {
            $req = New-ArmRequest -Method 'get' -Url $Urls[$j]
            [pscustomobject]@{ Index = $j; Request = $req; Task = $script:Http.SendAsync($req) }
        }
        foreach ($b in @($batch)) {
            try { $results[$b.Index] = ConvertFrom-ArmResponse $b.Task } finally { $b.Request.Dispose() }
        }
    }
    for ($j = 0; $j -lt $results.Count; $j++) {
        if (-not $results[$j].Ok -and $results[$j].Transient) { $results[$j] = Invoke-Arm -Url $Urls[$j] }
    }
    return , $results
}

# GET several collections concurrently, following nextLink. Returns one @{ Ok; Items; Error; NotFound } per URL.
function Get-ArmCollections {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Urls, [int]$ThrottleLimit = 16)
    $first = Invoke-ArmParallel -Urls $Urls -ThrottleLimit $ThrottleLimit
    $out = [object[]]::new($Urls.Count)
    for ($j = 0; $j -lt $Urls.Count; $j++) {
        $items = [System.Collections.Generic.List[object]]::new()
        $r = $first[$j]; $guard = 0
        while ($true) {
            if (-not $r.Ok) { $out[$j] = [pscustomobject]@{ Ok = $false; Items = $items; Error = $r.Error; NotFound = $r.NotFound }; break }
            if ($r.Data -and $r.Data.PSObject.Properties['value']) { foreach ($v in @($r.Data.value)) { $items.Add($v) } }
            $next = if ($r.Data -and $r.Data.PSObject.Properties['nextLink']) { $r.Data.nextLink } else { $null }
            if (-not $next) { $out[$j] = [pscustomobject]@{ Ok = $true; Items = $items; Error = $null; NotFound = $false }; break }
            if (++$guard -gt 500) { $out[$j] = [pscustomobject]@{ Ok = $false; Items = $items; Error = 'PaginationLimit'; NotFound = $false }; break }
            $r = Invoke-Arm -Url $next
        }
    }
    return , $out
}

function Get-ArmCollection {
    param([Parameter(Mandatory)][string]$Url)
    (Get-ArmCollections -Urls @($Url))[0]
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
    Add-ApiVersion, Invoke-ArmParallel, Get-ArmCollections, Get-StringSha256, Get-RotationFeedback -Variable ApiVersion
