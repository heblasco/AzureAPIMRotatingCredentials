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
# Key Vault is read through the ARM control plane only (metadata, never values), so it works with
# vaults whose data plane is private. It needs its own API version.
$script:KeyVaultApiVersion = '2024-11-01'
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

# ---------------------------------------------------------------- Key Vault (ARM control plane, metadata only)

# Splits https://<vault>.vault.azure.net/<secrets|keys|certificates>/<name>[/<version>].
function ConvertFrom-KeyVaultUri {
    param([string]$Uri)
    $u = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$u)) { return $null }
    $seg = @($u.AbsolutePath.Trim('/') -split '/' | Where-Object { $_ })
    if ($seg.Count -lt 2 -or $seg[0] -notin 'secrets', 'keys', 'certificates') { return $null }
    [pscustomobject][ordered]@{
        vaultName  = ($u.Host -split '\.')[0].ToLowerInvariant()
        objectType = $seg[0]
        name       = $seg[1]
        version    = if ($seg.Count -ge 3) { $seg[2] } else { $null }
    }
}

function ConvertFrom-UnixTime {
    param($Seconds)
    if ($null -eq $Seconds -or "$Seconds" -notmatch '^\d+$') { return $null }
    [DateTimeOffset]::FromUnixTimeSeconds([long]$Seconds).UtcDateTime
}

# ConvertFrom-Json may already return [datetime] (Utc/Unspecified for 'Z' strings) or a string.
function ConvertTo-UtcDateTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq 'Local') { $Value.ToUniversalTime() } else { [datetime]::SpecifyKind($Value, 'Utc') }) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $d = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d.UtcDateTime }
    return $null
}

# Accepts only timestamps with an explicit offset or 'Z' so the cutoff is never interpreted in local time.
function ConvertTo-CutoffUtc {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -notmatch '(Z|[+-]\d{2}:?\d{2})$') { throw "-CompromisedSince must include a UTC offset, e.g. 2026-11-20T00:00:00Z (got '$Value')." }
    $d = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { throw "Invalid -CompromisedSince '$Value'." }
    if ($d -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { throw '-CompromisedSince is in the future.' }
    $d.UtcDateTime
}

# vaultName (lower case) -> ARM resource ID, for every vault visible in the given subscriptions.
function Get-KeyVaultIndex {
    param([string[]]$SubscriptionIds)
    $subs = @($SubscriptionIds | Where-Object { $_ } | Sort-Object -Unique)
    $res = Get-ArmCollections -Urls @($subs | ForEach-Object { "https://management.azure.com/subscriptions/$_/providers/Microsoft.KeyVault/vaults?api-version=$script:KeyVaultApiVersion" })
    $index = @{}; $errors = @()
    for ($i = 0; $i -lt $subs.Count; $i++) {
        if (-not $res[$i].Ok) { $errors += [pscustomobject]@{ subscriptionId = $subs[$i]; error = $res[$i].Error }; continue }
        foreach ($v in $res[$i].Items) { $index[$v.name.ToLowerInvariant()] = $v.id }
    }
    [pscustomobject]@{ Index = $index; Errors = $errors }
}

# Projects an ARM secret/key resource to non-secret metadata. ARM never returns values.
function ConvertTo-KeyVaultObjectMeta {
    param($Resource, [ValidateSet('secrets', 'keys')][string]$ObjectType)
    $p = $Resource.properties
    $uriWithVersion = if ($ObjectType -eq 'secrets') { $p.PSObject.Properties['secretUriWithVersion']?.Value } else { $p.PSObject.Properties['keyUriWithVersion']?.Value }
    $a = $p.PSObject.Properties['attributes']?.Value
    [pscustomobject][ordered]@{
        name                    = $Resource.name
        objectType              = $ObjectType
        latestVersion           = if ($uriWithVersion) { ($uriWithVersion -split '/')[-1] } else { $null }
        latestVersionCreatedUtc = ConvertFrom-UnixTime (${a}?.PSObject.Properties['created']?.Value)
        updatedUtc              = ConvertFrom-UnixTime (${a}?.PSObject.Properties['updated']?.Value)
        expiresUtc              = ConvertFrom-UnixTime (${a}?.PSObject.Properties['exp']?.Value)
        enabled                 = ${a}?.PSObject.Properties['enabled']?.Value
        contentType             = $p.PSObject.Properties['contentType']?.Value
        keyType                 = $p.PSObject.Properties['kty']?.Value
    }
}

# Lists secrets or keys of a vault. Returns @{ Ok; Items (metadata); Error }.
function Get-KeyVaultObjects {
    param([string]$VaultResourceId, [ValidateSet('secrets', 'keys')][string]$ObjectType)
    $r = Get-ArmCollection -Url "https://management.azure.com$VaultResourceId/$ObjectType`?api-version=$script:KeyVaultApiVersion"
    [pscustomobject]@{ Ok = $r.Ok; Error = $r.Error; Items = @($r.Items | ForEach-Object { ConvertTo-KeyVaultObjectMeta $_ $ObjectType }) }
}

# Current (latest) version metadata of one secret. Returns $null with -ErrorText when unavailable.
function Get-KeyVaultSecretMeta {
    param([string]$VaultResourceId, [string]$Name)
    $r = Invoke-Arm -Url "https://management.azure.com$VaultResourceId/secrets/$Name`?api-version=$script:KeyVaultApiVersion"
    if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; NotFound = $r.NotFound; Error = $r.Error; Meta = $null } }
    [pscustomobject]@{ Ok = $true; NotFound = $false; Error = $null; Meta = (ConvertTo-KeyVaultObjectMeta $r.Data 'secrets') }
}

# Assessment of a Key Vault reference against the latest version and the optional compromise cutoff.
# Values: secret-not-found | metadata-unavailable | pinned-to-older-version | not-rotated-in-key-vault |
#         new-version-available | rotation-required (no cutoff given) | unknown
function Get-KeyVaultAssessment {
    param($Ref, $MetaResult, [Nullable[datetime]]$CutoffUtc)
    if (-not $MetaResult) { return 'metadata-unavailable' }
    if (-not $MetaResult.Ok) { return $(if ($MetaResult.NotFound) { 'secret-not-found' } else { 'metadata-unavailable' }) }
    $m = $MetaResult.Meta
    if ($Ref.version -and $m.latestVersion -and $Ref.version -ne $m.latestVersion) { return 'pinned-to-older-version' }
    if (-not $CutoffUtc) { return 'rotation-required' }
    if (-not $m.latestVersionCreatedUtc -or $m.latestVersionCreatedUtc -gt [datetime]::UtcNow.AddMinutes(5)) { return 'unknown' }
    if ($m.latestVersionCreatedUtc -gt $CutoffUtc) { return 'new-version-available' }
    return 'not-rotated-in-key-vault'
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
            elseif ($r.status -in $done -and ($r.verified -eq $false -or ($Verify -and $r.verified -ne $true))) { 'Unverified' }
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
    Add-ApiVersion, Invoke-ArmParallel, Get-ArmCollections, Get-StringSha256, Get-RotationFeedback,
    ConvertFrom-KeyVaultUri, ConvertFrom-UnixTime, ConvertTo-UtcDateTime, ConvertTo-CutoffUtc, Get-KeyVaultIndex, Get-KeyVaultObjects,
    Get-KeyVaultSecretMeta, Get-KeyVaultAssessment -Variable ApiVersion, KeyVaultApiVersion
