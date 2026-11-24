#Requires -Version 7.2
<#
.SYNOPSIS
    Rotates the auto-rotatable credentials listed by Get-ApimCredentials.ps1 (Azure CLI only).

.DESCRIPTION
    DRY-RUN by default: nothing changes unless -Apply is given (and confirmed, or -Force).

    Auto-rotated types:
      subscription-key    POST subscriptions/{sid}/regeneratePrimaryKey|regenerateSecondaryKey
      tenant-access       POST tenant/access/regeneratePrimaryKey|regenerateSecondaryKey
      gateway-key         POST gateways/{id}/regenerateKey  {"keyType":"primary|secondary"}
      named-value-kv      POST namedValues/{id}/refreshSecret (rotate the secret in Key Vault FIRST)
      named-value-secret  PATCH namedValues/{id} with a NEW value you supply (env var APIM_NV_<ID> or prompt)

    Manual types (backends, OAuth/OIDC/IdP, credential manager, loggers, caches, certificates, policies,
    plain named values) are never modified; they are reported as unremediated with next steps.

    Modes:
      default     Regenerates only -Key (Secondary) and skips the built-in 'master' subscription.
                  Use for planned rotation: move callers to the other key, rotate, switch, rotate the other.
      -Incident   Regenerates BOTH keys and includes 'master'. Every caller using the old keys breaks
                  immediately. Use when keys are (or may be) compromised.

    Secret safety: secret values are never printed or written. New named-value values are sent to ARM
    directly from memory over TLS (no temp files). Azure CLI is used only for sign-in and to obtain an
    ARM access token, which is never output.
    -Verify reads secrets (listSecrets/listKeys/listValue) only to compare in-memory SHA-256 hashes;
    only booleans are reported.

.EXAMPLE
    ./Invoke-ApimCredentialRotation.ps1 -InventoryFile apim-credentials-inventory.json              # dry-run
.EXAMPLE
    ./Invoke-ApimCredentialRotation.ps1 -InventoryFile inv.json -Incident -Apply -Verify             # incident
.EXAMPLE
    ./Invoke-ApimCredentialRotation.ps1 -InventoryFile inv.json -Types subscription-key -Key Primary -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InventoryFile,
    [ValidateSet('subscription-key', 'tenant-access', 'gateway-key', 'named-value-kv', 'named-value-secret')]
    [string[]]$Types = @('subscription-key', 'tenant-access', 'gateway-key', 'named-value-kv', 'named-value-secret'),
    [string]$Instance,
    [string[]]$Id,
    [ValidateSet('Primary', 'Secondary', 'Both')][string]$Key = 'Secondary',
    [switch]$IncludeMaster,
    [switch]$Incident,
    [switch]$AllowPinnedRefresh,
    [switch]$NonInteractive,
    [switch]$Apply,
    [switch]$Force,
    [switch]$Verify,
    [string]$ReportFile = ("apim-rotation-report-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss')),
    # CSV with one row per item: changed = Yes | Partial | Unverified | No | No (dry-run). Defaults next to -ReportFile.
    [string]$FeedbackFile
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ApimCredentials.Common.psm1') -Force

if ($Incident) {
    if ($PSBoundParameters.ContainsKey('Key') -and $Key -ne 'Both') { Write-Warning "-Incident overrides -Key $Key with Both." }
    $Key = 'Both'; $IncludeMaster = $true
}
$keysToRotate = if ($Key -eq 'Both') { @('primary', 'secondary') } else { @($Key.ToLower()) }

$inventory = Get-Content -LiteralPath $InventoryFile -Raw | ConvertFrom-Json -Depth 32
if (-not $inventory.summary.coverageComplete) {
    Write-Warning 'The inventory has INCOMPLETE coverage: some collections could not be enumerated. Re-run discovery before declaring the incident remediated.'
}

$account = Initialize-AzCli

$allItems = @($inventory.items)
$selected = @($allItems | Where-Object {
        $_.action -eq 'auto' -and $_.type -in $Types -and
        (-not $Instance -or $_.instance -eq $Instance) -and
        (-not $Id -or $_.id -in $Id)
    })

function Get-Prop {
    param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($p in $Path -split '\.') {
        if ($null -eq $cur) { return $null }
        $prop = $cur.PSObject.Properties[$p]
        if (-not $prop) { return $null }
        $cur = $prop.Value
    }
    $cur
}

function Get-KeyHashes {
    # Reads current keys and returns ONLY their SHA-256 hashes (kept in memory, never output).
    param([string]$Type, [string]$Base, [string]$ItemId)
    switch ($Type) {
        'subscription-key' { $r = Invoke-Arm -Method post -Url "$Base/subscriptions/$ItemId/listSecrets"; $p = 'primaryKey'; $s = 'secondaryKey' }
        'tenant-access' { $r = Invoke-Arm -Method post -Url "$Base/tenant/access/listSecrets"; $p = 'primaryKey'; $s = 'secondaryKey' }
        'gateway-key' { $r = Invoke-Arm -Method post -Url "$Base/gateways/$ItemId/listKeys"; $p = 'primary'; $s = 'secondary' }
        'named-value-secret' { $r = Invoke-Arm -Method post -Url "$Base/namedValues/$ItemId/listValue"; $p = 'value'; $s = $null }
    }
    if (-not $r.Ok -or -not $r.Data) { return $null }
    $h = @{ primary = Get-StringSha256 ([string](Get-Prop $r.Data $p)) }
    if ($s) { $h.secondary = Get-StringSha256 ([string](Get-Prop $r.Data $s)) }
    $r = $null
    return $h
}

function Get-NewSecretValue {
    param([string]$NamedValueId)
    $var = 'APIM_NV_' + ([regex]::Replace($NamedValueId.ToUpperInvariant(), '[^A-Z0-9]', '_'))
    $v = [Environment]::GetEnvironmentVariable($var)
    if ($v) { return $v }
    if ($NonInteractive) { return $null }
    $sec = Read-Host -AsSecureString "New value for named value '$NamedValueId' (empty = skip)"
    $plain = [Net.NetworkCredential]::new('', $sec).Password
    $sec.Dispose()
    return $plain
}

function Wait-NamedValue {
    # PATCH/refresh may return 202: poll until provisioning completes.
    param([string]$Url, [scriptblock]$Done, [int]$TimeoutSec = 180)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        $g = Invoke-Arm -Url $Url
        if ($g.Ok -and (& $Done $g.Data)) { return $g.Data }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    return $null
}

# Follows an ARM 202 (Azure-AsyncOperation or Location header). $true = completed, $false = failed or
# timed out, $null = no async header to follow (caller falls back to other evidence).
function Wait-ArmAsync {
    param($Response, [int]$TimeoutSec = 180)
    if ($Response.StatusCode -ne 202) { return $true }
    $op = $Response.Headers['Azure-AsyncOperation']; $loc = $Response.Headers['Location']
    if (-not $op -and -not $loc) { return $null }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        Start-Sleep -Seconds $(if ($Response.RetryAfter) { [Math]::Min($Response.RetryAfter, 30) } else { 5 })
        if ($op) {
            $g = Invoke-Arm -Url $op
            $st = if ($g.Ok) { Get-Prop $g.Data 'status' } else { $null }
            if ($st -eq 'Succeeded') { return $true }
            if ($st -in 'Failed', 'Canceled' -or (-not $g.Ok -and -not $g.Transient)) { return $false }
        }
        else {
            $g = Invoke-Arm -Url $loc
            if ($g.Ok -and $g.StatusCode -ne 202) { return $true }
            if (-not $g.Ok -and -not $g.Transient) { return $false }
        }
    } while ((Get-Date) -lt $deadline)
    return $false
}

$mode = if ($Incident) { 'incident' } else { 'planned' }
Write-Host ("Mode: {0} | keys: {1} | master: {2} | {3}" -f $mode, ($keysToRotate -join '+'), [bool]$IncludeMaster, $(if ($Apply) { 'APPLY' } else { 'DRY-RUN (use -Apply to change anything)' })) -ForegroundColor Yellow
if ($Apply -and $keysToRotate.Count -eq 2) {
    Write-Warning 'Both keys will be regenerated: every client using the current subscription / gateway / management keys will fail until it receives the new key.'
}
if ($Apply -and -not $Force) {
    $msg = "Rotate $($selected.Count) credential object(s) in $(@($selected.instance | Sort-Object -Unique) -join ', ')?"
    if (-not $PSCmdlet.ShouldContinue($msg, 'Confirm APIM credential rotation')) { Write-Host 'Cancelled.'; exit 2 }
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($it in $selected) {
    $base = Get-ApimBaseUrl $it.subscriptionId $it.resourceGroup $it.instance
    $res = [ordered]@{ instance = $it.instance; type = $it.type; id = $it.id; status = $null; reason = $null; keys = @(); verified = $null; issuerRevocationRequired = $false }
    Write-Host "[$($it.instance)] $($it.type) '$($it.id)'"

    if ($it.type -eq 'subscription-key' -and $it.id -eq 'master' -and -not $IncludeMaster) {
        $res.status = 'skipped'; $res.reason = 'built-in master subscription (use -IncludeMaster or -Incident)'
        Write-Host "   skipped: $($res.reason)" -ForegroundColor DarkYellow; $results.Add([pscustomobject]$res); continue
    }

    switch ($it.type) {
        { $_ -in 'subscription-key', 'tenant-access', 'gateway-key' } {
            $before = if ($Apply -and $Verify) { Get-KeyHashes $it.type $base $it.id } else { $null }
            $keyResults = @()
            foreach ($k in $keysToRotate) {
                if (-not $Apply) { $keyResults += [ordered]@{ key = $k; status = 'would-regenerate' }; continue }
                $kTitle = (Get-Culture).TextInfo.ToTitleCase($k)
                try {
                    switch ($it.type) {
                        'subscription-key' { $r = Invoke-Arm -Method post -Url "$base/subscriptions/$($it.id)/regenerate${kTitle}Key" }
                        'tenant-access' { $r = Invoke-Arm -Method post -Url "$base/tenant/access/regenerate${kTitle}Key" }
                        'gateway-key' { $r = Invoke-Arm -Method post -Url "$base/gateways/$($it.id)/regenerateKey" -Body @{ keyType = $k } }
                    }
                }
                catch { $r = [pscustomobject]@{ Ok = $false; Error = 'RequestError' } }
                $keyResults += [ordered]@{ key = $k; status = $(if ($r.Ok) { 'regenerated' } else { 'failed' }); error = $r.Error }
                Write-Host ("   {0}: {1}" -f $k, $(if ($r.Ok) { 'regenerated' } else { "FAILED ($($r.Error))" })) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
            }
            if ($Apply -and $Verify) {
                $after = Get-KeyHashes $it.type $base $it.id
                if ($before -and $after) {
                    $ok = $true
                    foreach ($kr in $keyResults) {
                        $changed = $before[$kr.key] -ne $after[$kr.key] -and $after[$kr.key]
                        $kr.verified = [bool]($(if ($kr.status -eq 'regenerated') { $changed } else { -not $changed }))
                        if (-not $kr.verified) { $ok = $false }
                    }
                    foreach ($other in @('primary', 'secondary') | Where-Object { $_ -notin $keysToRotate }) {
                        if ($before[$other] -ne $after[$other]) { $ok = $false }
                    }
                    $res.verified = $ok
                    Write-Host ("   verify: {0}" -f $(if ($ok) { 'selected keys changed, others untouched' } else { 'MISMATCH' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
                }
                else { $res.verified = $false; $res.reason = 'verification could not read keys (needs listSecrets/listKeys permission)' }
            }
            $res.keys = $keyResults
            $res.status = if (-not $Apply) { 'would-rotate' }
            elseif (@($keyResults | Where-Object status -EQ 'failed').Count -eq 0) { 'rotated' }
            elseif (@($keyResults | Where-Object status -EQ 'regenerated').Count -gt 0) { 'partially-rotated' }
            else { 'failed' }
            if ($it.type -eq 'gateway-key' -and $Apply) { $res.reason = 'Generate a new gateway token from the new key and redeploy the self-hosted gateway.' }
        }

        'named-value-kv' {
            $res.issuerRevocationRequired = $true
            $nvUrl = "$base/namedValues/$($it.id)"
            $cur = Invoke-Arm -Url $nvUrl
            if (-not $cur.Ok) { $res.status = 'failed'; $res.reason = $cur.Error; break }
            $kvId = Get-Prop $cur.Data 'properties.keyVault.secretIdentifier'
            $pinned = $kvId -match '/secrets/[^/]+/[0-9a-fA-F]{32}/?$'
            if ($pinned -and -not $AllowPinnedRefresh) {
                $res.status = 'skipped'; $res.reason = 'version-pinned Key Vault reference: point it to the new secret version (or use -AllowPinnedRefresh if already updated)'
                Write-Host "   skipped: $($res.reason)" -ForegroundColor DarkYellow; break
            }
            if (-not $Apply) { $res.status = 'would-refresh'; Write-Host '   would refresh from Key Vault (rotate the secret in Key Vault first)'; break }
            $prevTs = Get-Prop $cur.Data 'properties.keyVault.lastStatus.timeStampUtc'
            $r = Invoke-Arm -Method post -Url "$nvUrl/refreshSecret"
            if (-not $r.Ok) { $res.status = 'failed'; $res.reason = $r.Error; Write-Host "   FAILED ($($r.Error))" -ForegroundColor Red; break }
            $final = Wait-NamedValue -Url $nvUrl -Done { param($d) (Get-Prop $d 'properties.keyVault.lastStatus.timeStampUtc') -ne $prevTs }
            $code = Get-Prop $final 'properties.keyVault.lastStatus.code'
            $res.status = if ($final -and $code -eq 'Success') { 'refreshed' } else { 'failed' }
            $res.verified = ($res.status -eq 'refreshed')
            $res.reason = if ($res.status -eq 'refreshed') { 'Refreshed from Key Vault. This only reloads the current Key Vault value: confirm it is a NEW secret and revoke the old one at its issuer.' } else { "refresh did not complete (lastStatus: $code)" }
            Write-Host "   $($res.status)" -ForegroundColor $(if ($res.status -eq 'refreshed') { 'Green' } else { 'Red' })
        }

        'named-value-secret' {
            $res.issuerRevocationRequired = $true
            $nvUrl = "$base/namedValues/$($it.id)"
            $cur = Invoke-Arm -Url $nvUrl
            if (-not $cur.Ok) { $res.status = 'failed'; $res.reason = $cur.Error; break }
            if (-not (Get-Prop $cur.Data 'properties.secret') -or (Get-Prop $cur.Data 'properties.keyVault.secretIdentifier')) {
                $res.status = 'skipped'; $res.reason = 'named value classification changed since discovery; re-run discovery'; break
            }
            if (-not $Apply) { $res.status = 'would-update'; Write-Host '   would replace stored value (new value from APIM_NV_<ID> env var or prompt)'; break }
            $before = if ($Verify) { Get-KeyHashes 'named-value-secret' $base $it.id } else { $null }
            $new = Get-NewSecretValue $it.id
            if ([string]::IsNullOrEmpty($new)) { $res.status = 'skipped'; $res.reason = 'no new value supplied'; Write-Host "   skipped: $($res.reason)" -ForegroundColor DarkYellow; break }
            # The body exists only in memory and is sent straight to ARM over TLS; nothing touches disk.
            try { $r = Invoke-Arm -Method patch -Url $nvUrl -Body @{ properties = @{ value = $new; secret = $true } } -Headers @('If-Match=*') }
            catch { $r = [pscustomobject]@{ Ok = $false; Error = 'RequestError' } }
            finally { $new = $null }
            if (-not $r.Ok) { $res.status = 'failed'; $res.reason = $r.Error; Write-Host "   FAILED ($($r.Error))" -ForegroundColor Red; break }
            # With -Verify, poll until the stored value hash changes (strong evidence). Otherwise follow the
            # ARM async-operation header of a 202, falling back to provisioningState.
            if ($Verify) {
                if (-not $before) {
                    $res.status = 'updated'; $res.verified = $false
                    $res.reason = 'Update accepted but verification baseline could not be read (needs namedValues/listValue permission).'
                }
                else {
                    $deadline = (Get-Date).AddSeconds(180); $changed = $false
                    do {
                        $after = Get-KeyHashes 'named-value-secret' $base $it.id
                        if ($after -and $after.primary -and $after.primary -ne $before.primary) { $changed = $true; break }
                        Start-Sleep -Seconds 5
                    } while ((Get-Date) -lt $deadline)
                    $res.status = if ($changed) { 'updated' } else { 'failed' }
                    $res.verified = $changed
                    $res.reason = if ($changed) { 'Value replaced in APIM (verified). Revoke the OLD credential at its issuer after testing.' } else { 'Stored value did not change within timeout.' }
                }
            }
            else {
                $async = Wait-ArmAsync $r
                if ($null -ne $async) {
                    $res.status = if ($async) { 'updated' } else { 'failed' }
                    $res.reason = if ($async) { 'Value replaced in APIM (operation completed). Revoke the OLD credential at its issuer after testing.' } else { 'Async update operation failed or timed out.' }
                }
                else {
                    Start-Sleep -Seconds 5
                    $final = Wait-NamedValue -Url $nvUrl -Done { param($d) $ps = Get-Prop $d 'properties.provisioningState'; -not $ps -or $ps -eq 'Succeeded' }
                    $res.status = if ($final) { 'updated' } else { 'failed' }
                    $res.reason = 'Update accepted (completion inferred from provisioningState; use -Verify for proof). Revoke the OLD credential at its issuer after testing.'
                }
            }
            Write-Host "   $($res.status)" -ForegroundColor $(if ($res.status -eq 'updated') { 'Green' } else { 'Red' })
        }
    }
    $results.Add([pscustomobject]$res)
}

# Everything not rotated (manual items, skipped, failed, not selected) stays unremediated.
$doneStatuses = @('rotated', 'refreshed', 'updated')
$unremediated = [System.Collections.Generic.List[object]]::new()
foreach ($it in $allItems) {
    $r = $results | Where-Object { $_.instance -eq $it.instance -and $_.type -eq $it.type -and $_.id -eq $it.id } | Select-Object -First 1
    $partialKeys = $r -and $r.status -eq 'rotated' -and $it.type -in 'subscription-key', 'tenant-access', 'gateway-key' -and $keysToRotate.Count -lt 2
    $unverified = $r -and $Apply -and $Verify -and $r.status -in $doneStatuses -and $r.verified -ne $true
    if ($it.type -eq 'policy-review') { continue }
    if (-not $r -or $r.status -notin $doneStatuses -or $partialKeys -or $unverified) {
        $why = if (-not $r) { if ($it.action -eq 'manual') { 'manual rotation required' } else { 'not selected' } }
        elseif ($partialKeys) { "only $($keysToRotate -join '+') key regenerated; rotate the other key after callers switch" }
        elseif ($unverified) { "$($r.status) but verification failed or was unavailable: $($r.reason)" }
        else { "$($r.status): $($r.reason)" }
        $unremediated.Add([pscustomobject][ordered]@{ instance = $it.instance; type = $it.type; id = $it.id; reason = $why; note = $it.note })
    }
}
$revocations = @($results | Where-Object { $_.issuerRevocationRequired -and $_.status -in $doneStatuses })

$report = [ordered]@{
    metadata     = [ordered]@{
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o'); tool = 'Invoke-ApimCredentialRotation.ps1'
        inventoryFile = (Resolve-Path -LiteralPath $InventoryFile).Path; inventoryGeneratedAtUtc = $inventory.metadata.generatedAtUtc
        inventoryCoverageComplete = [bool]$inventory.summary.coverageComplete
        signedInAs = $account.user.name; mode = $mode; keys = $keysToRotate; includeMaster = [bool]$IncludeMaster
        applied = [bool]$Apply; verify = [bool]$Verify; secretValuesWritten = $false
    }
    summary      = [ordered]@{
        selected                 = $selected.Count
        rotated                  = @($results | Where-Object status -In $doneStatuses).Count
        wouldRotate              = @($results | Where-Object status -Like 'would-*').Count
        skipped                  = @($results | Where-Object status -EQ 'skipped').Count
        partiallyRotated         = @($results | Where-Object status -EQ 'partially-rotated').Count
        failed                   = @($results | Where-Object status -EQ 'failed').Count
        verificationFailed       = @($results | Where-Object verified -EQ $false).Count
        unremediated             = $unremediated.Count
        issuerRevocationsPending = $revocations.Count
        remediationComplete      = [bool]($Apply -and $inventory.summary.coverageComplete -and $unremediated.Count -eq 0 -and $revocations.Count -eq 0)
    }
    results      = $results
    unremediated = $unremediated
    nextSteps    = @(
        'Distribute the new subscription keys to legitimate callers and test your APIs.'
        'Revoke the OLD credentials at each issuer (Key Vault secret versions, backends, IdP app secrets, Event Hubs/Redis keys). Updating APIM does not revoke them.'
        'Rotate the manual items listed in "unremediated" following the note on each item.'
        'Re-run Get-ApimCredentials.ps1 and review subscriptions, users, policies and backends you did not create.'
    )
}
$outPath = if ([IO.Path]::IsPathRooted($ReportFile)) { $ReportFile } else { Join-Path (Get-Location).Path $ReportFile }
[IO.File]::WriteAllText($outPath, ($report | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))

Write-Host ''
$report.summary.GetEnumerator() | ForEach-Object { '{0,-26} {1}' -f $_.Key, $_.Value } | Write-Host
Write-Host "Report written to $ReportFile (no secret values included)." -ForegroundColor Green

if (-not $FeedbackFile) { $FeedbackFile = [IO.Path]::ChangeExtension(($ReportFile -replace 'report', 'feedback'), '.csv') }
$feedback = @(Get-RotationFeedback -Items $allItems -Results $results -Unremediated $unremediated -Applied ([bool]$Apply) -Verify ([bool]$Verify))
$fbPath = if ([IO.Path]::IsPathRooted($FeedbackFile)) { $FeedbackFile } else { Join-Path (Get-Location).Path $FeedbackFile }
$feedback | Export-Csv -LiteralPath $fbPath -Encoding utf8BOM
Write-Host ''
$feedback | Format-Table instance, type, id, changed, keysChanged, verified -AutoSize | Out-String -Width 200 | Write-Host
Write-Host ("Feedback written to {0}: {1} changed, {2} not changed (no secret values included)." -f $FeedbackFile,
    @($feedback | Where-Object changed -EQ 'Yes').Count, @($feedback | Where-Object changed -NE 'Yes').Count) -ForegroundColor Green
if ($report.summary.failed -gt 0 -or $report.summary.partiallyRotated -gt 0 -or $report.summary.verificationFailed -gt 0) { exit 1 }
