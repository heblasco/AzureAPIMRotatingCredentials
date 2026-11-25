#Requires -Version 7.2
<#
.SYNOPSIS
    Read-only discovery of credential-bearing objects in Azure API Management (Azure CLI only).

.DESCRIPTION
    Based on "Rotating credentials in Azure API Management" (Microsoft Tech Community) and
    cmendible's apim-credentials.sh gist. Produces a JSON inventory used by
    Invoke-ApimCredentialRotation.ps1.

    Secret values are NEVER read: listSecrets / listValue / show-secret are not called and only an
    allow-list of non-secret fields is written. Policies are inspected in memory; only line numbers,
    element names and rule names are reported, never policy content, except the vault and object names
    of direct Key Vault calls (policy-keyvault-call).

    Policy and naming analysis is heuristic. Any collection that could not be enumerated is reported
    in "coverage" with status "failed" and the inventory is flagged as incomplete.

.EXAMPLE
    ./Get-ApimCredentials.ps1 -ResourceGroup my-rg -Name my-apim
.EXAMPLE
    ./Get-ApimCredentials.ps1 -SubscriptionId <id>            # every APIM in the subscription
.EXAMPLE
    ./Get-ApimCredentials.ps1 -AllSubscriptions -OutFile all.json
.EXAMPLE
    # Key Vault exposure: list every Key Vault-linked credential and the contents of the affected vaults
    ./Get-ApimCredentials.ps1 -ResourceGroup my-rg -Name my-apim -KeyVault my-kv -CompromisedSince 2026-11-20T00:00:00Z
#>
[CmdletBinding(DefaultParameterSetName = 'Scoped')]
param(
    [Parameter(ParameterSetName = 'Scoped')][string]$SubscriptionId,
    [Parameter(ParameterSetName = 'Scoped')][string]$ResourceGroup,
    [Parameter(ParameterSetName = 'Scoped')][string]$Name,
    [Parameter(ParameterSetName = 'All')][switch]$AllSubscriptions,
    [string]$OutFile = 'apim-credentials-inventory.json',
    [switch]$SkipOperationPolicies,
    # Key Vaults to treat as exposed, by name or ARM resource ID. Vaults referenced by APIM are always included.
    [string[]]$KeyVault,
    # Do not list the contents of the affected vaults (only the referenced secrets are checked). Coverage becomes incomplete.
    [switch]$SkipKeyVaultContents,
    # Start of the exposure window, with an explicit offset (e.g. 2026-11-20T00:00:00Z). Used only to tell
    # whether each Key Vault secret has a version created afterwards; it never clears rotationRequired.
    [string]$CompromisedSince,
    # Maximum concurrent read-only ARM requests. Lower it if you hit ARM throttling (HTTP 429).
    [ValidateRange(1, 64)][int]$ThrottleLimit = 16
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ApimCredentials.Common.psm1') -Force
$CutoffUtc = ConvertTo-CutoffUtc $CompromisedSince

$NotSupportedRx = 'Bad ?Request|Method ?Not ?Allowed|NotSupported'
$SecretNameRx = '(?i)(pass(word|wd)?|pwd|secret|token|api[-_]?key|subscription[-_]?key|ocp-apim|connection[-_ ]?string|accountkey|sharedaccess|sas|credential|private[-_]?key|client[-_]?secret|authorization|auth|bearer|signature|\bkey\b|[-_]key$)'
$PolicyKeywordRx = '(?i)(authorization|password|token|api[-_]?key|subscription-key|ocp-apim|connection.?string|secret|bearer|basic\s|accountkey|sharedaccess|sig=)'
# Value shapes that look like a literal credential, regardless of the surrounding element.
$LiteralSecretRules = [ordered]@{
    'bearer-literal'      = '(?i)\bbearer\s+(?!\{\{)(?!@)[A-Za-z0-9\-_\.~\+/=]{16,}'
    'basic-literal'       = '(?i)\bbasic\s+(?!\{\{)(?!@)[A-Za-z0-9\+/=]{12,}'
    'jwt'                 = 'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.'
    'storage-account-key' = '(?i)AccountKey=[A-Za-z0-9\+/=]{20,}'
    'sas-key'             = '(?i)SharedAccessKey=[A-Za-z0-9\+/=]{20,}'
    'sas-signature'       = '(?i)[?&]sig=[A-Za-z0-9%\+/=]{20,}'
    'instrumentation-key' = '(?i)InstrumentationKey=[0-9a-f\-]{36}'
    'long-opaque-token'   = '(?<![A-Za-z0-9\+/\-_\{@\.])[A-Za-z0-9\+/_\-]{32,}={0,2}(?![A-Za-z0-9\+/\-_\}])'
}

function Get-ValueKind {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'empty' }
    $v = $Value.Trim()
    if ($v -match '^(\{\{[^{}]+\}\}\s*)+$') { return 'named-value-ref' }
    if ($v -match '^@[\(\{]') { return 'policy-expression' }
    if ($v -match '\{\{[^{}]+\}\}') { return 'mixed-literal-and-ref' }
    return 'literal'
}

function Get-LiteralSecretRuleHits {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return @() }
    $stripped = [regex]::Replace($Value, '\{\{[^{}]+\}\}', '')
    @($LiteralSecretRules.Keys | Where-Object {
            $rx = $LiteralSecretRules[$_]
            if ($_ -eq 'long-opaque-token') {
                # Ignore GUIDs, URLs/paths, thumbprints in attributes named thumbprint, and C# expressions.
                foreach ($m in [regex]::Matches($stripped, $rx)) {
                    $t = $m.Value
                    if ($t -match '^[0-9a-fA-F\-]{36}$') { continue }
                    if ($t -match '^[a-z\-_/]+$') { continue }
                    if ($t -cmatch '[A-Z]' -and $t -cmatch '[a-z]' -and $t -match '[0-9]') { return $true }
                }
                return $false
            }
            $stripped -match $rx
        })
}

function Get-PolicyFindings {
    param([string]$Xml)
    $result = [ordered]@{ parsed = $true; findings = @(); keywordLines = @() }
    $lines = $Xml -split '\r?\n'
    $kw = for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $PolicyKeywordRx) { $i + 1 } }
    $result.keywordLines = @($kw)

    try { $doc = [Xml.Linq.XDocument]::Parse($Xml, [Xml.Linq.LoadOptions]::SetLineInfo) }
    catch { $result.parsed = $false; return $result }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($el in $doc.Descendants()) {
        $local = $el.Name.LocalName
        $line = ([Xml.IXmlLineInfo]$el).LineNumber
        $nameAttr = $el.Attribute('name')
        $nameVal = if ($nameAttr) { $nameAttr.Value } else { $null }

        # Header / query parameter / variable whose name suggests a credential.
        if ($local -in 'set-header', 'set-query-parameter', 'set-variable' -and $nameVal -and $nameVal -match $SecretNameRx) {
            $vals = if ($local -eq 'set-variable') { @($el.Attribute('value')?.Value) } else { @($el.Elements() | Where-Object { $_.Name.LocalName -eq 'value' } | ForEach-Object Value) }
            foreach ($v in $vals) {
                $kind = Get-ValueKind $v
                if ($kind -in 'literal', 'mixed-literal-and-ref') {
                    $findings.Add([ordered]@{ line = $line; element = $local; target = $nameVal; rule = 'credential-named-' + $local; valueKind = $kind; severity = 'high' })
                }
            }
        }

        # Attributes that carry credentials (authentication-basic password, send-request auth, etc.).
        foreach ($at in $el.Attributes()) {
            $an = $at.Name.LocalName
            if ($an -in 'name', 'id', 'thumbprint', 'certificate-id', 'output-token-variable-name', 'header-name', 'query-parameter-name', 'variable-name', 'client-id', 'resource', 'username') { continue }
            # cache-*-value "key" is the cache entry name, not a credential.
            $isCacheKey = $an -eq 'key' -and $local -match '^cache-(lookup|store|remove)-value$'
            if (-not $isCacheKey -and $an -match $SecretNameRx) {
                $kind = Get-ValueKind $at.Value
                if ($kind -in 'literal', 'mixed-literal-and-ref') {
                    $findings.Add([ordered]@{ line = $line; element = $local; target = $an; rule = 'credential-attribute'; valueKind = $kind; severity = 'high' })
                }
            }
            foreach ($hit in Get-LiteralSecretRuleHits $at.Value) {
                $findings.Add([ordered]@{ line = $line; element = $local; target = "@$an"; rule = $hit; valueKind = Get-ValueKind $at.Value; severity = 'high' })
            }
        }

        # Element text content (handles multi-line <value>, <set-body>, etc.).
        $text = ($el.Nodes() | Where-Object { $_ -is [Xml.Linq.XText] } | ForEach-Object Value) -join ''
        foreach ($hit in Get-LiteralSecretRuleHits $text) {
            $findings.Add([ordered]@{ line = $line; element = $local; target = 'text'; rule = $hit; valueKind = Get-ValueKind $text; severity = 'high' })
        }
    }
    $result.findings = @($findings)
    return $result
}

# Names inside {{...}} (named value references). Works on any string held in memory.
function Get-NamedValueRefs {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    @([regex]::Matches($Text, '\{\{\s*([^{}]+?)\s*\}\}') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

# certificate-id / thumbprint attributes of <authentication-certificate> in a policy (in memory only).
function Get-PolicyCertificateRefs {
    param([string]$Xml)
    if ([string]::IsNullOrEmpty($Xml)) { return @() }
    @([regex]::Matches($Xml, '<authentication-certificate\b[^>]*?\b(?:certificate-id|thumbprint)\s*=\s*"([^"{}@]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

# Direct Key Vault data-plane calls made by a policy at runtime (send-request, set-backend-service, etc.).
# {{named values}} are resolved with the known non-secret values first so URLs held in named values are found.
# Returns calls (vault/object per line, or dynamic when built at runtime), managed identity auth lines for
# Key Vault, and cache-store-value lines (cached values survive a Key Vault rotation until they expire).
$KeyVaultDnsRx = 'vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)'
function Get-PolicyKeyVaultCalls {
    param([string]$Xml, [hashtable]$NamedValueValues)
    $res = [ordered]@{ calls = @(); managedIdentityLines = @(); cacheStoreLines = @() }
    if ([string]::IsNullOrEmpty($Xml)) { return [pscustomobject]$res }
    $urlRx = "(?i)https://([a-z0-9-]{3,24})\.$KeyVaultDnsRx(?::443)?(?:/(secrets|keys|certificates)(?:/([A-Za-z0-9-]+)(?![A-Za-z0-9-]*(?:&quot;|[`"'\s])*\+))?(?:/([0-9a-fA-F]{32}))?)?"
    $calls = [System.Collections.Generic.List[object]]::new()
    $lines = $Xml -split '\r?\n'
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = [regex]::Replace($lines[$i], '\{\{\s*([^{}]+?)\s*\}\}', {
                param($m) $k = $m.Groups[1].Value.ToLowerInvariant()
                if ($NamedValueValues -and $NamedValueValues.ContainsKey($k)) { $NamedValueValues[$k] } else { $m.Value } })
        if ($l -match '(?i)<cache-store-value\b') { $res.cacheStoreLines += $i + 1 }
        if ($l -match "(?i)<authentication-managed-identity\b[^>]*\bresource\s*=\s*[`"']https://$KeyVaultDnsRx") { $res.managedIdentityLines += $i + 1; continue }
        $found = [regex]::Matches($l, $urlRx)
        foreach ($m in $found) {
            $calls.Add([pscustomobject][ordered]@{
                    line = $i + 1; vaultName = $m.Groups[1].Value.ToLowerInvariant()
                    objectType = $(if ($m.Groups[2].Success) { $m.Groups[2].Value.ToLowerInvariant() } else { $null })
                    objectName = $(if ($m.Groups[3].Success) { $m.Groups[3].Value } else { $null })
                    version = $(if ($m.Groups[4].Success) { $m.Groups[4].Value.ToLowerInvariant() } else { $null })
                    dynamic = -not $m.Groups[3].Success
                })
        }
        # Vault host built at runtime (e.g. "https://" + name + ".vault.azure.net/...").
        if ($found.Count -eq 0 -and $l -match "(?i)\.$KeyVaultDnsRx") {
            $calls.Add([pscustomobject][ordered]@{ line = $i + 1; vaultName = $null; objectType = $null; objectName = $null; version = $null; dynamic = $true })
        }
    }
    $res.calls = @($calls)
    [pscustomobject]$res
}

function New-Item2 {
    param([hashtable]$Ctx, [string]$Type, [string]$Id, [string]$Action, [string]$Note, [hashtable]$Details)
    $o = [ordered]@{
        subscriptionId = $Ctx.subscriptionId
        resourceGroup  = $Ctx.resourceGroup
        instance       = $Ctx.instance
        type           = $Type
        id             = $Id
        action         = $Action
        note           = $Note
    }
    if ($Details) { foreach ($k in $Details.Keys) { $o[$k] = $Details[$k] } }
    return [pscustomobject]$o
}

function Get-Prop {
    param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($p in $Path -split '\.') {
        if ($null -eq $cur) { return $null }
        $prop = $cur.PSObject.Properties[$p]
        if (-not $prop) { return $null }
        $cur = $prop.Value
    }
    return $cur
}

function Invoke-InstanceDiscovery {
    param([string]$Sub, [string]$Rg, [string]$Apim)

    Write-Host ">> $Apim ($Rg / $Sub)" -ForegroundColor Cyan
    $base = Get-ApimBaseUrl $Sub $Rg $Apim
    $ctx = @{ subscriptionId = $Sub; resourceGroup = $Rg; instance = $Apim }
    $items = [System.Collections.Generic.List[object]]::new()
    $coverage = [System.Collections.Generic.List[object]]::new()
    # Who uses what: lower-case named value name / certificate id or thumbprint -> consumers.
    $nvRefs = @{}; $certRefs = @{}
    $addRef = {
        param([hashtable]$Map, [string[]]$Keys, [string]$Consumer)
        foreach ($k in @($Keys | Where-Object { $_ })) {
            $kk = $k.ToLowerInvariant()
            if (-not $Map.ContainsKey($kk)) { $Map[$kk] = [System.Collections.Generic.List[string]]::new() }
            if (-not $Map[$kk].Contains($Consumer)) { $Map[$kk].Add($Consumer) }
        }
    }

    # Prefetch every top-level collection and single resource concurrently; sections below read the cache.
    $topLevel = @('subscriptions', 'namedValues', 'backends', 'authorizationServers', 'openidConnectProviders', 'identityProviders',
        'authorizationProviders', 'loggers', 'caches', 'certificates', 'gateways', 'products', 'apis', 'policyFragments?format=rawxml', 'workspaces')
    $pre = @{}
    $fetched = Get-ArmCollections -Urls @($topLevel | ForEach-Object { "$base/$_" }) -ThrottleLimit $ThrottleLimit
    for ($i = 0; $i -lt $topLevel.Count; $i++) { $pre[$topLevel[$i]] = $fetched[$i] }
    $singles = Invoke-ArmParallel -Urls @($base, "$base/tenant/access") -ThrottleLimit $ThrottleLimit

    $list = {
        param([string]$Collection, [string]$RelUrl, [switch]$OptionalFeature, $Result)
        $r = if ($Result) { $Result } elseif ($pre.ContainsKey($RelUrl)) { $pre[$RelUrl] } else { Get-ArmCollection -Url "$base/$RelUrl" }
        $status = if ($r.Ok) { 'ok' } elseif ($OptionalFeature -and ($r.NotFound -or $r.Error -match $NotSupportedRx)) { 'not-supported' } else { 'failed' }
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = $Collection; status = $status; count = $r.Items.Count; error = $r.Error })
        if ($status -eq 'failed') { Write-Warning "[$Apim] could not enumerate $Collection ($($r.Error))" }
        return $r.Items
    }

    $svc = $singles[0]
    $instanceInfo = [ordered]@{ subscriptionId = $Sub; resourceGroup = $Rg; name = $Apim }
    if ($svc.Ok) {
        $instanceInfo.sku = Get-Prop $svc.Data 'sku.name'
        $instanceInfo.location = $svc.Data.location
        $instanceInfo.managedIdentity = Get-Prop $svc.Data 'identity.type'
        $instanceInfo.publicNetworkAccess = Get-Prop $svc.Data 'properties.publicNetworkAccess'
    }
    else { $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'service'; status = 'failed'; count = 0; error = $svc.Error }) }

    # 1. Subscription keys
    foreach ($s in & $list 'subscriptions' 'subscriptions') {
        $isMaster = $s.name -eq 'master'
        $items.Add((New-Item2 $ctx 'subscription-key' $s.name 'auto' ($(if ($isMaster) { "Built-in all-access subscription. Rotate in incident mode (-IncludeMaster)." } else { 'Regenerate primary/secondary. Move callers to the other key first when possible.' })) @{
                    displayName = Get-Prop $s 'properties.displayName'; scope = Get-Prop $s 'properties.scope'; state = Get-Prop $s 'properties.state'
                    ownerId = Get-Prop $s 'properties.ownerId'; allowTracing = Get-Prop $s 'properties.allowTracing'; expirationDate = Get-Prop $s 'properties.expirationDate'
                    builtInMaster = $isMaster
                }))
    }

    # 2. Named values
    foreach ($nv in & $list 'namedValues' 'namedValues') {
        $secret = [bool](Get-Prop $nv 'properties.secret')
        $kvId = Get-Prop $nv 'properties.keyVault.secretIdentifier'
        $display = Get-Prop $nv 'properties.displayName'
        $isLogger = $display -like 'Logger-Credentials--*'
        if ($kvId) {
            $versioned = $kvId -match '/secrets/[^/]+/[0-9a-fA-F]{32}/?$'
            $items.Add((New-Item2 $ctx 'named-value-kv' $nv.name 'auto' ($(if ($versioned) { 'Version-pinned Key Vault reference: create new secret version and update the identifier BEFORE refresh, otherwise refresh reloads the same value.' } else { 'Rotate the secret in Key Vault first, then refreshSecret. Refresh does not revoke the old value at its issuer.' })) @{
                        displayName = $display; keyVaultSecretId = $kvId; versionPinned = $versioned
                        keyVaultIdentity = Get-Prop $nv 'properties.keyVault.identityClientId'
                        lastRefreshStatus = Get-Prop $nv 'properties.keyVault.lastStatus.code'
                        lastRefreshUtc = Get-Prop $nv 'properties.keyVault.lastStatus.timeStampUtc'
                        issuerRevocationRequired = $true
                    }))
        }
        elseif ($secret) {
            $items.Add((New-Item2 $ctx 'named-value-secret' $nv.name 'auto' ($(if ($isLogger) { 'Logger credential (connection string / instrumentation key) stored by APIM. Rotate at the target (Event Hubs/App Insights), then provide the new value.' } else { 'Secret stored in APIM. Create the new credential at its issuer, provide it via env var APIM_NV_<ID> or prompt. Consider moving to Key Vault.' })) @{
                        displayName = $display; loggerCredential = $isLogger; issuerRevocationRequired = $true
                    }))
        }
        elseif ($display -match $SecretNameRx -or $nv.name -match $SecretNameRx) {
            $items.Add((New-Item2 $ctx 'named-value-plain' $nv.name 'manual' 'Non-secret named value whose name suggests a credential. Its value has been visible in plain text: treat as exposed, rotate at issuer and mark secret / move to Key Vault.' @{
                        displayName = $display; heuristic = $true
                    }))
        }
    }

    # 3. Backends (credentials and proxy authentication). URLs are reduced to scheme+host so that
    # credentials embedded in userinfo, path or query never reach the inventory.
    foreach ($be in & $list 'backends' 'backends') {
        $cred = Get-Prop $be 'properties.credentials'
        $proxyUser = Get-Prop $be 'properties.proxy.username'
        $proxyPwd = Get-Prop $be 'properties.proxy.password'
        $headers = @(); $queries = @(); $kinds = @()
        foreach ($p in @((Get-Prop $cred 'header')?.PSObject.Properties)) { if ($p) { $k = @(@($p.Value) | ForEach-Object { Get-ValueKind $_ }); $kinds += $k; $headers += [ordered]@{ name = $p.Name; valueKinds = $k } } }
        foreach ($p in @((Get-Prop $cred 'query')?.PSObject.Properties)) { if ($p) { $k = @(@($p.Value) | ForEach-Object { Get-ValueKind $_ }); $kinds += $k; $queries += [ordered]@{ name = $p.Name; valueKinds = $k } } }
        $auth = Get-Prop $cred 'authorization'
        $authKind = if ($auth) { Get-ValueKind (Get-Prop $auth 'parameter') } else { $null }
        $proxyKind = if ($proxyPwd) { Get-ValueKind $proxyPwd } else { $null }
        $kinds += @($authKind, $proxyKind) | Where-Object { $_ }
        $hasLiteral = @($kinds | Where-Object { $_ -in 'literal', 'mixed-literal-and-ref' }).Count -gt 0
        $certs = @(@(Get-Prop $cred 'certificate') + @(Get-Prop $cred 'certificateIds') | Where-Object { $_ })
        $sf = Get-Prop $be 'properties.properties.serviceFabricCluster'
        $beConsumer = "backend:$($be.name)"
        $nvTexts = @(foreach ($p in @((Get-Prop $cred 'header')?.PSObject.Properties) + @((Get-Prop $cred 'query')?.PSObject.Properties)) { if ($p) { @($p.Value) } }) + @((Get-Prop $auth 'parameter'), $proxyPwd)
        & $addRef $nvRefs @($nvTexts | ForEach-Object { Get-NamedValueRefs ([string]$_) }) $beConsumer
        & $addRef $certRefs @($certs | ForEach-Object { ([string]$_ -split '/')[-1] }) $beConsumer
        if ($sf) { & $addRef $certRefs @(([string](Get-Prop $sf 'clientCertificateId') -split '/')[-1], (Get-Prop $sf 'clientCertificatethumbprint')) $beConsumer }
        if (-not $headers -and -not $queries -and -not $auth -and -not $certs -and -not $proxyUser -and -not $proxyPwd) { continue }
        $urlHost = $null
        $u = $null
        if ([Uri]::TryCreate([string](Get-Prop $be 'properties.url'), [UriKind]::Absolute, [ref]$u)) { $urlHost = "$($u.Scheme)://$($u.Host)" }
        $items.Add((New-Item2 $ctx 'backend' $be.name 'manual' 'Create new credential at the backend, PATCH backend with current ETag (or update the referenced named value), test, then revoke the old one.' @{
                    urlHost = $urlHost; headers = $headers; queryParameters = $queries
                    authorizationScheme = Get-Prop $auth 'scheme'; authorizationValueKind = $authKind
                    proxyAuthentication = [bool]($proxyUser -or $proxyPwd); proxyPasswordValueKind = $proxyKind
                    certificateCount = $certs.Count; hasLiteralSecret = $hasLiteral
                }))
    }

    # 4. OAuth2 servers, OIDC providers, developer portal identity providers, credential manager
    foreach ($x in & $list 'authorizationServers' 'authorizationServers') {
        $items.Add((New-Item2 $ctx 'oauth2-server' $x.name 'manual' 'New client secret at the IdP (az ad app credential reset --append), update here, republish dev portal, test, delete old secret.' @{
                    displayName = Get-Prop $x 'properties.displayName'; clientId = Get-Prop $x 'properties.clientId' }))
    }
    foreach ($x in & $list 'openidConnectProviders' 'openidConnectProviders') {
        $items.Add((New-Item2 $ctx 'oidc-provider' $x.name 'manual' 'New client secret at the IdP, update here, test, delete old secret.' @{
                    displayName = Get-Prop $x 'properties.displayName'; clientId = Get-Prop $x 'properties.clientId'; metadataEndpoint = Get-Prop $x 'properties.metadataEndpoint' }))
    }
    foreach ($x in & $list 'identityProviders' 'identityProviders') {
        $items.Add((New-Item2 $ctx 'identity-provider' $x.name 'manual' 'Developer portal sign-in provider: new client secret at the IdP, update here, test, delete old secret.' @{
                    idpType = Get-Prop $x 'properties.type'; clientId = Get-Prop $x 'properties.clientId' }))
    }
    foreach ($x in & $list 'authorizationProviders' 'authorizationProviders' -OptionalFeature) {
        $items.Add((New-Item2 $ctx 'credential-manager' $x.name 'manual' 'Credential manager provider: new client secret at the IdP, update provider, re-consent connections if needed, delete old secret.' @{
                    displayName = Get-Prop $x 'properties.displayName'; identityProvider = Get-Prop $x 'properties.identityProvider' }))
    }

    # 5. Loggers and external caches
    foreach ($x in & $list 'loggers' 'loggers') {
        $c = Get-Prop $x 'properties.credentials'
        $credKeys = @(); $kinds = @()
        if ($c) { foreach ($p in $c.PSObject.Properties) { $credKeys += $p.Name; $kinds += Get-ValueKind ([string]$p.Value); & $addRef $nvRefs @(Get-NamedValueRefs ([string]$p.Value)) "logger:$($x.name)" } }
        if (-not $credKeys) { continue }
        $items.Add((New-Item2 $ctx 'logger' $x.name 'manual' 'Rotate the connection string/key at the target (Event Hubs/App Insights). If the credential is a {{named value}}, rotate that named value; otherwise update logger with current ETag. Prefer managed identity.' @{
                    loggerType = Get-Prop $x 'properties.loggerType'; credentialKeys = $credKeys; valueKinds = $kinds; resourceId = Get-Prop $x 'properties.resourceId' }))
    }
    foreach ($x in & $list 'caches' 'caches' -OptionalFeature) {
        & $addRef $nvRefs @(Get-NamedValueRefs ([string](Get-Prop $x 'properties.connectionString'))) "cache:$($x.name)"
        $items.Add((New-Item2 $ctx 'external-cache' $x.name 'manual' 'Regenerate the Redis access key, update the cache connection string, then revoke the old key.' @{
                    description = Get-Prop $x 'properties.description'; useFromLocation = Get-Prop $x 'properties.useFromLocation'
                    connectionStringKind = Get-ValueKind (Get-Prop $x 'properties.connectionString') }))
    }

    # 6. Certificates (client certificates for backends / policies)
    foreach ($x in & $list 'certificates' 'certificates') {
        $kvId = Get-Prop $x 'properties.keyVault.secretIdentifier'
        $common = @{ subject = Get-Prop $x 'properties.subject'; thumbprint = Get-Prop $x 'properties.thumbprint'; expirationDate = Get-Prop $x 'properties.expirationDate' }
        if ($kvId) {
            $common += @{
                keyVaultSecretId = $kvId; versionPinned = [bool]((ConvertFrom-KeyVaultUri $kvId)?.version)
                keyVaultIdentity = Get-Prop $x 'properties.keyVault.identityClientId'
                lastRefreshStatus = Get-Prop $x 'properties.keyVault.lastStatus.code'
                lastRefreshUtc = Get-Prop $x 'properties.keyVault.lastStatus.timeStampUtc'
                issuerRevocationRequired = $true
            }
            $items.Add((New-Item2 $ctx 'certificate-kv' $x.name 'auto' 'Key Vault-backed certificate. Reissue it in Key Vault with a NEW key pair (a renewal may reuse the exposed key), then refreshSecret. Revoke the old certificate.' $common))
        }
        else {
            $items.Add((New-Item2 $ctx 'certificate' $x.name 'manual' 'Issue a new certificate (prefer Key Vault reference), update backends/policies to use it, then revoke the old one.' ($common + @{ keyVaultBacked = $false })))
        }
    }

    # 6b. Custom domain certificates loaded from Key Vault (service hostnameConfigurations).
    if ($svc.Ok) {
        $hcs = @(Get-Prop $svc.Data 'properties.hostnameConfigurations' | Where-Object { $_ })
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'hostnameConfigurations'; status = 'ok'; count = $hcs.Count; error = $null })
        foreach ($h in $hcs) {
            $kvId = Get-Prop $h 'keyVaultId'
            if (-not $kvId) { continue }
            $items.Add((New-Item2 $ctx 'hostname-certificate-kv' "$(Get-Prop $h 'type'):$(Get-Prop $h 'hostName')" 'manual' 'Custom domain certificate from Key Vault. Reissue it with a NEW key pair in Key Vault; APIM auto-syncs unversioned references (can take 1-2 days, no SLA on Developer tier). Use the portal certificate sync or re-apply the hostname configuration, then check the certificate served on the endpoint. Revoke the old certificate.' @{
                        hostnameType = Get-Prop $h 'type'; hostName = Get-Prop $h 'hostName'; keyVaultSecretId = $kvId
                        versionPinned = [bool]((ConvertFrom-KeyVaultUri $kvId)?.version); keyVaultIdentity = Get-Prop $h 'identityClientId'
                        thumbprint = Get-Prop $h 'certificate.thumbprint'; expirationDate = Get-Prop $h 'certificate.expiry'
                        issuerRevocationRequired = $true
                    }))
        }
    }

    # 7. Self-hosted gateway keys (and which certificates their hostname configurations use)
    $shg = @(& $list 'gateways' 'gateways' -OptionalFeature | Where-Object { $_.name -ne 'managed' })
    foreach ($gw in $shg) {
        $items.Add((New-Item2 $ctx 'gateway-key' $gw.name 'auto' 'Self-hosted gateway keys. Regenerating invalidates tokens derived from that key: issue a new gateway token and redeploy the gateway.' @{
                    description = Get-Prop $gw 'properties.description' }))
    }
    if ($shg.Count -gt 0) {
        $gwHc = Get-ArmCollections -Urls @($shg | ForEach-Object { "$base/gateways/$($_.name)/hostnameConfigurations" }) -ThrottleLimit $ThrottleLimit
        for ($i = 0; $i -lt $shg.Count; $i++) {
            foreach ($hc in & $list "gateways/$($shg[$i].name)/hostnameConfigurations" '' -Result $gwHc[$i]) {
                & $addRef $certRefs @(([string](Get-Prop $hc 'properties.certificateId') -split '/')[-1]) "gateway:$($shg[$i].name)/$($hc.name)"
            }
        }
    }

    # 8. Direct management API (tenant access) keys
    $ta = $singles[1]
    if ($ta.Ok) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'tenant/access'; status = 'ok'; count = 1; error = $null })
        $enabled = [bool](Get-Prop $ta.Data 'properties.enabled')
        $items.Add((New-Item2 $ctx 'tenant-access' 'access' 'auto' ($(if ($enabled) { 'Direct Management API is ENABLED: keys are usable. Rotate both and consider disabling.' } else { 'Direct Management API disabled; keys exist but cannot be used. Rotation is harmless.' })) @{
                    directManagementApiEnabled = $enabled }))
    }
    else {
        $st = if ($ta.NotFound -or $ta.Error -match 'Bad ?Request') { 'not-supported' } else { 'failed' }
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'tenant/access'; status = $st; count = 0; error = $ta.Error })
        if ($st -eq 'failed') { Write-Warning "[$Apim] could not read tenant/access ($($ta.Error))" }
    }

    # 9. Policies (global, products, APIs, operations, fragments). Content stays in memory only.
    $policyTargets = [System.Collections.Generic.List[object]]::new()
    $policyTargets.Add(@{ id = 'global'; scope = 'global'; url = 'policies' })
    foreach ($p in & $list 'products' 'products') { $policyTargets.Add(@{ id = "product:$($p.name)"; scope = 'product'; url = "products/$($p.name)/policies" }) }
    $apis = @(& $list 'apis' 'apis')
    foreach ($a in $apis) { $policyTargets.Add(@{ id = "api:$($a.name)"; scope = 'api'; url = "apis/$($a.name)/policies" }) }
    if ($SkipOperationPolicies) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'operation-policies'; status = 'skipped'; count = 0; error = 'Skipped by -SkipOperationPolicies.' })
    }
    elseif ($apis.Count -gt 0) {
        $opResults = Get-ArmCollections -Urls @($apis | ForEach-Object { "$base/apis/$($_.name)/operations" }) -ThrottleLimit $ThrottleLimit
        for ($i = 0; $i -lt $apis.Count; $i++) {
            $an = $apis[$i].name
            foreach ($op in & $list "apis/$an/operations" "apis/$an/operations" -Result $opResults[$i]) {
                $policyTargets.Add(@{ id = "operation:$an/$($op.name)"; scope = 'operation'; url = "apis/$an/operations/$($op.name)/policies" })
            }
        }
    }
    $policiesScanned = 0
    # Non-secret named value values (in memory only) so Key Vault URLs held in {{named values}} are resolved.
    $nvPlain = @{}
    foreach ($nv in @($pre['namedValues'].Items)) {
        if (-not (Get-Prop $nv 'properties.secret') -and (Get-Prop $nv 'properties.value')) {
            foreach ($k in @($nv.name, (Get-Prop $nv 'properties.displayName')) | Where-Object { $_ }) { $nvPlain[$k.ToLowerInvariant()] = Get-Prop $nv 'properties.value' }
        }
    }
    $addKvPolicy = {
        param([string]$Id, [string]$Scope, [string]$Xml)
        $kv = Get-PolicyKeyVaultCalls -Xml $Xml -NamedValueValues $nvPlain
        if ($kv.calls.Count -eq 0 -and $kv.managedIdentityLines.Count -eq 0) { return }
        $cached = $kv.cacheStoreLines.Count -gt 0
        $items.Add((New-Item2 $ctx 'policy-keyvault-call' $Id 'manual' ("Policy reads Key Vault directly at runtime. Rotate the listed Key Vault objects (new credential at the issuer, new version); the policy picks up the latest version on its next call unless the URL pins a version." + $(if ($cached) { ' The policy caches values (cache-store-value): purge the cache or wait for the cache duration after rotating.' } else { '' }) + ' Retest the API afterwards.') @{
                    scope = $Scope; keyVaultCalls = $kv.calls; managedIdentityLines = $kv.managedIdentityLines
                    cachesValue = $cached; cacheStoreLines = $kv.cacheStoreLines
                    exposure = 'key-vault'; rotationRequired = $true
                }))
    }
    $polResults = Get-ArmCollections -Urls @($policyTargets | ForEach-Object { "$base/$($_.url)" }) -ThrottleLimit $ThrottleLimit
    for ($pi = 0; $pi -lt $policyTargets.Count; $pi++) {
        $t = $policyTargets[$pi]
        $r = $polResults[$pi]
        if (-not $r.Ok) {
            if (-not $r.NotFound) { $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = "policy:$($t.id)"; status = 'failed'; count = 0; error = $r.Error }); Write-Warning "[$Apim] could not read policy $($t.id) ($($r.Error))" }
            continue
        }
        foreach ($pol in $r.Items) {
            $xml = Get-Prop $pol 'properties.value'
            if (-not $xml) { continue }
            $policiesScanned++
            & $addRef $nvRefs @(Get-NamedValueRefs $xml) "policy:$($t.id)"
            & $addRef $certRefs @(Get-PolicyCertificateRefs $xml) "policy:$($t.id)"
            & $addKvPolicy $t.id $t.scope $xml
            $f = Get-PolicyFindings $xml
            if ($f.findings.Count -gt 0 -or -not $f.parsed) {
                $items.Add((New-Item2 $ctx 'policy' $t.id 'manual' 'Possible hard-coded credential. Review the listed lines in the portal policy editor, rotate at the source and replace with a Key Vault-backed {{named value}}.' @{
                            scope = $t.scope; parsed = $f.parsed; findings = $f.findings; keywordLines = $f.keywordLines }))
            }
            elseif ($f.keywordLines.Count -gt 0) {
                $items.Add((New-Item2 $ctx 'policy-review' $t.id 'manual' 'Credential-related keywords found (no literal secret detected). Quick review recommended.' @{
                            scope = $t.scope; keywordLines = $f.keywordLines }))
            }
        }
    }
    foreach ($frag in & $list 'policyFragments' 'policyFragments?format=rawxml' -OptionalFeature) {
        $xml = Get-Prop $frag 'properties.value'
        if (-not $xml) {
            $one = Invoke-Arm -Url "$base/policyFragments/$($frag.name)?format=rawxml"
            $xml = if ($one.Ok) { Get-Prop $one.Data 'properties.value' } else { $null }
            if (-not $xml) {
                $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = "policy:fragment:$($frag.name)"; status = 'failed'; count = 0; error = $(if ($one.Ok) { 'EmptyFragmentContent' } else { $one.Error }) })
                Write-Warning "[$Apim] could not read policy fragment $($frag.name)"
                continue
            }
        }
        $policiesScanned++
        & $addRef $nvRefs @(Get-NamedValueRefs $xml) "policy:fragment:$($frag.name)"
        & $addRef $certRefs @(Get-PolicyCertificateRefs $xml) "policy:fragment:$($frag.name)"
        & $addKvPolicy "fragment:$($frag.name)" 'fragment' $xml
        $f = Get-PolicyFindings $xml
        if ($f.findings.Count -gt 0 -or -not $f.parsed) {
            $items.Add((New-Item2 $ctx 'policy' "fragment:$($frag.name)" 'manual' 'Possible hard-coded credential in policy fragment. Review in the portal, rotate at source, use a Key Vault-backed {{named value}}.' @{
                        scope = 'fragment'; parsed = $f.parsed; findings = $f.findings; keywordLines = $f.keywordLines }))
        }
        elseif ($f.keywordLines.Count -gt 0) {
            $items.Add((New-Item2 $ctx 'policy-review' "fragment:$($frag.name)" 'manual' 'Credential-related keywords found in fragment (no literal secret detected).' @{
                        scope = 'fragment'; keywordLines = $f.keywordLines }))
        }
    }
    $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'policies-scanned'; status = 'ok'; count = $policiesScanned; error = $null })

    # 10. Workspaces are not scanned: flag them so coverage is not overstated.
    $ws = $pre['workspaces']
    if ($ws.Ok -and $ws.Items.Count -gt 0) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'workspaces'; status = 'not-scanned'; count = $ws.Items.Count; error = 'Workspace-scoped resources are not covered by this script.' })
        Write-Warning "[$Apim] has $($ws.Items.Count) workspace(s); workspace-scoped credentials are NOT scanned."
    }
    elseif (-not $ws.Ok -and -not ($ws.NotFound -or $ws.Error -match $NotSupportedRx)) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'workspaces'; status = 'failed'; count = 0; error = $ws.Error })
        Write-Warning "[$Apim] could not enumerate workspaces ($($ws.Error))"
    }

    # Attach consumers (impact map) to named values and certificates.
    foreach ($it in $items) {
        $keys = switch -Wildcard ($it.type) {
            'named-value*' { @($it.id, $it.displayName) }
            'certificate*' { @($it.id, $it.thumbprint) }
            default { $null }
        }
        if ($null -eq $keys) { continue }
        $used = @($keys | Where-Object { $_ } | ForEach-Object { $k = $_.ToLowerInvariant(); $m = if ($it.type -like 'named-value*') { $nvRefs } else { $certRefs }; if ($m.ContainsKey($k)) { $m[$k] } } | Sort-Object -Unique)
        $it | Add-Member -NotePropertyName usedBy -NotePropertyValue $used -Force
    }

    return @{ instance = [pscustomobject]$instanceInfo; items = $items; coverage = $coverage }
}

# ---------------------------------------------------------------- main
$account = Initialize-AzCli

$targets = @()
if ($AllSubscriptions) {
    $subs = Get-ArmCollection -Url 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    if (-not $subs.Ok) { throw "Could not list subscriptions ($($subs.Error))." }
    $subIds = @($subs.Items | Where-Object state -EQ 'Enabled' | ForEach-Object subscriptionId)
}
else {
    $subIds = @($(if ($SubscriptionId) { $SubscriptionId } else { $account.id }))
}

$globalCoverage = [System.Collections.Generic.List[object]]::new()
foreach ($sid in $subIds) {
    if ($Name) {
        if (-not $ResourceGroup) { throw '-Name requires -ResourceGroup.' }
        $targets += [pscustomobject]@{ sub = $sid; rg = $ResourceGroup; name = $Name }
        continue
    }
    $listUrl = if ($ResourceGroup) { "https://management.azure.com/subscriptions/$sid/resourceGroups/$ResourceGroup/providers/Microsoft.ApiManagement/service" }
    else { "https://management.azure.com/subscriptions/$sid/providers/Microsoft.ApiManagement/service" }
    $r = Get-ArmCollection -Url $listUrl
    if (-not $r.Ok) {
        Write-Warning "Could not list APIM in subscription $sid ($($r.Error))"
        $globalCoverage.Add([pscustomobject][ordered]@{ instance = $null; collection = "apim-list:$sid"; status = 'failed'; count = 0; error = $r.Error })
        continue
    }
    foreach ($s in $r.Items) { $targets += [pscustomobject]@{ sub = $sid; rg = ($s.id -split '/')[4]; name = $s.name } }
}
if (-not $targets) { throw 'No API Management instances found.' }

$allItems = [System.Collections.Generic.List[object]]::new()
$allCoverage = [System.Collections.Generic.List[object]]::new()
foreach ($c in $globalCoverage) { $allCoverage.Add($c) }
$instances = @()
foreach ($t in $targets) {
    $res = Invoke-InstanceDiscovery -Sub $t.sub -Rg $t.rg -Apim $t.name
    $instances += $res.instance
    foreach ($i in $res.items) { $allItems.Add($i) }
    foreach ($c in $res.coverage) { $allCoverage.Add($c) }
}

# ---------------------------------------------------------------- Key Vault exposure
# Every APIM item that loads a credential from Key Vault, plus the full contents (metadata only) of the
# affected vaults: vaults referenced by APIM and vaults passed with -KeyVault.
$kvLinked = @($allItems | Where-Object { $_.PSObject.Properties['keyVaultSecretId'] -and $_.keyVaultSecretId })
$kvPolicy = @($allItems | Where-Object type -EQ 'policy-keyvault-call')
$vaults = [ordered]@{}   # name -> @{ resourceId; explicit }
foreach ($it in $kvLinked) { $ref = ConvertFrom-KeyVaultUri $it.keyVaultSecretId; if ($ref -and -not $vaults.Contains($ref.vaultName)) { $vaults[$ref.vaultName] = @{ resourceId = $null; explicit = $false } } }
foreach ($c in @($kvPolicy | ForEach-Object { $_.keyVaultCalls } | Where-Object vaultName)) { if (-not $vaults.Contains($c.vaultName)) { $vaults[$c.vaultName] = @{ resourceId = $null; explicit = $false } } }
$dynPolicies = @($kvPolicy | Where-Object { @($_.keyVaultCalls | Where-Object { -not $_.vaultName }).Count -gt 0 -or ($_.keyVaultCalls.Count -eq 0) })
foreach ($p in $dynPolicies) { Write-Warning "[$($p.instance)] policy $($p.id) calls Key Vault with a URL built at runtime (or only authenticates to it): pass the vault(s) it uses with -KeyVault." }
foreach ($kvArg in @($KeyVault | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $isId = $kvArg -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[^/]+$'
    $n = ($kvArg -split '/')[-1].ToLowerInvariant()
    $vaults[$n] = @{ resourceId = $(if ($isId) { $kvArg } else { $null }); explicit = $true }
}
$keyVaultInfo = @()
if ($vaults.Count -gt 0) {
    Write-Host ">> Key Vault exposure: $($vaults.Keys -join ', ')" -ForegroundColor Cyan
    $kvIdx = Get-KeyVaultIndex -SubscriptionIds $subIds
    foreach ($e in $kvIdx.Errors) { $allCoverage.Add([pscustomobject][ordered]@{ instance = $null; collection = "keyvault-list:$($e.subscriptionId)"; status = 'failed'; count = 0; error = $e.error }) }

    $metaByVault = @{}   # vault -> @{ secrets = @{name -> meta}; listed = bool }
    foreach ($vn in @($vaults.Keys)) {
        $v = $vaults[$vn]
        if (-not $v.resourceId) { $v.resourceId = $kvIdx.Index[$vn] }
        $metaByVault[$vn] = @{ secrets = @{}; keys = @{}; listed = $false }
        if (-not $v.resourceId) {
            $allCoverage.Add([pscustomobject][ordered]@{ instance = $vn; collection = "keyvault:$vn"; status = 'not-found'; count = 0; error = 'Vault not found in the scanned subscriptions (other subscription or no access). Pass its resource ID with -KeyVault.' })
            Write-Warning "Key Vault '$vn' could not be resolved; its contents and versions are NOT checked."
            $keyVaultInfo += [pscustomobject][ordered]@{ name = $vn; resourceId = $null; explicit = $v.explicit; contentsScanned = $false }
            continue
        }
        $vSeg = $v.resourceId -split '/'
        $vctx = @{ subscriptionId = $vSeg[2]; resourceGroup = $vSeg[4]; instance = $vn }
        $consumersOf = {
            param([string]$ObjName)
            @($kvLinked | Where-Object { $r = ConvertFrom-KeyVaultUri $_.keyVaultSecretId; $r -and $r.vaultName -eq $vn -and $r.name -eq $ObjName } | ForEach-Object { "$($_.instance)/$($_.type)/$($_.id)" })
            @($kvPolicy | Where-Object { @($_.keyVaultCalls | Where-Object { $_.vaultName -eq $vn -and $_.objectName -eq $ObjName }).Count -gt 0 } | ForEach-Object { "$($_.instance)/policy:$($_.id)" })
        }
        if ($SkipKeyVaultContents) {
            $allCoverage.Add([pscustomobject][ordered]@{ instance = $vn; collection = "keyvault:$vn/contents"; status = 'skipped'; count = 0; error = 'Skipped by -SkipKeyVaultContents.' })
        }
        else {
            foreach ($ot in 'secrets', 'keys') {
                $lr = Get-KeyVaultObjects -VaultResourceId $v.resourceId -ObjectType $ot
                $allCoverage.Add([pscustomobject][ordered]@{ instance = $vn; collection = "keyvault:$vn/$ot"; status = $(if ($lr.Ok) { 'ok' } else { 'failed' }); count = $lr.Items.Count; error = $lr.Error })
                if (-not $lr.Ok) { Write-Warning "Could not list $ot of Key Vault '$vn' ($($lr.Error))"; continue }
                if ($ot -eq 'secrets') { $metaByVault[$vn].listed = $true }
                foreach ($m in $lr.Items) {
                    if ($ot -eq 'secrets') { $metaByVault[$vn].secrets[$m.name.ToLowerInvariant()] = $m } else { $metaByVault[$vn].keys[$m.name.ToLowerInvariant()] = $m }
                    $isCertLike = $ot -eq 'secrets' -and $m.contentType -match 'pkcs12|pem'
                    $note = if ($ot -eq 'keys') { 'Exposed Key Vault key: create a new key version (rotate), re-wrap / re-encrypt / re-sign what depends on it, then disable the old versions.' }
                    elseif ($isCertLike) { 'Exposed certificate / private key: reissue the certificate with a NEW key pair, store it as a new version, update consumers, then revoke the old certificate.' }
                    else { 'Exposed Key Vault secret: issue a NEW credential at its issuer, store it as a new version, refresh consumers, then revoke the old credential at the issuer and disable old versions.' }
                    $assess = Get-KeyVaultAssessment -Ref ([pscustomobject]@{ version = $null }) -MetaResult ([pscustomobject]@{ Ok = $true; NotFound = $false; Meta = $m }) -CutoffUtc $CutoffUtc
                    $allItems.Add((New-Item2 $vctx $(if ($ot -eq 'keys') { 'keyvault-key' } else { 'keyvault-secret' }) $m.name 'manual' $note @{
                                resourceKind = 'Microsoft.KeyVault/vaults'; exposure = 'key-vault'; rotationRequired = $true
                                latestVersion = $m.latestVersion; latestVersionCreatedUtc = $m.latestVersionCreatedUtc; enabled = $m.enabled
                                expiresUtc = $m.expiresUtc; contentType = $m.contentType; keyType = $m.keyType
                                keyVaultAssessment = $assess; usedBy = @(& $consumersOf $m.name); issuerRevocationRequired = $true
                            }))
                }
            }
        }
        $keyVaultInfo += [pscustomobject][ordered]@{ name = $vn; resourceId = $v.resourceId; explicit = $v.explicit; contentsScanned = [bool]$metaByVault[$vn].listed }
    }

    # Mark every APIM item that loads from Key Vault and assess its reference.
    foreach ($it in $kvLinked) {
        $ref = ConvertFrom-KeyVaultUri $it.keyVaultSecretId
        $v = if ($ref) { $vaults[$ref.vaultName] } else { $null }
        $mr = $null
        if ($ref -and $v -and $v.resourceId -and $ref.objectType -eq 'secrets') {
            $m = $metaByVault[$ref.vaultName].secrets[$ref.name.ToLowerInvariant()]
            $mr = if ($m) { [pscustomobject]@{ Ok = $true; NotFound = $false; Meta = $m } }
            else { Get-KeyVaultSecretMeta -VaultResourceId $v.resourceId -Name $ref.name }
        }
        $assess = Get-KeyVaultAssessment -Ref $ref -MetaResult $mr -CutoffUtc $CutoffUtc
        $latest = if ($mr -and $mr.Ok) { $mr.Meta } else { $null }
        $loaded = $null
        if ($latest -and $latest.latestVersionCreatedUtc -and $it.PSObject.Properties['lastRefreshUtc'] -and $it.lastRefreshUtc) {
            $lr = ConvertTo-UtcDateTime $it.lastRefreshUtc
            $loaded = ($it.lastRefreshStatus -eq 'Success') -and $lr -and ($lr -gt $latest.latestVersionCreatedUtc) -and ($assess -ne 'pinned-to-older-version')
        }
        $it | Add-Member -Force -NotePropertyName exposure -NotePropertyValue 'key-vault'
        $it | Add-Member -Force -NotePropertyName rotationRequired -NotePropertyValue $true
        $it | Add-Member -Force -NotePropertyName keyVault -NotePropertyValue ([pscustomobject][ordered]@{
                vaultName = ${ref}?.vaultName; vaultResourceId = ${v}?.resourceId; objectName = ${ref}?.name
                configuredVersion = ${ref}?.version; latestVersion = ${latest}?.latestVersion; latestVersionCreatedUtc = ${latest}?.latestVersionCreatedUtc
                assessment = $assess; apimLoadedLatestVersion = $loaded; metadataError = $(if ($mr -and -not $mr.Ok) { $mr.Error } else { $null })
            })
    }

    # Assess every direct Key Vault call made by a policy (policies read the latest version at runtime).
    foreach ($it in $kvPolicy) {
        foreach ($c in @($it.keyVaultCalls)) {
            $v = if ($c.vaultName) { $vaults[$c.vaultName] } else { $null }
            $assess = 'dynamic-reference'
            if ($c.vaultName -and -not $c.dynamic) {
                $mr = $null
                if ($v -and $v.resourceId) {
                    # Certificates are also exposed as a secret with the same name.
                    $m = if ($c.objectType -eq 'keys') { $metaByVault[$c.vaultName].keys[$c.objectName.ToLowerInvariant()] } else { $metaByVault[$c.vaultName].secrets[$c.objectName.ToLowerInvariant()] }
                    $mr = if ($m) { [pscustomobject]@{ Ok = $true; NotFound = $false; Meta = $m } }
                    elseif ($c.objectType -ne 'keys') { Get-KeyVaultSecretMeta -VaultResourceId $v.resourceId -Name $c.objectName }
                }
                $assess = Get-KeyVaultAssessment -Ref $c -MetaResult $mr -CutoffUtc $CutoffUtc
            }
            $c | Add-Member -Force -NotePropertyName vaultResourceId -NotePropertyValue (${v}?.resourceId)
            $c | Add-Member -Force -NotePropertyName assessment -NotePropertyValue $assess
        }
    }
}

$failed = @($allCoverage | Where-Object status -In 'failed', 'not-scanned', 'skipped', 'not-found')
$kvPendingStates = 'rotation-required', 'not-rotated-in-key-vault', 'pinned-to-older-version', 'secret-not-found', 'metadata-unavailable', 'unknown'
$inventory = [ordered]@{
    metadata = [ordered]@{
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        tool             = 'Get-ApimCredentials.ps1'
        apiVersion       = $ApiVersion
        signedInAs       = $account.user.name
        tenantId         = $account.tenantId
        secretValuesRead = $false
        heuristicNote    = 'Named-value and policy credential detection is heuristic. Review policy-review items and coverage.'
        instances        = $instances
        compromisedSinceUtc = $(if ($CutoffUtc) { $CutoffUtc.ToString('o') } else { $null })
        keyVaults        = $keyVaultInfo
    }
    summary  = [ordered]@{
        coverageComplete = ($failed.Count -eq 0)
        totalItems       = $allItems.Count
        autoRotatable    = @($allItems | Where-Object action -EQ 'auto').Count
        manual           = @($allItems | Where-Object action -EQ 'manual').Count
        keyVaultLinkedItems = $kvLinked.Count
        keyVaultObjects  = @($allItems | Where-Object type -In 'keyvault-secret', 'keyvault-key').Count
        keyVaultPendingInKeyVault = @($kvLinked | Where-Object { $_.keyVault.assessment -in $kvPendingStates }).Count
        keyVaultPolicyCallers = $kvPolicy.Count
        byType           = [ordered]@{}
    }
    coverage = $allCoverage
    items    = $allItems
}
foreach ($g in ($allItems | Group-Object type | Sort-Object Name)) { $inventory.summary.byType[$g.Name] = $g.Count }

$json = $inventory | ConvertTo-Json -Depth 20
$outPath = if ([IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location).Path $OutFile }
[IO.File]::WriteAllText($outPath, $json, [Text.UTF8Encoding]::new($false))

$allItems | Select-Object instance, type, id, action, @{n = 'detail'; e = {
        $i = $_
        switch ($i.type) {
            'subscription-key' { "$($i.displayName) [$($i.state)]" }
            'tenant-access' { "enabled=$($i.directManagementApiEnabled)" }
            'policy' { "lines " + (($i.findings | ForEach-Object { $_.line } | Sort-Object -Unique) -join ',') }
            'policy-review' { "keyword lines " + ($i.keywordLines -join ',') }
            { $_ -in 'keyvault-secret', 'keyvault-key' } { "$($i.keyVaultAssessment); usedBy=$(@($i.usedBy).Count)" }
            'policy-keyvault-call' { ((@($i.keyVaultCalls) | ForEach-Object { "L$($_.line) $(if ($_.vaultName) { $_.vaultName } else { '?' })/$(if ($_.objectName) { $_.objectName } else { '?' }): $($_.assessment)" }) + @(if ($i.managedIdentityLines) { "MI auth L$($i.managedIdentityLines -join ',')" }) + @(if ($i.cachesValue) { 'cached' })) -join '; ' }
            default {
                if ($i.PSObject.Properties['keyVault'] -and $i.keyVault) { "KV $($i.keyVault.vaultName)/$($i.keyVault.objectName): $($i.keyVault.assessment)" }
                elseif ($i.PSObject.Properties['subject']) { $i.subject }
                else { $i.displayName }
            }
        } } } | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host ("Items: {0} (auto: {1}, manual: {2})" -f $inventory.summary.totalItems, $inventory.summary.autoRotatable, $inventory.summary.manual)
if ($vaults.Count -gt 0) {
    Write-Host ("Key Vault: {0} APIM item(s) linked, {1} policy(ies) calling Key Vault directly, {2} vault object(s) to rotate, {3} linked item(s) still pending in Key Vault{4}" -f $inventory.summary.keyVaultLinkedItems, $inventory.summary.keyVaultPolicyCallers, $inventory.summary.keyVaultObjects, $inventory.summary.keyVaultPendingInKeyVault, $(if (-not $CutoffUtc) { ' (no -CompromisedSince: versions cannot be judged)' } else { '' }))
}
if ($failed) { Write-Warning "Coverage INCOMPLETE: $($failed.Count) collection(s) failed. See 'coverage' in $OutFile." }
Write-Host "Inventory written to $OutFile (no secret values included)." -ForegroundColor Green
