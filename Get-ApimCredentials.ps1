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
    element names and rule names are reported, never policy content.

    Policy and naming analysis is heuristic. Any collection that could not be enumerated is reported
    in "coverage" with status "failed" and the inventory is flagged as incomplete.

.EXAMPLE
    ./Get-ApimCredentials.ps1 -ResourceGroup my-rg -Name my-apim
.EXAMPLE
    ./Get-ApimCredentials.ps1 -SubscriptionId <id>            # every APIM in the subscription
.EXAMPLE
    ./Get-ApimCredentials.ps1 -AllSubscriptions -OutFile all.json
#>
[CmdletBinding(DefaultParameterSetName = 'Scoped')]
param(
    [Parameter(ParameterSetName = 'Scoped')][string]$SubscriptionId,
    [Parameter(ParameterSetName = 'Scoped')][string]$ResourceGroup,
    [Parameter(ParameterSetName = 'Scoped')][string]$Name,
    [Parameter(ParameterSetName = 'All')][switch]$AllSubscriptions,
    [string]$OutFile = 'apim-credentials-inventory.json',
    [switch]$SkipOperationPolicies
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ApimCredentials.Common.psm1') -Force

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
            if ($an -match $SecretNameRx) {
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

    $list = {
        param([string]$Collection, [string]$RelUrl, [switch]$OptionalFeature)
        $r = Get-ArmCollection -Url "$base/$RelUrl"
        $status = if ($r.Ok) { 'ok' } elseif ($OptionalFeature -and ($r.NotFound -or $r.Error -match 'Bad Request|MethodNotAllowed|NotSupported')) { 'not-supported' } else { 'failed' }
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = $Collection; status = $status; count = $r.Items.Count; error = $r.Error })
        if ($status -eq 'failed') { Write-Warning "[$Apim] could not enumerate $Collection ($($r.Error))" }
        return $r.Items
    }

    $svc = Invoke-Arm -Url $base
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
        if ($c) { foreach ($p in $c.PSObject.Properties) { $credKeys += $p.Name; $kinds += Get-ValueKind ([string]$p.Value) } }
        if (-not $credKeys) { continue }
        $items.Add((New-Item2 $ctx 'logger' $x.name 'manual' 'Rotate the connection string/key at the target (Event Hubs/App Insights). If the credential is a {{named value}}, rotate that named value; otherwise update logger with current ETag. Prefer managed identity.' @{
                    loggerType = Get-Prop $x 'properties.loggerType'; credentialKeys = $credKeys; valueKinds = $kinds; resourceId = Get-Prop $x 'properties.resourceId' }))
    }
    foreach ($x in & $list 'caches' 'caches' -OptionalFeature) {
        $items.Add((New-Item2 $ctx 'external-cache' $x.name 'manual' 'Regenerate the Redis access key, update the cache connection string, then revoke the old key.' @{
                    description = Get-Prop $x 'properties.description'; useFromLocation = Get-Prop $x 'properties.useFromLocation'
                    connectionStringKind = Get-ValueKind (Get-Prop $x 'properties.connectionString') }))
    }

    # 6. Certificates (client certificates for backends)
    foreach ($x in & $list 'certificates' 'certificates') {
        $items.Add((New-Item2 $ctx 'certificate' $x.name 'manual' 'Issue a new certificate (prefer Key Vault reference), update backends/policies to use it, then revoke the old one.' @{
                    subject = Get-Prop $x 'properties.subject'; thumbprint = Get-Prop $x 'properties.thumbprint'; expirationDate = Get-Prop $x 'properties.expirationDate'
                    keyVaultBacked = [bool](Get-Prop $x 'properties.keyVault.secretIdentifier') }))
    }

    # 7. Self-hosted gateway keys
    foreach ($gw in & $list 'gateways' 'gateways' -OptionalFeature) {
        if ($gw.name -eq 'managed') { continue }
        $items.Add((New-Item2 $ctx 'gateway-key' $gw.name 'auto' 'Self-hosted gateway keys. Regenerating invalidates tokens derived from that key: issue a new gateway token and redeploy the gateway.' @{
                    description = Get-Prop $gw 'properties.description' }))
    }

    # 8. Direct management API (tenant access) keys
    $ta = Invoke-Arm -Url "$base/tenant/access"
    if ($ta.Ok) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'tenant/access'; status = 'ok'; count = 1; error = $null })
        $enabled = [bool](Get-Prop $ta.Data 'properties.enabled')
        $items.Add((New-Item2 $ctx 'tenant-access' 'access' 'auto' ($(if ($enabled) { 'Direct Management API is ENABLED: keys are usable. Rotate both and consider disabling.' } else { 'Direct Management API disabled; keys exist but cannot be used. Rotation is harmless.' })) @{
                    directManagementApiEnabled = $enabled }))
    }
    else {
        $st = if ($ta.NotFound -or $ta.Error -match 'Bad Request') { 'not-supported' } else { 'failed' }
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'tenant/access'; status = $st; count = 0; error = $ta.Error })
        if ($st -eq 'failed') { Write-Warning "[$Apim] could not read tenant/access ($($ta.Error))" }
    }

    # 9. Policies (global, products, APIs, operations, fragments). Content stays in memory only.
    $policyTargets = [System.Collections.Generic.List[object]]::new()
    $policyTargets.Add(@{ id = 'global'; scope = 'global'; url = 'policies' })
    foreach ($p in & $list 'products' 'products') { $policyTargets.Add(@{ id = "product:$($p.name)"; scope = 'product'; url = "products/$($p.name)/policies" }) }
    foreach ($a in & $list 'apis' 'apis') {
        $policyTargets.Add(@{ id = "api:$($a.name)"; scope = 'api'; url = "apis/$($a.name)/policies" })
        if (-not $SkipOperationPolicies) {
            foreach ($op in & $list "apis/$($a.name)/operations" "apis/$($a.name)/operations") {
                $policyTargets.Add(@{ id = "operation:$($a.name)/$($op.name)"; scope = 'operation'; url = "apis/$($a.name)/operations/$($op.name)/policies" })
            }
        }
    }
    if ($SkipOperationPolicies) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'operation-policies'; status = 'skipped'; count = 0; error = 'Skipped by -SkipOperationPolicies.' })
    }
    $policiesScanned = 0
    foreach ($t in $policyTargets) {
        $r = Get-ArmCollection -Url "$base/$($t.url)"
        if (-not $r.Ok) {
            if (-not $r.NotFound) { $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = "policy:$($t.id)"; status = 'failed'; count = 0; error = $r.Error }); Write-Warning "[$Apim] could not read policy $($t.id) ($($r.Error))" }
            continue
        }
        foreach ($pol in $r.Items) {
            $xml = Get-Prop $pol 'properties.value'
            if (-not $xml) { continue }
            $policiesScanned++
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
    $ws = Get-ArmCollection -Url "$base/workspaces"
    if ($ws.Ok -and $ws.Items.Count -gt 0) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'workspaces'; status = 'not-scanned'; count = $ws.Items.Count; error = 'Workspace-scoped resources are not covered by this script.' })
        Write-Warning "[$Apim] has $($ws.Items.Count) workspace(s); workspace-scoped credentials are NOT scanned."
    }
    elseif (-not $ws.Ok -and -not ($ws.NotFound -or $ws.Error -match 'Bad Request|MethodNotAllowed|NotSupported')) {
        $coverage.Add([pscustomobject][ordered]@{ instance = $Apim; collection = 'workspaces'; status = 'failed'; count = 0; error = $ws.Error })
        Write-Warning "[$Apim] could not enumerate workspaces ($($ws.Error))"
    }

    return @{ instance = [pscustomobject]$instanceInfo; items = $items; coverage = $coverage }
}

# ---------------------------------------------------------------- main
$account = Initialize-AzCli

$targets = @()
if ($AllSubscriptions) {
    $subs = Invoke-AzCli -Arguments @('account', 'list', '--query', '[?state==`Enabled`].id', '-o', 'json')
    $subIds = @($subs.Stdout | ConvertFrom-Json)
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
    $a = @('apim', 'list', '--subscription', $sid, '-o', 'json')
    if ($ResourceGroup) { $a += @('--resource-group', $ResourceGroup) }
    $r = Invoke-AzCli -Arguments $a
    if ($r.ExitCode -ne 0) {
        Write-Warning "Could not list APIM in subscription $sid ($($r.Error))"
        $globalCoverage.Add([pscustomobject][ordered]@{ instance = $null; collection = "apim-list:$sid"; status = 'failed'; count = 0; error = $r.Error })
        continue
    }
    foreach ($s in @($r.Stdout | ConvertFrom-Json)) { $targets += [pscustomobject]@{ sub = $sid; rg = $s.resourceGroup; name = $s.name } }
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

$failed = @($allCoverage | Where-Object status -In 'failed', 'not-scanned', 'skipped')
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
    }
    summary  = [ordered]@{
        coverageComplete = ($failed.Count -eq 0)
        totalItems       = $allItems.Count
        autoRotatable    = @($allItems | Where-Object action -EQ 'auto').Count
        manual           = @($allItems | Where-Object action -EQ 'manual').Count
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
            default { $i.displayName }
        } } } | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host ("Items: {0} (auto: {1}, manual: {2})" -f $inventory.summary.totalItems, $inventory.summary.autoRotatable, $inventory.summary.manual)
if ($failed) { Write-Warning "Coverage INCOMPLETE: $($failed.Count) collection(s) failed. See 'coverage' in $OutFile." }
Write-Host "Inventory written to $OutFile (no secret values included)." -ForegroundColor Green
