# Azure API Management – Rotating Credentials

PowerShell 7 + Azure CLI scripts to **discover** every credential stored in or exposed by an
Azure API Management (APIM) instance and **rotate** the ones that can be rotated automatically,
following Microsoft's guidance in
[Rotating credentials in Azure API Management](https://techcommunity.microsoft.com/blog/integrationsonazureblog/rotating-credentials-in-azure-api-management/4575478).

Inspired by cmendible's gist
[Discover and rotate Azure API Management credentials with az cli](https://gist.github.com/cmendible/6783ab574038e2abf64a83b47a041152).

> **Secret safety:** no script ever prints or writes a secret value. Inventories, reports and
> feedback files contain only resource identifiers, metadata and booleans.

## Files

| File | Purpose |
| --- | --- |
| `Get-ApimCredentials.ps1` | Read-only discovery. Writes a JSON inventory of affected items. |
| `Invoke-ApimCredentialRotation.ps1` | Rotates the auto-rotatable items in the inventory. Dry-run by default. |
| `ApimCredentials.Common.psm1` | Shared helpers (ARM HTTP client, token, paging, parallel GETs, feedback). |

## Requirements

- PowerShell 7.2+ (`pwsh`)
- Azure CLI (`az`), signed in with `az login`
- Permissions on the APIM instance: Reader for discovery; API Management Service Contributor
  (or equivalent) for rotation. `-Verify` also needs the `listSecrets` / `listKeys` / `listValue` actions.

## How it works (performance)

The Azure CLI is used only to read the signed-in account and obtain an ARM access token
(`az account get-access-token`). Every ARM call is then sent directly from PowerShell through a
single reused `HttpClient`, and read-only GETs (collections, operations, policies) run concurrently.
Each call takes milliseconds instead of the seconds needed to start an `az rest` process, so a
discovery that took minutes now finishes in seconds. The token is refreshed automatically and is never
written or printed. Transient errors (429, 5xx) are retried for reads only, honouring `Retry-After`;
mutations are never retried.

Use `-ThrottleLimit` (default 16) on `Get-ApimCredentials.ps1` to change the number of concurrent
requests, for example lower it if ARM starts throttling.

## Step-by-step guide

### Step 1 – Install the prerequisites

```powershell
winget install Microsoft.PowerShell      # PowerShell 7 (Windows; see docs for macOS/Linux)
winget install Microsoft.AzureCLI        # Azure CLI
```

Open a new **PowerShell 7** terminal (`pwsh`) after installing.

### Step 2 – Get the scripts

```powershell
git clone https://github.com/heblasco/AzureAPIMRotatingCredentials.git
cd AzureAPIMRotatingCredentials
```

On Windows, if the execution policy blocks the scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Get-ChildItem *.ps1, *.psm1 | Unblock-File
```

### Step 3 – Sign in to Azure

```powershell
az login
az account set --subscription "<subscription-name-or-id>"
az account show --query "{subscription:name, user:user.name}" -o table
```

### Step 4 – Discover affected credentials (read-only)

```powershell
./Get-ApimCredentials.ps1 -ResourceGroup <resource-group> -Name <apim-name>
```

This writes `apim-credentials-inventory.json`. Nothing is changed in Azure.

### Step 5 – Review the inventory

```powershell
$inv = Get-Content ./apim-credentials-inventory.json -Raw | ConvertFrom-Json
$inv.summary                                              # totals and coverageComplete
$inv.items | Format-Table type, id, action, note -Wrap    # what was found
$inv.coverage | Where-Object status -ne 'ok'              # anything not fully scanned
```

- `action = auto` items will be rotated by the next script.
- `action = manual` items (backends, IdP secrets, loggers, certificates, policies…) must be rotated
  by hand following the `note` of each item.
- If `summary.coverageComplete` is `false`, check `coverage` before trusting the result.

### Step 6 – Dry-run the rotation

```powershell
./Invoke-ApimCredentialRotation.ps1 -InventoryFile ./apim-credentials-inventory.json -Incident
```

Shows exactly what would be rotated. Nothing is changed. Drop `-Incident` to preview a planned
(secondary-key only) rotation instead.

### Step 7 – Provide new values for secret named values (only if listed)

Items of type `named-value-secret` need the new value you obtained from the issuer. Either set an
environment variable before running (name = `APIM_NV_` + ID in upper case, non-alphanumerics as `_`):

```powershell
$env:APIM_NV_API_KEY = Read-Host 'New value for api-key' -MaskInput
```

or let the script prompt for it securely. For Key Vault-backed named values, rotate the secret in
Key Vault **first**; the script then refreshes APIM.

### Step 8 – Rotate

```powershell
# Incident (credentials compromised): both keys, including 'master'
./Invoke-ApimCredentialRotation.ps1 -InventoryFile ./apim-credentials-inventory.json -Incident -Apply -Verify

# Planned rotation instead: secondary key only (repeat later with -Key Primary)
./Invoke-ApimCredentialRotation.ps1 -InventoryFile ./apim-credentials-inventory.json -Apply -Verify
```

Answer `Y` when asked to confirm (or add `-Force` for unattended runs).

### Step 9 – Check the results

```powershell
Import-Csv ./apim-rotation-feedback-*.csv | Format-Table instance, type, id, changed, detail -Wrap
```

- `changed = Yes` → rotated and verified.
- Anything else → see `detail`, and `unremediated` in the JSON report.
- Exit code `0` means success; `1` means something failed, was partial or could not be verified.

### Step 10 – Finish the remediation

1. Distribute the new keys to legitimate callers and test your APIs.
2. Revoke the old credentials at their issuers (Key Vault versions, backends, IdP secrets…).
3. Rotate the `manual` items.
4. Run Step 4 again to confirm the final state.

## 1. Discover affected credentials

```powershell
# One instance
./Get-ApimCredentials.ps1 -ResourceGroup my-rg -Name my-apim

# Every APIM in a subscription / in every subscription you can see
./Get-ApimCredentials.ps1 -SubscriptionId <subscription-id>
./Get-ApimCredentials.ps1 -AllSubscriptions -OutFile all.json

# Faster: skip per-operation policies (coverage is then reported as incomplete)
./Get-ApimCredentials.ps1 -ResourceGroup my-rg -Name my-apim -SkipOperationPolicies
```

Output: `apim-credentials-inventory.json`

```text
{ metadata, summary { coverageComplete, totalItems, autoRotatable, manual, byType }, coverage[], items[] }
```

What is scanned (API version `2024-05-01`):

| Area | Item type | Action |
| --- | --- | --- |
| Subscriptions (incl. built-in `master`) | `subscription-key` | auto |
| Direct management API (`tenant/access`) | `tenant-access` | auto |
| Self-hosted gateways | `gateway-key` | auto |
| Named values backed by Key Vault | `named-value-kv` | auto (refresh after rotating in Key Vault) |
| Secret named values stored in APIM | `named-value-secret` | auto (you supply the new value) |
| Plain-text named values that look like secrets | `named-value-plain` | manual |
| Backends (credentials, headers, query, proxy auth, client certificates) | `backend` | manual |
| OAuth 2.0 / OpenID Connect servers, identity providers, credential manager | `oauth2-server`, `oidc-provider`, `identity-provider`, `credential-manager` | manual |
| Loggers (Application Insights, Event Hubs), external caches | `logger`, `external-cache` | manual |
| Certificates | `certificate` | manual |
| Global, product, API and operation policies, policy fragments | `policy` (literal secret detected), `policy-review` (keywords only) | manual review (heuristic) |
| Workspaces | coverage only | reported as `not-scanned` (inventory marked incomplete) |

Every collection is listed in `coverage`. If anything could not be enumerated (or was skipped),
`summary.coverageComplete` is `false`. Policy detection is heuristic and reports only line numbers
and rule names, never policy content.

## 2. Rotate

```powershell
# Dry-run (default): shows what would change, changes nothing
./Invoke-ApimCredentialRotation.ps1 -InventoryFile apim-credentials-inventory.json

# Planned rotation: regenerate only the secondary key, skip 'master'
./Invoke-ApimCredentialRotation.ps1 -InventoryFile apim-credentials-inventory.json -Apply -Verify

# Incident (keys compromised): regenerate BOTH keys, include 'master'
./Invoke-ApimCredentialRotation.ps1 -InventoryFile apim-credentials-inventory.json -Incident -Apply -Verify
```

| Parameter | Description |
| --- | --- |
| `-Apply` | Actually perform changes (asks for confirmation unless `-Force`). |
| `-Incident` | Rotate both keys and include `master`. All callers using old keys break immediately. |
| `-Key Primary\|Secondary\|Both` | Keys to regenerate in planned mode (default `Secondary`). |
| `-IncludeMaster` | Include the built-in `master` subscription in planned mode. |
| `-Types` | Limit to some item types. |
| `-Instance`, `-Id` | Limit to an instance and/or item IDs. |
| `-Verify` | After each change, compare in-memory SHA-256 hashes of the secrets to prove they changed. |
| `-AllowPinnedRefresh` | Refresh Key Vault named values pinned to a specific secret version. |
| `-NonInteractive` | Never prompt for new named-value values (use env vars instead). |
| `-ReportFile` | Detailed JSON report (default `apim-rotation-report-<timestamp>.json`). |
| `-FeedbackFile` | Per-item CSV summary (default derived from `-ReportFile`). |

New values for `named-value-secret` items are read from the environment variable
`APIM_NV_<ID>` (upper case, non-alphanumeric characters replaced by `_`) or prompted securely.
They are sent to ARM directly from memory over TLS; nothing is written to disk.

### Outputs

- **Report (JSON):** `metadata`, `summary` (rotated, skipped, failed, verificationFailed,
  unremediated, issuerRevocationsPending, `remediationComplete`), `results`, `unremediated`, `nextSteps`.
- **Feedback (CSV):** one row per inventory item, saying whether it changed:

```csv
"instance","type","id","changed","status","keysChanged","verified","detail"
"my-apim","subscription-key","master","Yes","rotated","primary+secondary","True","OK"
"my-apim","backend","my-backend","No","manual","",,"manual rotation required"
```

`changed` is one of `Yes`, `Partial` (only one key regenerated), `Unverified` (applied but
`-Verify` could not confirm), `No` (failed, manual or not selected) or `No (dry-run)`.

`remediationComplete` is `true` only when changes were applied, inventory coverage was complete,
nothing is left unremediated and no issuer revocation is pending.

Exit codes: `0` success, `1` failures / partial rotation / verification failed, `2` cancelled.

## After rotating

1. Distribute the new subscription keys to legitimate callers and test your APIs.
2. Revoke the **old** credentials at each issuer (Key Vault secret versions, backend systems,
   identity provider client secrets, Event Hubs / Redis keys). Updating APIM does not revoke them.
3. Rotate the manual items listed in `unremediated`, following the note on each item.
4. Re-run `Get-ApimCredentials.ps1` and review subscriptions, users, policies and backends you did not create.

## Disclaimer

Rotation is disruptive by design. Always run a dry-run first and test in a non-production
instance. Provided as-is under the [MIT License](LICENSE).
