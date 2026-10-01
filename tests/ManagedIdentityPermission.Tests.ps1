$ErrorActionPreference = 'Stop'

# All Graph commands are local mocks. This test never connects to a tenant.
$script:connectedScopes = @()
$script:servicePrincipals = @(1..105 | ForEach-Object {
    [PSCustomObject]@{ Id = "managed-identity-$_"; DisplayName = "Managed identity $_" }
})

function Connect-MgGraph {
    param($Scopes, $TenantId)
    $script:connectedScopes = @($Scopes)
    if ($TenantId -ne 'offline-test-tenant') { throw 'Unexpected tenant.' }
}

function Get-MgServicePrincipal {
    param($Filter, [switch]$All)
    if ($Filter -ne "ServicePrincipalType eq 'ManagedIdentity'") { throw 'Unexpected filter.' }
    if ($All) { return $script:servicePrincipals }
    return @($script:servicePrincipals | Select-Object -First 100)
}

function Get-MgOauth2PermissionGrant { return @() }

function Get-MgServicePrincipalAppRoleAssignment {
    param($ServicePrincipalId, [switch]$All)
    if (-not $All) { throw 'App role assignments must include all pages.' }
    [PSCustomObject]@{ AppRoleId = 'permission-id'; ResourceDisplayName = 'Microsoft Graph' }
}

function Find-MgGraphPermission {
    [PSCustomObject]@{ Id = 'permission-id'; Name = 'Application.Read.All' }
}

. (Join-Path $PSScriptRoot '../Get-THManagedIdentitityPermission.ps1')

$report = @(Get-THManagedIdentityPermission -tenantId 'offline-test-tenant')
if ($report.Count -ne 105) { throw "Expected 105 identities, got $($report.Count)." }
if ($report[-1].ServicePrincipalId -ne 'managed-identity-105') { throw 'The last page is missing.' }
if ($script:connectedScopes.Count -ne 1 -or $script:connectedScopes[0] -ne 'Application.Read.All') {
    throw 'The report must connect using only Application.Read.All.'
}

# Any remaining OAuth grant lookup is unnecessary for this report.
function Get-MgOauth2PermissionGrant { throw 'Unexpected unused OAuth grant query.' }

$json = Get-THManagedIdentityPermission -tenantId 'offline-test-tenant' -JSON | ConvertFrom-Json
if (@($json).Count -ne 105) { throw 'JSON output omitted identities.' }
$html = Get-THManagedIdentityPermission -tenantId 'offline-test-tenant' -HTML | Out-String
if ($html -notmatch 'managed-identity-105') { throw 'HTML output omitted the last identity.' }

Write-Output 'PASS: all 105 identities, read-only scope, native/JSON/HTML output, no OAuth grant query.'
