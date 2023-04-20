#------------------------------------------------------------------------------  
#  
# Copyright 2023 Microsoft Corporation.  All rights reserved.  
#  
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
# We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code 
# form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in 
# which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is 
# embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#  
#------------------------------------------------------------------------------ 

<#
.DESCRIPTION
Report on permissions assigned to a System-Assigned Managed Identity in an Azure Active Directory tenant.
.NOTES
Version:        0.1
Author:         Tim Haintz - Senior Customer Experience Engineer - Security CxE.                                        
Creation Date:  15/03/2023
.LINK
https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions?pivots=ms-powershell
https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/accessing-microsoft-graph-data-with-powershell/ba-p/3741077
https://learn.microsoft.com/en-us/powershell/microsoftgraph/find-mg-graph-permission?view=graph-powershell-1.0
https://learn.microsoft.com/en-us/powershell/microsoftgraph/find-mg-graph-command?view=graph-powershell-1.0
.EXAMPLE
Get-THManagedIdentityPermission -tenantId '<AzureAD TENANT ID>'
.EXAMPLE
Get-THManagedIdentityPermission -tenantId '<AzureAD TENANT ID>' -HTML | Out-File -FilePath 'C:\Temp\ManagedIdentityPermissionReport.html'
.EXAMPLE
Get-THManagedIdentityPermission -tenantId '<AzureAD TENANT ID>' -JSON
#>
function Get-THManagedIdentityPermission
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$tenantId, #Azure Active Directory Tenant ID
        [Parameter(Mandatory=$false)]
        [switch]$HTML,
        [Parameter(Mandatory=$false)]
        [switch]$JSON
    )
    $css = 
    @"
    <style>
        body {
            font-family: Arial;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            border: 1px solid black;
        }
        th, td {
            text-align: left;
            padding: 8px;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
    </style>
"@
    $preContent = @"
    <h2>Managed Identity Permission Report</h2>
    <p>The report below shows the assigned permissions to Managed Identities</p>
"@
    #Below scopes are needed to view permissions correctly as per https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions?pivots=ms-powershell
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -TenantId $tenantId | Out-Null
    $miServicePrincipals = Get-MgServicePrincipal -Filter "ServicePrincipalType eq 'ManagedIdentity'"
    #Use the Id from the output of the above $miServicePrincipals for the appropriate Service Principal
    ##The Id from the previous cmdlet is then used as the -ServicePrincipalId in the below cmdlet
    #The below OAuth2 cmdlet may be empty
    $output = @()
    foreach ($miServicePrincipal in $miServicePrincipals)
    {
        #Need to test if the below $spOAuth2PermissionsGrants is needed. Need to setup and test.
        $spOAuth2PermissionsGrants = Get-MgOauth2PermissionGrant -All| Where-Object { $_.clientId -eq $miServicePrincipal.Id }
        #Get the application permissions that have been granted. Returned AppRoleId is used to compare in foreach loop. 
        $spApplicationPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miServicePrincipal.Id -All
        #$findMgGraphPermissions is the list of permissions avaiable. Used to compare what has been granted to what is available in the foreach loop.
        $findMgGraphPermissions = Find-MgGraphPermission
        foreach ($spApplicationPermission in $spApplicationPermissions) 
        {
            foreach ($findMgGraphPermission in $findMgGraphPermissions) 
            {
                if($spApplicationPermission.approleid -eq $findMgGraphPermission.id)
                {
                    $output += [PSCustomObject]@{
                        ServicePrincipalName = $miServicePrincipal.DisplayName
                        ServicePrincipalId = $miServicePrincipal.Id
                        Permission = $findMgGraphPermission.Name
                        ResourceName = $spApplicationPermission.ResourceDisplayName
                        DateCollected = Get-Date -Format yyyyMMdd
                    }
                }
            }
        }
    }
    if ($HTML)
    {
        $output | ConvertTo-Html -As Table -PreContent $preContent -head $css -PostContent "<p>HTML report generated on $(Get-Date)</p>"
    }
    elseif ($JSON)
    {
        $output | ConvertTo-Json
    }
    else
    {
        $output
    }
}