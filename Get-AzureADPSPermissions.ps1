<# 
.SYNOPSIS
    Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

.PARAMETER DelegatedPermissions
    If set, will return delegated permissions. If neither this switch nor the ApplicationPermissions switch is set,
    both application and delegated permissions will be returned.

.PARAMETER ApplicationPermissions
    If set, will return application permissions. If neither this switch nor the DelegatedPermissions switch is set,
    both application and delegated permissions will be returned.

.PARAMETER ShowProgress
    Whether or not to display a progress bar when retrieving application permissions (which could take some time).

.PARAMETER PrecacheSize
    The number of users to pre-load into a cache. For tenants with over a thousand users,
    increasing this may improve performance of the script.

.EXAMPLE
    PS C:\> .\Get-AzureADPSPermissions.ps1 | Export-Csv -Path "permissions.csv" -NoTypeInformation
    Generates a CSV report of all permissions granted to all apps.

.EXAMPLE
    PS C:\> .\Get-AzureADPSPermissions.ps1 -ApplicationPermissions -ShowProgress | Where-Object { $_.Permission -eq "Directory.Read.All" }
    Get all apps which have application permissions for Directory.Read.All.
#>

[CmdletBinding()]
param(
    [switch] $DelegatedPermissions,

    [switch] $ApplicationPermissions,

    [switch] $ShowProgress,

    [int] $PrecacheSize = 999
)

# Get tenant details to test that Connect-AzureAD has been called
try {
    $tenant_details = Get-AzureADTenantDetail
} catch {
    throw "You must call Connect-AzureAD before running this script."
}
Write-Verbose ("TenantId: {0}, InitialDomain: {1}" -f `
                $tenant_details.ObjectId, `
                ($tenant_details.VerifiedDomains | Where-Object { $_.Initial }).Name)

# An in-memory cache of objects by {object ID} andy by {object class, object ID} 
$script:ObjectByObjectId = @{}
$script:ObjectByObjectClassId = @{}

# Function to add an object to the cache
function CacheObject($Object) {
    if ($Object) {
        if (-not $script:ObjectByObjectClassId.ContainsKey($Object.ObjectType)) {
            $script:ObjectByObjectClassId[$Object.ObjectType] = @{}
        }
        $script:ObjectByObjectClassId[$Object.ObjectType][$Object.ObjectId] = $Object
        $script:ObjectByObjectId[$Object.ObjectId] = $Object
    }
}

# Function to retrieve an object from the cache (if it's there), or from Azure AD (if not).
function GetObjectByObjectId($ObjectId) {
    if (-not $script:ObjectByObjectId.ContainsKey($ObjectId)) {
        Write-Verbose ("Querying Azure AD for object '{0}'" -f $ObjectId)
        try {
            $object = Get-AzureADObjectByObjectId -ObjectId $ObjectId
            CacheObject -Object $object
        } catch { 
            Write-Verbose "Object not found."
        }
    }
    return $script:ObjectByObjectId[$ObjectId]
}

# Get all ServicePrincipal objects and add to the cache
Write-Verbose "Retrieving ServicePrincipal objects..."
Get-AzureADServicePrincipal -All $true | Where-Object {
    CacheObject -Object $_
}

if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

    # Get one page of User objects and add to the cache
    Write-Verbose "Retrieving User objects..."
    Get-AzureADUser -Top $PrecacheSize | Where-Object {
        CacheObject -Object $_
    }

    # Get all existing OAuth2 permission grants, get the client, resource and scope details
    Write-Verbose "Retrieving OAuth2PermissionGrants..."
    Get-AzureADOAuth2PermissionGrant -All $true | ForEach-Object {
        $grant = $_
        if ($grant.Scope) {
            $grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {
                
                $scope = $_

                $client = GetObjectByObjectId -ObjectId $grant.ClientId
                $resource = GetObjectByObjectId -ObjectId $grant.ResourceId
                $principalDisplayName = ""
                if ($grant.PrincipalId) {
                    $principal = GetObjectByObjectId -ObjectId $grant.PrincipalId
                    $principalDisplayName = $principal.DisplayName
                }

                New-Object PSObject -Property ([ordered]@{
                    "PermissionType" = "Delegated"
                                    
                    "ClientObjectId" = $grant.ClientId
                    "ClientDisplayName" = $client.DisplayName
                    
                    "ResourceObjectId" = $grant.ResourceId
                    "ResourceDisplayName" = $resource.DisplayName
                    "Permission" = $scope

                    "ConsentType" = $grant.ConsentType
                    "PrincipalObjectId" = $grant.PrincipalId
                    "PrincipalDisplayName" = $principalDisplayName
                })
            }
        }
    }
}

if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

    # Iterate over all ServicePrincipal objects and get app permissions
    Write-Verbose "Retrieving AppRoleAssignments..."
    $servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count
    $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {
        
        if ($ShowProgress) {
            Write-Progress -Activity "Retrieving application permissions..." `
                        -Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
                        -PercentComplete (($i / $servicePrincipalCount) * 100)
        }

        $client = $_.Value
        
        Get-AzureADServiceAppRoleAssignedTo -ObjectId $client.ObjectId -All $true `
        | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {
            $assignment = $_

            $resource = GetObjectByObjectId -ObjectId $assignment.ResourceId
            $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

            New-Object PSObject -Property ([ordered]@{
                "PermissionType" = "Application"
                
                "ClientObjectId" = $assignment.PrincipalId
                "ClientDisplayName" = $client.DisplayName
                
                "ResourceObjectId" = $assignment.ResourceId
                "ResourceDisplayName" = $resource.DisplayName
                "Permission" = $appRole.Value
            })
        }
    }
}