<# 
.SYNOPSIS
Exports Active Directory group access for one or more users.

.DESCRIPTION
Fetches group memberships for a single user or a list of users, then writes CSV output for:

1. UserGroupMembership.csv - one row per user/group association.
2. CombinedGroupAccess.csv - de-duplicated group list across all supplied users.
3. UserLookupStatus.csv - lookup and processing status per input user.
4. PerUser/*.csv - one CSV per resolved user.

By default, the script includes nested group access by walking parent group memberships.
Use -DirectOnly when you only want groups directly assigned to the user.

.PARAMETER Users
One or more user identities. SamAccountName, distinguished name, GUID, SID, UPN, and mail are supported.

.PARAMETER UserListPath
Path to a TXT file with one user per line, or a CSV file containing a user column.

.PARAMETER UserColumn
CSV column name to read from UserListPath. Defaults to "User".

.PARAMETER OutputFolder
Folder where CSV outputs will be written.

.PARAMETER DirectOnly
Only export direct group memberships. Without this switch, nested parent groups are included.

.PARAMETER Server
Optional domain controller or AD LDS server to query.

.PARAMETER Credential
Optional credential for Active Directory queries.

.EXAMPLE
.\Export-AdUserGroupAccess.ps1 -Users jdoe

.EXAMPLE
.\Export-AdUserGroupAccess.ps1 -Users jdoe,asmith -OutputFolder C:\Temp\AdAccess

.EXAMPLE
.\Export-AdUserGroupAccess.ps1 -UserListPath .\users.csv -UserColumn SamAccountName

.EXAMPLE
.\Export-AdUserGroupAccess.ps1 -UserListPath .\users.txt -DirectOnly
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('User', 'Identity')]
    [string[]]$Users,

    [Parameter(Mandatory = $false)]
    [string]$UserListPath,

    [Parameter(Mandatory = $false)]
    [string]$UserColumn = 'User',

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = (Join-Path -Path $PSScriptRoot -ChildPath 'ad-group-access-output'),

    [Parameter(Mandatory = $false)]
    [switch]$DirectOnly,

    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UserProperties = @(
    'DisplayName',
    'Mail',
    'UserPrincipalName',
    'SamAccountName',
    'DistinguishedName',
    'Enabled',
    'ObjectGUID',
    'SID',
    'PrimaryGroupID'
)

$script:GroupProperties = @(
    'Mail',
    'Description',
    'GroupCategory',
    'GroupScope',
    'ObjectGUID',
    'SID',
    'SamAccountName',
    'DistinguishedName'
)

$script:GroupCache = @{}

function New-AdCommandParameters {
    $params = @{}

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $params['Server'] = $Server
    }

    if ($null -ne $Credential) {
        $params['Credential'] = $Credential
    }

    return $params
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $false)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-TextValue {
    param(
        [Parameter(Mandatory = $false)]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [array]) {
        return (($Value | ForEach-Object { ConvertTo-TextValue -Value $_ }) -join '; ')
    }

    $valueProperty = $Value.PSObject.Properties['Value']
    if ($null -ne $valueProperty) {
        return [string]$valueProperty.Value
    }

    return [string]$Value
}

function ConvertTo-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $escaped = $Value
    $escaped = $escaped.Replace('\', '\5c')
    $escaped = $escaped.Replace('*', '\2a')
    $escaped = $escaped.Replace('(', '\28')
    $escaped = $escaped.Replace(')', '\29')
    $escaped = $escaped.Replace([string][char]0, '\00')

    return $escaped
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $safeName = [regex]::Replace($Value, '[\\/:*?"<>|]+', '_').Trim()

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'user'
    }

    if ($safeName.Length -gt 100) {
        $safeName = $safeName.Substring(0, 100)
    }

    return $safeName
}

function Import-UserIdentities {
    $rawIdentities = [System.Collections.Generic.List[string]]::new()

    if ($Users) {
        foreach ($user in $Users) {
            if (-not [string]::IsNullOrWhiteSpace($user)) {
                $rawIdentities.Add($user.Trim()) | Out-Null
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($UserListPath)) {
        if (-not (Test-Path -LiteralPath $UserListPath -PathType Leaf)) {
            throw "User list file was not found: $UserListPath"
        }

        $resolvedPath = (Resolve-Path -LiteralPath $UserListPath).Path
        $extension = [System.IO.Path]::GetExtension($resolvedPath)

        if ($extension -ieq '.csv') {
            $rows = @(Import-Csv -LiteralPath $resolvedPath)
            if ($rows.Count -eq 0) {
                throw "CSV user list has no data rows: $resolvedPath"
            }

            $columns = @($rows[0].PSObject.Properties.Name)
            $selectedColumn = $UserColumn

            if ($columns -notcontains $selectedColumn) {
                if ($columns.Count -eq 1) {
                    $selectedColumn = $columns[0]
                    Write-Warning "Column '$UserColumn' was not found. Using the only CSV column '$selectedColumn'."
                }
                else {
                    throw "CSV user list does not contain column '$UserColumn'. Available columns: $($columns -join ', ')"
                }
            }

            foreach ($row in $rows) {
                $value = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $row -Name $selectedColumn)
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $rawIdentities.Add($value.Trim()) | Out-Null
                }
            }
        }
        else {
            foreach ($line in Get-Content -LiteralPath $resolvedPath) {
                $value = $line.Trim()
                if (-not [string]::IsNullOrWhiteSpace($value) -and -not $value.StartsWith('#')) {
                    $rawIdentities.Add($value) | Out-Null
                }
            }
        }
    }

    if ($rawIdentities.Count -eq 0) {
        throw 'Provide at least one user through -Users or -UserListPath.'
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $distinctIdentities = [System.Collections.Generic.List[string]]::new()

    foreach ($identity in $rawIdentities) {
        if ($seen.Add($identity)) {
            $distinctIdentities.Add($identity) | Out-Null
        }
    }

    return @($distinctIdentities)
}

function Resolve-AdUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    $adParams = New-AdCommandParameters
    $identityLookupError = $null

    try {
        return Get-ADUser -Identity $Identity -Properties $script:UserProperties @adParams
    }
    catch {
        $identityLookupError = $_.Exception.Message
    }

    $lookupValue = $Identity
    if ($Identity -match '^[^\\]+\\(.+)$') {
        $lookupValue = $Matches[1]
    }

    $escapedValue = ConvertTo-LdapFilterValue -Value $lookupValue
    $ldapFilter = "(|(sAMAccountName=$escapedValue)(userPrincipalName=$escapedValue)(mail=$escapedValue))"
    $matches = @(Get-ADUser -LDAPFilter $ldapFilter -Properties $script:UserProperties @adParams)

    if ($matches.Count -eq 1) {
        return $matches[0]
    }

    if ($matches.Count -gt 1) {
        $matchedUsers = (($matches | Select-Object -ExpandProperty SamAccountName) -join ', ')
        throw "Multiple AD users matched '$Identity': $matchedUsers"
    }

    throw "User was not found: $Identity. Identity lookup error: $identityLookupError"
}

function Get-PrimaryGroupForUser {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    $sidValue = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'SID')
    $primaryGroupId = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'PrimaryGroupID')

    if ([string]::IsNullOrWhiteSpace($sidValue) -or [string]::IsNullOrWhiteSpace($primaryGroupId)) {
        return $null
    }

    $domainSid = $sidValue -replace '-\d+$', ''
    $primaryGroupSid = "$domainSid-$primaryGroupId"
    $adParams = New-AdCommandParameters

    try {
        return Get-ADGroup -Identity $primaryGroupSid -Properties $script:GroupProperties @adParams
    }
    catch {
        Write-Warning "Could not resolve primary group SID '$primaryGroupSid' for user '$($User.SamAccountName)': $($_.Exception.Message)"
        return $null
    }
}

function Get-GroupDetails {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group
    )

    $groupDn = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $Group -Name 'DistinguishedName')
    if ([string]::IsNullOrWhiteSpace($groupDn)) {
        return $Group
    }

    if ($script:GroupCache.ContainsKey($groupDn)) {
        return $script:GroupCache[$groupDn]
    }

    $adParams = New-AdCommandParameters

    try {
        $details = Get-ADGroup -Identity $groupDn -Properties $script:GroupProperties @adParams
    }
    catch {
        Write-Warning "Could not enrich group '$groupDn': $($_.Exception.Message)"
        $details = $Group
    }

    $script:GroupCache[$groupDn] = $details
    return $details
}

function Get-UserGroupMembershipItems {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    $adParams = New-AdCommandParameters
    $seenGroupDns = @{}
    $items = [System.Collections.Generic.List[object]]::new()
    $queue = [System.Collections.Generic.Queue[object]]::new()

    $directGroups = @(Get-ADPrincipalGroupMembership -Identity $User @adParams)
    $primaryGroup = Get-PrimaryGroupForUser -User $User

    if ($null -ne $primaryGroup) {
        $directGroups += $primaryGroup
    }

    foreach ($group in $directGroups) {
        $queue.Enqueue([pscustomobject]@{
                Group          = $group
                MembershipType = 'Direct'
                NestingLevel   = 0
                MembershipPath = (ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'Name'))
            })
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $groupDn = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $item.Group -Name 'DistinguishedName')

        if ([string]::IsNullOrWhiteSpace($groupDn)) {
            continue
        }

        if ($seenGroupDns.ContainsKey($groupDn)) {
            continue
        }

        $seenGroupDns[$groupDn] = $true
        $items.Add($item) | Out-Null

        if ($DirectOnly) {
            continue
        }

        try {
            $parentGroups = @(Get-ADPrincipalGroupMembership -Identity $item.Group @adParams)
        }
        catch {
            Write-Warning "Could not fetch parent groups for '$groupDn': $($_.Exception.Message)"
            $parentGroups = @()
        }

        foreach ($parentGroup in $parentGroups) {
            $parentDn = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $parentGroup -Name 'DistinguishedName')
            if ([string]::IsNullOrWhiteSpace($parentDn) -or $seenGroupDns.ContainsKey($parentDn)) {
                continue
            }

            $parentName = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $parentGroup -Name 'Name')
            $membershipPath = if ([string]::IsNullOrWhiteSpace($item.MembershipPath)) {
                $parentName
            }
            else {
                '{0} > {1}' -f $item.MembershipPath, $parentName
            }

            $queue.Enqueue([pscustomobject]@{
                    Group          = $parentGroup
                    MembershipType = 'Nested'
                    NestingLevel   = ($item.NestingLevel + 1)
                    MembershipPath = $membershipPath
                })
        }
    }

    return @($items)
}

function New-MembershipOutputRow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputIdentity,

        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [object]$MembershipItem
    )

    $group = Get-GroupDetails -Group $MembershipItem.Group

    [pscustomobject]@{
        InputIdentity        = $InputIdentity
        UserSamAccountName   = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'SamAccountName')
        UserPrincipalName    = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'UserPrincipalName')
        UserDisplayName      = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'DisplayName')
        UserEnabled          = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'Enabled')
        UserMail             = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'Mail')
        UserDistinguishedName = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $User -Name 'DistinguishedName')
        MembershipType       = $MembershipItem.MembershipType
        NestingLevel         = $MembershipItem.NestingLevel
        MembershipPath       = $MembershipItem.MembershipPath
        GroupName            = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'Name')
        GroupSamAccountName  = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'SamAccountName')
        GroupCategory        = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'GroupCategory')
        GroupScope           = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'GroupScope')
        GroupMail            = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'Mail')
        GroupDescription     = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'Description')
        GroupSID             = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'SID')
        GroupObjectGuid      = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'ObjectGUID')
        GroupDistinguishedName = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $group -Name 'DistinguishedName')
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

$outputRoot = if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    Join-Path -Path $PSScriptRoot -ChildPath 'ad-group-access-output'
}
else {
    $OutputFolder
}

$null = New-Item -Path $outputRoot -ItemType Directory -Force
$perUserFolder = Join-Path -Path $outputRoot -ChildPath 'PerUser'
$null = New-Item -Path $perUserFolder -ItemType Directory -Force

$membershipCsv = Join-Path -Path $outputRoot -ChildPath 'UserGroupMembership.csv'
$combinedCsv = Join-Path -Path $outputRoot -ChildPath 'CombinedGroupAccess.csv'
$statusCsv = Join-Path -Path $outputRoot -ChildPath 'UserLookupStatus.csv'

$inputIdentities = Import-UserIdentities
$allMembershipRows = [System.Collections.Generic.List[object]]::new()
$statusRows = [System.Collections.Generic.List[object]]::new()

foreach ($identity in $inputIdentities) {
    Write-Host "Processing $identity ..."

    try {
        $user = Resolve-AdUser -Identity $identity
        $membershipItems = @(Get-UserGroupMembershipItems -User $user)

        foreach ($membershipItem in $membershipItems) {
            $allMembershipRows.Add((New-MembershipOutputRow -InputIdentity $identity -User $user -MembershipItem $membershipItem)) | Out-Null
        }

        $directCount = @($membershipItems | Where-Object { $_.MembershipType -eq 'Direct' }).Count
        $nestedCount = @($membershipItems | Where-Object { $_.MembershipType -eq 'Nested' }).Count

        $statusRows.Add([pscustomobject]@{
                InputIdentity      = $identity
                Status             = 'Found'
                UserSamAccountName = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $user -Name 'SamAccountName')
                UserPrincipalName  = ConvertTo-TextValue -Value (Get-ObjectPropertyValue -InputObject $user -Name 'UserPrincipalName')
                Message            = $null
                GroupCount         = $membershipItems.Count
                DirectGroupCount   = $directCount
                NestedGroupCount   = $nestedCount
            }) | Out-Null
    }
    catch {
        $statusRows.Add([pscustomobject]@{
                InputIdentity      = $identity
                Status             = 'Error'
                UserSamAccountName = $null
                UserPrincipalName  = $null
                Message            = $_.Exception.Message
                GroupCount         = 0
                DirectGroupCount   = 0
                NestedGroupCount   = 0
            }) | Out-Null

        Write-Warning "Failed to process '$identity': $($_.Exception.Message)"
    }
}

$sortedMembershipRows = @($allMembershipRows | Sort-Object UserSamAccountName, NestingLevel, GroupName, GroupDistinguishedName)
$sortedMembershipRows | Export-Csv -Path $membershipCsv -NoTypeInformation -Encoding UTF8

foreach ($userGroup in ($sortedMembershipRows | Group-Object UserSamAccountName)) {
    $safeUserName = ConvertTo-SafeFileName -Value $userGroup.Name
    $perUserCsv = Join-Path -Path $perUserFolder -ChildPath "$safeUserName-groups.csv"
    $userGroup.Group | Sort-Object NestingLevel, GroupName, GroupDistinguishedName | Export-Csv -Path $perUserCsv -NoTypeInformation -Encoding UTF8
}

$combinedRows = @(
    $sortedMembershipRows |
        Group-Object GroupDistinguishedName |
        ForEach-Object {
            $first = $_.Group | Select-Object -First 1
            $usersWithAccess = @($_.Group | Sort-Object UserSamAccountName -Unique | Select-Object -ExpandProperty UserSamAccountName)
            $directUsers = @($_.Group | Where-Object { $_.MembershipType -eq 'Direct' } | Sort-Object UserSamAccountName -Unique | Select-Object -ExpandProperty UserSamAccountName)
            $nestedUsers = @($_.Group | Where-Object { $_.MembershipType -eq 'Nested' } | Sort-Object UserSamAccountName -Unique | Select-Object -ExpandProperty UserSamAccountName)

            [pscustomobject]@{
                GroupName              = $first.GroupName
                GroupSamAccountName    = $first.GroupSamAccountName
                GroupCategory          = $first.GroupCategory
                GroupScope             = $first.GroupScope
                GroupMail              = $first.GroupMail
                GroupDescription       = $first.GroupDescription
                GroupSID               = $first.GroupSID
                GroupObjectGuid        = $first.GroupObjectGuid
                GroupDistinguishedName = $first.GroupDistinguishedName
                UserCount              = $usersWithAccess.Count
                Users                  = ($usersWithAccess -join '; ')
                DirectUserCount        = $directUsers.Count
                DirectUsers            = ($directUsers -join '; ')
                NestedUserCount        = $nestedUsers.Count
                NestedUsers            = ($nestedUsers -join '; ')
            }
        } |
        Sort-Object GroupName, GroupDistinguishedName
)

$combinedRows | Export-Csv -Path $combinedCsv -NoTypeInformation -Encoding UTF8
$statusRows | Sort-Object InputIdentity | Export-Csv -Path $statusCsv -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host 'Done.'
Write-Host "Per-user association CSV: $membershipCsv"
Write-Host "Combined de-duplicated CSV: $combinedCsv"
Write-Host "Lookup/status CSV: $statusCsv"
Write-Host "Individual per-user CSV folder: $perUserFolder"
