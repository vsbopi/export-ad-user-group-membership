# Export-AdUserGroupAccess

PowerShell utility for exporting Active Directory user group memberships (direct, nested, and primary group) to UTF-8 CSV files. Use it for access audits, access reviews, or migration planning.

## Prerequisites

- **PowerShell 5.1+** (the script declares `#requires -Version 5.1`)
- **RSAT: Active Directory module** — run on a domain-joined Windows host with RSAT installed, a domain controller, or any machine where `Import-Module ActiveDirectory` succeeds
- **AD read permissions** to run `Get-ADUser`, `Get-ADGroup`, and `Get-ADPrincipalGroupMembership` for the target users (typical: account ops, helpdesk, or delegated read, depending on org policy)
- **Network reachability** to a domain controller (or pass `-Server` to target a specific DC or AD LDS instance)

Use `-Credential` when queries must run under alternate credentials.

## Quick start

```powershell
# Single user (default output: .\ad-group-access-output\)
.\Export-AdUserGroupAccess.ps1 -Users jdoe

# Multiple users with a custom output folder
.\Export-AdUserGroupAccess.ps1 -Users jdoe,asmith -OutputFolder C:\Temp\AdAccess

# Users from a CSV column
.\Export-AdUserGroupAccess.ps1 -UserListPath .\users.csv -UserColumn SamAccountName

# Users from a text file (one identity per line; lines starting with # are ignored)
.\Export-AdUserGroupAccess.ps1 -UserListPath .\users.txt

# Direct memberships only (no nested parent groups)
.\Export-AdUserGroupAccess.ps1 -Users jdoe -DirectOnly
```

For full parameter help and examples:

```powershell
Get-Help .\Export-AdUserGroupAccess.ps1 -Full
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `Users` | One or more user identities. Accepts SamAccountName, distinguished name, GUID, SID, UPN, and mail. Aliases: `User`, `Identity`. |
| `UserListPath` | Path to a `.txt` file (one user per line) or a `.csv` file containing a user column. |
| `UserColumn` | CSV column name to read from `UserListPath`. Defaults to `User`. If the column is missing and the CSV has only one column, that column is used with a warning. |
| `OutputFolder` | Folder where CSV outputs are written. Defaults to `ad-group-access-output` under the script directory. |
| `DirectOnly` | Export only direct group memberships. Without this switch, nested parent groups are included. |
| `Server` | Optional domain controller or AD LDS server to query. |
| `Credential` | Optional credential (`PSCredential`) for Active Directory queries. |

At least one of `-Users` or `-UserListPath` is required.

## Output files

All outputs are written as UTF-8 CSV under `OutputFolder` (default: `ad-group-access-output/`).

| File | Description |
|------|-------------|
| `UserGroupMembership.csv` | One row per user–group association, with nesting metadata (`MembershipType`, `NestingLevel`, `MembershipPath`) and enriched user/group columns (account names, mail, SIDs, DNs, and related attributes). |
| `CombinedGroupAccess.csv` | One row per distinct group across all successfully processed users, with aggregated user lists (`Users`, `DirectUsers`, `NestedUsers`) and counts. |
| `UserLookupStatus.csv` | Per input identity: status (`Found` or `Error`), resolved account names, group counts, and error messages when lookup fails. |
| `PerUser/<SamAccountName>-groups.csv` | Same shape as membership rows, split per resolved user under the `PerUser/` subfolder. |

By default, the script walks parent group memberships to include nested access and resolves each user's **primary group** as a direct membership. Use `-DirectOnly` to limit results to groups assigned directly to the user (primary group is still included).

## Identity resolution

For each input identity, the script resolves the AD user in this order:

1. **`Get-ADUser -Identity`** — accepts SAM account name, distinguished name, GUID, SID, UPN, and mail.
2. **LDAP fallback** — if that fails, queries by `sAMAccountName`, `userPrincipalName`, and `mail`. Values in `DOMAIN\user` form use the part after the backslash for the LDAP search.
3. **Ambiguous match** — if multiple users match the fallback filter, the script fails that identity with a hard error listing the matched SamAccountNames.
4. **Not found** — if no user matches, the script records an error in `UserLookupStatus.csv` and continues with remaining identities.

## Privacy

Exported CSVs can contain **PII and access metadata** (account names, mail, group memberships, SIDs, and related attributes). Treat `ad-group-access-output/` as sensitive.

This repository lists `ad-group-access-output/` in [.gitignore](.gitignore) so generated exports are not committed by default. If sample runs exist under that path, remove them from version control or rely on `.gitignore` going forward. Do not commit real AD export data.

## Disclaimer

This script is an administrative utility. Validate behavior in a lab before production use. Your organization's Active Directory policies, change controls, and data-handling requirements apply.
