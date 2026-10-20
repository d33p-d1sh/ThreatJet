# Object Inventory

`Export-ADObjectInventory` writes a complete picture of the directory into an
`Inventory\` subfolder. The findings tell you what is wrong; the inventory lets you ask
your own questions — scoping an engagement, hunting, or answering "how many X do we
have" without another collection run.

```powershell
Export-ADObjectInventory -Path C:\Audit
Export-ADObjectInventory -Path C:\Audit -ObjectType Users,Groups
Export-ADObjectInventory -Path C:\Audit -SkipRelationships
Invoke-ThreatJetAssessment -IncludeInventory      # as part of a full run
```

---

## Two shapes of the same data

### `AD_Inventory_<Type>.csv` — wide, one row per object

Every property the object has. Built for reading and filtering in a spreadsheet.

Multi-valued attributes are joined with **` | `** — a delimiter chosen because it does
not occur in distinguished names, unlike a comma or semicolon. Each multi-valued
attribute also gets a **`_Count`** column, so you can sort by "users in the most groups"
without parsing anything.

| Type | Source |
|---|---|
| `Users` | `Get-ADUser -Properties *` |
| `Computers` | `Get-ADComputer -Properties *` |
| `Groups` | `Get-ADGroup -Properties *` |
| `ManagedServiceAccounts` | `Get-ADServiceAccount -Properties *` |
| `OrganizationalUnits` | `Get-ADOrganizationalUnit -Properties *` |
| `Contacts`, `ForeignSecurityPrincipals`, `Containers` | `Get-ADObject` by objectClass |
| `GPOs` | `Get-GPO -All` |
| `Trusts` | `Get-ADTrust -Properties *` |
| `Domain`, `Forest`, `DomainControllers` | `Get-ADDomain` / `Get-ADForest` / `Get-ADDomainController` |
| `Sites`, `Subnets` | Configuration naming context |

### `REL_*.csv` — normalised, one row per value

The same multi-valued data as edge lists. Built for joining, pivoting, and loading into
a graph tool.

Every relationship file has the same first two columns — `Source_Name`, `Source_DN` —
followed by the value and a `_Name` column holding the value's leaf CN, so the file is
readable without post-processing.

| File | Edge |
|---|---|
| `REL_Group_Members.csv` | group → member |
| `REL_Group_MemberOf.csv` | group → parent group (nesting) |
| `REL_User_MemberOf.csv` | user → group |
| `REL_Computer_MemberOf.csv` | computer → group |
| `REL_User_SPNs.csv` | user → SPN |
| `REL_Computer_SPNs.csv` | computer → SPN |
| `REL_gMSA_SPNs.csv` | gMSA → SPN |
| `REL_User_SIDHistory.csv` | user → historical SID |
| `REL_User_DelegationTargets.csv` | user → `msDS-AllowedToDelegateTo` |
| `REL_Computer_DelegationTargets.csv` | computer → `msDS-AllowedToDelegateTo` |
| `REL_gMSA_Retrievers.csv` | gMSA → principal allowed to retrieve the password |
| `REL_GPO_Links.csv` | container → GPO, with `Link_Enabled` / `Link_Enforced` |

`REL_GPO_Links.csv` is derived from the `gPLink` attribute on OUs and the domain head,
not from the GPO itself — links live on the container side. The enabled and enforced
flags are decoded from the link options bitmask.

---

## How values are flattened

`Export-Csv` calls `ToString()` on complex values, which is why naive AD exports are
full of `Microsoft.ActiveDirectory.Management.ADPropertyValueCollection` and
`System.Byte[]`. The flattener handles each type deliberately:

| Type | Output |
|---|---|
| Multi-valued | joined with ` \| `, plus `<Name>_Count` |
| `SecurityIdentifier`, `GUID` | string form (`S-1-5-21-…`) |
| `DateTime` | round-trip ISO 8601 — sortable and unambiguous |
| `byte[]` ≤ 256 bytes | base64 |
| `byte[]` > 256 bytes | `(binary, N bytes)` |
| `$null` | empty string, not the word "null" |
| Strings | **never** enumerated into characters |

That last one matters: `[string]` implements `IEnumerable`, so a careless
implementation turns `"hello"` into `h | e | l | l | o`. The smoke test asserts against
this specifically.

Large binary attributes with no value in a flat CSV (`nTSecurityDescriptor`,
`thumbnailPhoto`, `userCertificate`, replication metadata) are recorded as
`(binary omitted)` rather than dumped — they would add hundreds of megabytes of
unreadable data. **ACLs are exported separately and properly by `Collect-ACLs`.**

---

## Worked examples

All of these run offline against the CSVs.

**Kerberoastable accounts, ranked by password age**

```powershell
$users = Import-Csv .\Inventory\AD_Inventory_Users.csv
$users | Where-Object { $_.ServicePrincipalNames_Count -gt 0 -and $_.Enabled -eq 'True' } |
    Sort-Object { [datetime]$_.PasswordLastSet } |
    Select-Object SamAccountName, PasswordLastSet, ServicePrincipalNames
```

**Effective membership of a privileged group, including nesting**

```powershell
$edges = Import-Csv .\Inventory\REL_Group_Members.csv

function Get-Effective ($groupName, $seen = @{}) {
    $edges | Where-Object Source_Name -eq $groupName | ForEach-Object {
        if (-not $seen[$_.Member_DN]) {
            $seen[$_.Member_DN] = $true
            $_.Member_DN_Name
            Get-Effective $_.Member_DN_Name $seen
        }
    }
}
Get-Effective 'Domain Admins' | Sort-Object -Unique
```

**Accounts with SIDHistory (persistence or migration leftovers)**

```powershell
Import-Csv .\Inventory\REL_User_SIDHistory.csv |
    Select-Object Source_Name, SIDHistory
```

**Stale computers still enabled**

```powershell
Import-Csv .\Inventory\AD_Inventory_Computers.csv |
    Where-Object { $_.Enabled -eq 'True' -and $_.LastLogonDate -and
                   [datetime]$_.LastLogonDate -lt (Get-Date).AddDays(-180) } |
    Select-Object Name, OperatingSystem, LastLogonDate
```

**gMSAs retrievable by a broad group**

```powershell
Import-Csv .\Inventory\REL_gMSA_Retrievers.csv |
    Where-Object Retriever_DN_Name -match 'Domain Users|Authenticated Users|Everyone'
```

**Unlinked or disabled GPO links**

```powershell
$links = Import-Csv .\Inventory\REL_GPO_Links.csv
$gpos  = Import-Csv .\Inventory\AD_Inventory_GPOs.csv

$gpos | Where-Object { $_.Id -notin $links.GPO_GUID } | Select-Object DisplayName
$links | Where-Object Link_Enabled -eq 'False'
```

---

## Cost and handling

`-Properties *` on every object is the slowest and largest part of an assessment. On a
large estate expect the inventory to dominate both runtime and output size; use
`-ObjectType` to scope it, or `-SkipRelationships` if you only need the wide files.

**Treat the inventory as more sensitive than the findings.** It is a complete map of
the directory — every account, every group, every delegation. That is exactly the
reconnaissance an attacker would otherwise have to perform. Encrypt at rest, restrict
access to the engagement team, and delete it when the work is done.
