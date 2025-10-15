<#
.SYNOPSIS
Retrieve BitLocker recovery keys from Entra ID (Microsoft Graph) by device serial numbers from a CSV.

.DESCRIPTION
- App-only authentication via certificate (Service Principal).
- Reads device serial numbers from a CSV and resolves Intune managed device -> Azure AD device.
- Retrieves BitLocker recovery keys and exports:
  - A consolidated CSV report (recommended)
  - Optional per-device TXT file
- Supports optional encryption of recovery keys at rest using DPAPI.
- Includes retry logic, robust error handling, and non-interactive automation-friendly mode.

.REQUIREMENTS
- Microsoft Graph PowerShell SDK (Microsoft.Graph).
- App registration with certificate authentication.
- App permissions (Application):
    Device.ReadWrite.All
    DeviceManagementConfiguration.ReadWrite.All
    DeviceManagementManagedDevices.ReadWrite.All
    DeviceManagementServiceConfig.ReadWrite.All
    Directory.Read.All
    BitlockerKey.Read.All
- (Delegated not used in app-only mode.)
- Recommended Admin Roles for the Service Principal:
    Intune Administrator
    Cloud Device Administrator

.PARAMETER TenantId
Entra tenant ID (GUID).

.PARAMETER AppId
App Registration (Client) ID (GUID).

.PARAMETER CertThumbPrint
Certificate thumbprint from the CurrentUser\My store.

.PARAMETER CSVPath
Path to input CSV. Must contain a column with serial numbers (default column name is 'serialNumber').

.PARAMETER SerialNumberColumn
CSV column name that contains device serial numbers. Default: 'serialNumber'.

.PARAMETER OutputCsvPath
Path to a consolidated CSV report file. Created if it does not exist.

.PARAMETER BLRKFolder
Folder where per-device TXT files will be written (if -PerDeviceTxt is used). Created if missing.

.PARAMETER PerDeviceTxt
Also create a per-device TXT with device details + keys.

.PARAMETER EncryptOutput
Encrypt recovery key values at rest using DPAPI (CurrentUser scope). TXT and CSV will store base64 of encrypted data.

.PARAMETER RestrictAcl
Restrict NTFS ACL on the BLRKFolder (and CSV directory) to the current user only.

.PARAMETER UseFileDialog
Open a file dialog to select CSV if -CSVPath is not provided. Useful for ad-hoc runs.

.PARAMETER MaxRetry
Max retries for transient Graph errors (HTTP 429/5xx). Default: 3.

.PARAMETER InitialBackoffSec
Initial exponential backoff seconds between retries. Default: 2.

.EXAMPLE
.\Get-BitlockerKeys_Enhanced.ps1 `
  -TenantId "11111111-2222-3333-4444-eeeeeeeeeeee" `
  -AppId "3100e08a-c4b2-4945-9635-3dc4fa3a3268" `
  -CertThumbPrint "3056F81BAC36AF83BC85C26964976ED2855B599C" `
  -CSVPath "D:\Input\serials.csv" `
  -OutputCsvPath "D:\Reports\BitLockerKeys.csv" `
  -BLRKFolder "D:\Data\BitLockerKeys" `
  -PerDeviceTxt `
  -EncryptOutput `
  -RestrictAcl

.NOTES
Author: Joymalya Basu Roy (enhanced version)
Version: 1.1 - 2025-10-15
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]  [string] $TenantId,
    [Parameter(Mandatory = $true)]  [string] $AppId,
    [Parameter(Mandatory = $true)]  [string] $CertThumbPrint,

    [Parameter(Mandatory = $false)] [string] $CSVPath,
    [Parameter(Mandatory = $false)] [string] $SerialNumberColumn = 'serialNumber',
    [Parameter(Mandatory = $false)] [string] $OutputCsvPath = '',

    [Parameter(Mandatory = $false)] [string] $BLRKFolder = '',
    [switch] $PerDeviceTxt,

    [switch] $EncryptOutput,
    [switch] $RestrictAcl,
    [switch] $UseFileDialog,

    [int] $MaxRetry = 3,
    [int] $InitialBackoffSec = 2
)

#region Utilities

function Ensure-Module {
    param([Parameter(Mandatory=$true)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Module '$Name' not found. Installing..."
        try {
            Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            throw "Failed to install module '$Name'. $_"
        }
    }
    Import-Module $Name -ErrorAction Stop
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$true)][int]$MaxRetry,
        [Parameter(Mandatory=$true)][int]$InitialBackoffSec
    )
    $attempt = 0
    $delay = [double]::Parse($InitialBackoffSec)
    while ($true) {
        try {
            return & $ScriptBlock
        } catch {
            $err = $_
            $status = $err.Exception.Response.StatusCode.Value__ 2>$null
            if ($attempt -lt $MaxRetry -and ($status -in 429,500,502,503,504 -or $err.Exception.Message -match 'Timeout|temporarily unavailable')) {
                $attempt++
                Write-Warning "Transient error (HTTP $status). Retry $attempt of $MaxRetry in $([math]::Round($delay,2))s..."
                Start-Sleep -Seconds ([int][math]::Ceiling($delay))
                $delay *= 2
                continue
            }
            throw $err
        }
    }
}

function Protect-String {
    param([Parameter(Mandatory=$true)][string]$Plain)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    $prot  = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Convert]::ToBase64String($prot)
}

function Unprotect-String {
    param([Parameter(Mandatory=$true)][string]$Base64)
    $prot  = [Convert]::FromBase64String($Base64)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($prot, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Ensure-Folder {
    param([Parameter(Mandatory=$true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Restrict-FolderAclToCurrentUser {
    param([Parameter(Mandatory=$true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRuleProtection($true, $false) # disable inheritance
    $acl.AddAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}

#endregion Utilities

#region Graph connection & validation

function Connect-NewGraphSession {
    [CmdletBinding()]
    param()

    try {
        Connect-MgGraph -AppID $AppId -TenantId $TenantId -CertificateThumbprint $CertThumbPrint -NoWelcome -ErrorAction Stop
    } catch {
        throw "Failed to connect to Microsoft Graph. $_"
    }

    try {
        $global:TenantName = ((Get-MgOrganization -ErrorAction Stop).VerifiedDomains | Where-Object IsDefault -eq $true).Name
        Write-Host "Connected to Tenant: $global:TenantName"
    } catch {
        Write-Warning "Connected, but failed to resolve tenant name. $_"
    }
}

function Test-BitlockerPermission {
    # Attempt a harmless call to validate BitLocker permission; will 403 if missing
    try {
        $null = Get-MgInformationProtectionBitlockerRecoveryKey -Top 1 -ErrorAction Stop
        return $true
    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
            Write-Error "App likely lacks BitlockerKey.Read.All application permission or admin consent."
            return $false
        }
        # Network/transient errors should be retried by caller
        throw
    }
}

#endregion Graph connection & validation

#region Domain helpers

function Get-ManagedDeviceBySerial {
    param([Parameter(Mandatory=$true)][string]$Serial)
    # Filter supports eq on serialNumber
    Invoke-WithRetry -MaxRetry $MaxRetry -InitialBackoffSec $InitialBackoffSec -ScriptBlock {
        Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$($Serial.Replace("'","''"))'" -ConsistencyLevel eventual -ErrorAction Stop
    }
}

function Get-AadDeviceById {
    param([Parameter(Mandatory=$true)][string]$DeviceObjectId)
    Invoke-WithRetry -MaxRetry $MaxRetry -InitialBackoffSec $InitialBackoffSec -ScriptBlock {
        # Use -DeviceId for direct lookup (faster & safer than -Filter)
        Get-MgDevice -DeviceId $DeviceObjectId -ExpandProperty registeredOwners -ErrorAction Stop
    }
}

function Get-RegisteredOwnerUpn {
    param([Parameter(Mandatory=$true)][Microsoft.Graph.PowerShell.Models.IMicrosoftGraphDevice]$AadDevice)
    # registeredOwners is a collection of directoryObjects; user objects carry userPrincipalName in AdditionalProperties
    if ($AadDevice.registeredOwners -and $AadDevice.registeredOwners.Count -gt 0) {
        $userOwner = $AadDevice.registeredOwners | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' } | Select-Object -First 1
        if ($userOwner) { return $userOwner.AdditionalProperties.userPrincipalName }
    }
    return 'N/A'
}

function Get-BitlockerKeysForDevice {
    param([Parameter(Mandatory=$true)][string]$AadDeviceObjectId)

    # First list key IDs for this device
    $keyRows = Invoke-WithRetry -MaxRetry $MaxRetry -InitialBackoffSec $InitialBackoffSec -ScriptBlock {
        Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$AadDeviceObjectId'" -ErrorAction Stop
    }

    if (-not $keyRows) { return @() }

    $results = @()
    foreach ($row in @($keyRows)) {
        # Retrieve the 'key' property
        $keyMaterial = Invoke-WithRetry -MaxRetry $MaxRetry -InitialBackoffSec $InitialBackoffSec -ScriptBlock {
            (Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $row.Id -Property key -ErrorAction Stop).key
        }

        $results += [PSCustomObject]@{
            BitlockerRecoveryKeyId = $row.Id
            CreatedDateTime        = $row.CreatedDateTime
            DeviceId               = $row.DeviceId
            VolumeType             = $row.VolumeType
            RecoveryKey            = $keyMaterial
        }
    }
    return $results
}

#endregion Domain helpers

#region Export helpers

function Ensure-OutputTargets {
    if ($PerDeviceTxt) {
        if ([string]::IsNullOrWhiteSpace($BLRKFolder)) {
            throw "BLRKFolder is required when -PerDeviceTxt is used."
        }
        Ensure-Folder -Path $BLRKFolder
        if ($RestrictAcl) { Restrict-FolderAclToCurrentUser -Path $BLRKFolder }
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputCsvPath)) {
        $csvFolder = Split-Path -Path $OutputCsvPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($csvFolder)) {
            Ensure-Folder -Path $csvFolder
            if ($RestrictAcl) { Restrict-FolderAclToCurrentUser -Path $csvFolder }
        }
        if (-not (Test-Path -LiteralPath $OutputCsvPath)) {
            # Create with header
            "" | Out-File -FilePath $OutputCsvPath -Encoding UTF8
        }
    }
}

function Write-PerDeviceTxt {
    param(
        [Parameter(Mandatory=$true)][string]$DeviceName,
        [Parameter(Mandatory=$true)][string]$DeviceId,
        [Parameter(Mandatory=$true)][string]$OwnerUPN,
        [Parameter(Mandatory=$true)][string]$OwnershipType,
        [Parameter(Mandatory=$true)][string]$TrustType,
        [Parameter(Mandatory=$true)][string]$MgmtType,
        [Parameter(Mandatory=$true)][string]$SerialNumber,
        [Parameter(Mandatory=$true)][array] $KeyObjects
    )
    $path = Join-Path $BLRKFolder "$($DeviceName)_$($DeviceId).txt"

    $keyLines = if ($KeyObjects.Count -gt 0) {
        ($KeyObjects | ForEach-Object {
            $rk = $_.RecoveryKey
            if ($EncryptOutput) { $rk = Protect-String -Plain $rk }
            "Id: $($_.BitlockerRecoveryKeyId)  Volume: $($_.VolumeType)  Created: $($_.CreatedDateTime)  Key: $rk"
        }) -join "`r`n"
    } else {
        "No BitLocker recovery keys found."
    }

    $content = @"
Device Name: $DeviceName
Owner UPN: $OwnerUPN
OwnershipType: $OwnershipType
TrustType: $TrustType
ManagementType: $MgmtType
SerialNumber: $SerialNumber

$keyLines
"@

    Set-Content -Path $path -Value $content -Encoding utf8 -Force
    Write-Host "Per-device file generated: $path"
}

function Append-CsvRow {
    param(
        [Parameter(Mandatory=$true)][string]$OutputCsv,
        [Parameter(Mandatory=$true)][pscustomobject]$Row
    )
    $Row | Export-Csv -Path $OutputCsv -Encoding UTF8 -NoTypeInformation -Append
}

#endregion Export helpers

# ------------------------- Main ----------------------------

try {
    Ensure-Module -Name Microsoft.Graph
} catch {
    Write-Error $_
    exit 1
}

# Resolve input CSV path (non-interactive by default)
if ([string]::IsNullOrWhiteSpace($CSVPath) -and $UseFileDialog) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        $ofd.Filter = "CSV Files (*.csv)|*.csv"
        $ofd.Title = "Select a CSV file containing serial numbers"
        if ($ofd.ShowDialog() -eq 'OK') {
            $CSVPath = $ofd.FileName
        }
    } catch {
        throw "Failed to open file dialog. Provide -CSVPath instead. $_"
    }
}

if ([string]::IsNullOrWhiteSpace($CSVPath) -or -not (Test-Path -LiteralPath $CSVPath)) {
    throw "Input CSV not found. Provide -CSVPath or use -UseFileDialog."
}

# Prepare outputs
Ensure-OutputTargets

# Connect & validate
Connect-NewGraphSession

# Validate BitLocker permission (fast fail if no consent)
if (-not (Test-BitlockerPermission)) {
    throw "Insufficient permissions for BitLocker recovery keys. Please grant/admin-consent 'BitlockerKey.Read.All' (Application)."
}

# Import input CSV
$csv = Import-Csv -LiteralPath $CSVPath
if (-not $csv -or $csv.Count -eq 0) {
    throw "No rows found in CSV: $CSVPath"
}
if (-not ($csv | Get-Member -Name $SerialNumberColumn -MemberType NoteProperty)) {
    throw "CSV does not contain the required column '$SerialNumberColumn'."
}

# Process
$index = 0
$total = $csv.Count
$reportRows = @()

foreach ($row in $csv) {
    $index++
    $serial = [string]$row.$SerialNumberColumn
    if ([string]::IsNullOrWhiteSpace($serial)) { continue }

    Write-Progress -Activity "Processing devices" -Status "Serial: $serial ($index of $total)" -PercentComplete (($index / $total) * 100)

    try {
        $managed = Get-ManagedDeviceBySerial -Serial $serial

        if (-not $managed) {
            Write-Warning "No Intune managed device found for serial '$serial'."
            # Still emit a report row (no keys)
            if ($OutputCsvPath) {
                Append-CsvRow -OutputCsv $OutputCsvPath -Row ([PSCustomObject]@{
                    SerialNumber      = $serial
                    DeviceName        = ''
                    AadDeviceObjectId = ''
                    OwnerUPN          = ''
                    OwnershipType     = ''
                    TrustType         = ''
                    ManagementType    = ''
                    BitlockerKeyId    = ''
                    VolumeType        = ''
                    CreatedDateTime   = ''
                    RecoveryKey       = ''
                    Status            = 'NotFound'
                    Message           = 'No managed device for this serial.'
                })
            }
            continue
        }

        foreach ($md in @($managed)) {
            # Prefer Azure AD Device ID from Intune
            $aadId = $md.AzureAdDeviceId
            if ([string]::IsNullOrWhiteSpace($aadId)) {
                Write-Warning "Managed device '$($md.DeviceName)' missing AzureAdDeviceId. Skipping."
                continue
            }

            $aadDevice = $null
            try {
                $aadDevice = Get-AadDeviceById -DeviceObjectId $aadId
            } catch {
                Write-Warning "Failed to resolve AAD device '$aadId' for '$($md.DeviceName)': $_"
                continue
            }

            $ownerUpn    = Get-RegisteredOwnerUpn -AadDevice $aadDevice
            $ownership   = $aadDevice.DeviceOwnership
            $trustType   = $aadDevice.TrustType
            $mgmtType    = $aadDevice.ManagementType
            $deviceName  = $aadDevice.DisplayName
            $deviceId    = $aadDevice.Id

            $keys = @()
            try {
                $keys = Get-BitlockerKeysForDevice -AadDeviceObjectId $deviceId
            } catch {
                Write-Warning "Error fetching BitLocker keys for device '$deviceName' ($deviceId): $_"
                $keys = @()
            }

            # Per-device TXT (optional)
            if ($PerDeviceTxt) {
                Write-PerDeviceTxt -DeviceName $deviceName -DeviceId $deviceId -OwnerUPN $ownerUpn `
                    -OwnershipType $ownership -TrustType $trustType -MgmtType $mgmtType -SerialNumber $serial `
                    -KeyObjects $keys
            }

            # Consolidated CSV rows
            if ($OutputCsvPath) {
                if ($keys.Count -gt 0) {
                    foreach ($k in $keys) {
                        $rk = $k.RecoveryKey
                        if ($EncryptOutput) { $rk = Protect-String -Plain $rk }

                        Append-CsvRow -OutputCsv $OutputCsvPath -Row ([PSCustomObject]@{
                            SerialNumber      = $serial
                            DeviceName        = $deviceName
                            AadDeviceObjectId = $deviceId
                            OwnerUPN          = $ownerUpn
                            OwnershipType     = $ownership
                            TrustType         = $trustType
                            ManagementType    = $mgmtType
                            BitlockerKeyId    = $k.BitlockerRecoveryKeyId
                            VolumeType        = $k.VolumeType
                            CreatedDateTime   = $k.CreatedDateTime
                            RecoveryKey       = $rk
                            Status            = 'OK'
                            Message           = ''
                        })
                    }
                } else {
                    Append-CsvRow -OutputCsv $OutputCsvPath -Row ([PSCustomObject]@{
                        SerialNumber      = $serial
                        DeviceName        = $deviceName
                        AadDeviceObjectId = $deviceId
                        OwnerUPN          = $ownerUpn
                        OwnershipType     = $ownership
                        TrustType         = $trustType
                        ManagementType    = $mgmtType
                        BitlockerKeyId    = ''
                        VolumeType        = ''
                        CreatedDateTime   = ''
                        RecoveryKey       = ''
                        Status            = 'NoKeys'
                        Message           = 'No BitLocker keys found for this device.'
                    })
                }
            }
        }

    } catch {
        $msg = "Unexpected error for serial '$serial': $_"
        Write-Warning $msg

        if ($OutputCsvPath) {
            Append-CsvRow -OutputCsv $OutputCsvPath -Row ([PSCustomObject]@{
                SerialNumber      = $serial
                DeviceName        = ''
                AadDeviceObjectId = ''
                OwnerUPN          = ''
                OwnershipType     = ''
                TrustType         = ''
                ManagementType    = ''
                BitlockerKeyId    = ''
                VolumeType        = ''
                CreatedDateTime   = ''
                RecoveryKey       = ''
                Status            = 'Error'
                Message           = $msg
            })
        }
    }
}

Write-Progress -Activity "Processing devices" -Completed
Write-Host "Done."

if ($EncryptOutput) {
    Write-Host "NOTE: Recovery keys are encrypted at rest using DPAPI (CurrentUser). Use Unprotect-String to decrypt when needed."
}