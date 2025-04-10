<#

.SYNOPSIS
Script to retrieve bitlocker keys for devices against serialnumber provided as a CSV input. Needs to be executed as Entra registered application

COPYRIGHT
Copyright (c) Atos 2024.

AUTHOR
Joymalya Basu Roy

.INPUTS
A CSV file having device serial numbers for which you want to export the bitlocker keys. See required parameters

.OUTPUTS
Retrieves bitlocker keys for specified devices and exports result to csv file per device.

.DESCRIPTION
Script to retrieve bitlocker keys for devices against serialnumber provided as a CSV input and export results to csv file per device. 

Required permissions:
    Microsoft Graph
        Application:
            Device.ReadWrite.All
            DeviceManagementConfiguration.ReadWrite.All
            DeviceManagementManagedDevices.ReadWrite.All
            DeviceManagementServiceConfig.ReadWrite.All
            Directory.Read.All
            BitlockerKey.Read.All
            Delegated:
            Directory.AccessAsUser.All

Assigned admin roles to the service principal:
    Intune administrator
    Cloud device administrator

Mandatory parameters:
    TenantId
    AppId
    CerThumbPrint
    BLRKFolder

VERSION HISTORY
1.0 - 2024-09-08    - Joymalya Basu Roy - Initial release

.PARAMETER TenantId
Id of the Entra tenant to be targeted

.PARAMETER Appid
AppID of the Entra registered application

.PARAMETER CertThumbPrint
Certificate Thumbprint of the Entra registered application certificate. The certficate must be imported prior into the certificate personal store of the user who is executing this script

.PARAMETER BLRKFolder
Mandatory parameter to specify a path to a folder where BitLocker Recovery Key information should be stored.

.EXAMPLE
Run script storing recovery key information on a dedicated folder on drive "D:"

.\Get-BitlockerKeys.ps1 -AppId "3100e08a-c4b2-4945-9635-3dc4fa3a3268" -TenantId "11111111-2222-3333-4444-eeeeeeeeeeee" -CertThumbPrint "3056F81BAC36AF83BC85C26964976ED2855B599C" -BLRKFolder "D:\Data\BitLockerKeys"


#>

Param (
	    [parameter(Mandatory=$true)] [string] $TenantId,
	    [parameter(Mandatory=$true)] [String] $AppId,
	    [parameter(Mandatory=$true)] [String] $CertThumbPrint,
        [Parameter(Mandatory=$true)] [string] $BLRKFolder = ""
)


# Required Graph permissions 
$RequiredScopes = @( "Device.ReadWrite.All","DeviceManagementConfiguration.ReadWrite.All","DeviceManagementManagedDevices.ReadWrite.All","DeviceManagementServiceConfig.ReadWrite.All","Directory.Read.All","BitlockerKey.Read.All" )

# check if required PowerShell modules are installed
Import-Module Microsoft.Graph
if (-not (Get-Module -Name "Microsoft.Graph")) {
    Write-Host "Please install first the PowerShell Graph module from PowerShell Gallery`n`n	https://www.powershellgallery.com/packages/Microsoft.Graph`n"
	Write-Host "Exiting Script"
}

Function Connect-NewGraphSession() {
    [cmdletbinding()] param()

	try {
        Connect-MgGraph -AppID $AppId -TenantId $TenantId -CertificateThumbprint $CertThumbPrint -NoWelcome -ErrorAction stop
    }
    catch {
        Write-Host "Error occured on logon to Graph:`n$_"
    }
    $Global:TenantName = $null
	$Global:TenantName = ((Get-MgOrganization).VerifiedDomains | Where-Object IsDefault -eq 'true').Name
	$Scopes = $(Get-MgContext).scopes
	ForEach ($RequiredScope in $RequiredScopes) {
		If ($Scopes -notcontains  $RequiredScope) {
			Write-Host "Script may not work properly,required Scope not found: $RequiredScope"
		} 
	}
    Write-Host "Connected to Tenant: $Global:TenantName"
} 

function Get-BLRK {
    param (
        [Parameter(Mandatory=$true)][string]$deviceId
    )
    try {
        $Blk = $null
        $Blk = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$deviceId'" -ErrorAction Stop | Select-Object Id,CreatedDateTime,DeviceId,@{n="Recovery Key";e={(Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $_.Id -Property key).key}},VolumeType    
        return [array]$Blk
    }
    catch {
        Write-Host "Error occured on reading BitLocker Recovery Key(s)`n$_`n"
        return $null
    }
}

function Export-BLRK {
    param (
        [Parameter(Mandatory=$true)][string]$DeviceId,
        [Parameter(Mandatory=$true)][string]$DeviceName,
        [Parameter(Mandatory=$true)][string]$BLRKFolder,
        [Parameter(Mandatory=$false)][string]$OwnerUPN,
        [Parameter(Mandatory=$false)][string]$OwnershipType,
        [Parameter(Mandatory=$false)][string]$TrustType,
        [Parameter(Mandatory=$false)][string]$MgmtType,
        [Parameter(Mandatory=$false)][string]$SerialNumber
    )
    # export BitLocker Key to log file folder
    $RecoveryKey = $null
    $RecoveryKey = Get-BLRK ( $DeviceId )
    if ( $RecoveryKey ) {
        try {
            Set-Content -Path $( $BLRKFolder + "\" + $DeviceName + "_" + $DeviceID + ".txt" ) -Value $("Device Name: " + $DeviceName + "`n" + "Owner UPN: " + $OwnerUPN + "`n" + "OwnershipType: " + $OwnershipType + "`n" + "TrustType: " + $TrustType + "`n" + "ManagementType: " + $MgmtType + "`n" + "SerialNumber: " + $SerialNumber + "`n" + $($RecoveryKey | Out-String ).Trim("`r`n") )  -Encoding utf8 -Force -ErrorAction Stop
            Write-Host "Recovery Key File generated for Device $DeviceName at location $BLRKFolder"
        }
        catch {
            Write-Host "Error occured on storing BitLocker Recovery Key for $DeviceName`n$_"
        }
    }
}

##### Main script starts here

Add-Type -AssemblyName System.Windows.Forms

# Connect to Graph
Connect-NewGraphSession

if ( $null -eq $Global:TenantName -or $Global:TenantName -eq ""  ) {
    Write-Host "Error, not connected to MG Graph"
}


# Create a file dialog object
$fileDialog = New-Object System.Windows.Forms.OpenFileDialog

# Set the properties of the dialog
$fileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop') 
$fileDialog.Filter = "CSV Files (*.csv)|*.csv"
$fileDialog.Title = "Select a CSV File"

# Show the dialog and check if the user clicked "OK"
if ($fileDialog.ShowDialog() -eq "OK") {
    # Get the selected file path
    $filePath = $fileDialog.FileName

    # Import the CSV
    $csvData = Import-Csv $filePath
}

foreach($device in $csvData){

    $IntuneDevice = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$($device.serialNumber)'" -ErrorAction Stop
    $azDevice = Get-MgDevice -Filter "displayName eq '$($IntuneDevice.DeviceName)'" -ExpandProperty registeredOwners
    $regOwnerUPN = &{if ($azDevice.registeredOwners) { $azDevice.registeredOwners[0].AdditionalProperties.userPrincipalName } else { "N/A" }}
    $devOwnership = $azDevice.DeviceOwnership
    $devTrust = $azDevice.TrustType
    $devMgmt = $azDevice.ManagementType
    
    Export-BLRK -DeviceId $azDevice.deviceId -DeviceName $azDevice.displayName -BLRKFolder $BLRKFolder -OwnerUPN $regOwnerUPN -OwnershipType $devOwnership -TrustType $devTrust -MgmtType $devMgmt
}

