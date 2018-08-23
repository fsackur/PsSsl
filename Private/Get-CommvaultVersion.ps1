function Get-CommvaultVersion
{
    <#
        .SYNOPSIS
        Gets the version of the Commvault agent.

        .DESCRIPTION
        Gets the version of the Commvault agent. Returns null if Commvault is not installed.

        .OUTPUTS
        [version]

        .LINK
        https://one.rackspace.com/display/MBU/MS+SQL+Backup+failure+when+TLS+1.0+Disabled
    #>
    [CmdletBinding()]
    [OutputType([version])]
    param ()

    $CommvaultServices = Get-WmiObject Win32_Service -Filter "DisplayName LIKE 'CommVault%'"

    if ($null -eq $CommvaultServices) {
        return $null
    }

    $ClBackupExeFile = $CommvaultServices |
        ForEach-Object {$_.PathName -replace "^(\'|`")" -replace "('|`").*"} |   #just get executable path of service
        ForEach-Object {Get-ChildItem (Split-Path $_) -Filter 'CLBackup.exe'} |  #in case different paths, check all
        Select-Object -First 1

    return [version]$ClBackupExeFile.VersionInfo.FileVersion

}
