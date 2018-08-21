function Get-CommVaultVersion
{
    <#
        .Synopsis
        Get the version of the CommVault agent

        .Description
        Returns version object.

        $null output indicates that CommVault is not installed.

        .Link
        https://one.rackspace.com/display/MBU/MS+SQL+Backup+failure+when+TLS+1.0+Disabled
    #>
    $CommVaultServices = Get-WmiObject Win32_Service -Filter "DisplayName LIKE 'CommVault%'"

    if ($null -eq $CommVaultServices) {
        return $null
    }

    $ClBackup = $CommVaultServices |
        foreach {$_.PathName -replace "^(\'|`")" -replace "('|`").*"} |   #just get executable path of service
        foreach {Get-ChildItem (Split-Path $_) -Filter 'CLBackup.exe'} |  #in case different paths, check all
        select -First 1

    return [version]$ClBackup.VersionInfo.FileVersion

}
