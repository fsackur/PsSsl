function Get-InstalledSqlFeatures
{
    <#
        .SYNOPSIS
        Gets installed features of MS SQL Server.

        .DESCRIPTION
        Gets installed software where the display name matches 'SQL'.

        Output is filtered from Software\Get-InstalledSoftware.

        Caches result in script variable.

        .OUTPUTS
        [psobject[]]

        .EXAMPLE
        New-ReadinessSpecObject -AddMember 'SqlFeatures'

        SupportsTls12 RequiredActions SqlFeatures
        ------------- --------------- -----------
                False {}

        Creates an object with 'SupportsTls12', 'RequiredActions' and 'SqlFeatures' properties. 'SupportsTls12'
        is initialised as false; 'RequiredActions' is initialised as an empty array; 'SqlFeatures' is initialised
        as null.

        .NOTES
        This is for internal use. It is quick and dirty. Output will not be useful to customer; prefer the Installed Feature Report from Setup.exe.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param ()

    if (-not $Script:InstalledSqlFeatures)
    {
        $InstalledSoftware           = Software\Get-InstalledSoftware
        $Script:InstalledSqlFeatures = $InstalledSoftware | Where-Object {$_.DisplayName -match 'SQL'}
    }
    return $Script:InstalledSqlFeatures
}
