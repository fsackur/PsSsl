function Get-WmiOS
{
    <#
        .SYNOPSIS
        Gets an instance of the Win32_OperatingSystem class.

        .DESCRIPTION
        Gets an instance of the Win32_OperatingSystem class.

        Caches result in script variable.

        .OUTPUTS
        [System.Management.ManagementObject#root\cimv2\Win32_OperatingSystem]

        .EXAMPLE
        Get-WmiOS
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param ()

    if (-not $Script:WmiOS)
    {
        $Script:WmiOS = Get-WmiObject Win32_OperatingSystem
    }
    return $Script:WmiOS
}
