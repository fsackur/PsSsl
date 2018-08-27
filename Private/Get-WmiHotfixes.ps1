function Get-WmiHotfixes
{
    <#
        .SYNOPSIS
        Gets all instances of the Win32_QuickFixEngineering class.

        .DESCRIPTION
        Gets all instances of the Win32_QuickFixEngineering class.

        Caches result in script variable.

        .OUTPUTS
        [System.Management.ManagementObject#root\cimv2\Win32_QuickFixEngineering]

        .EXAMPLE
        Get-WmiHotfixes
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param ()

    if (-not $Script:WmiHotfixes)
    {
        $Script:WmiHotfixes = Get-WmiObject Win32_QuickFixEngineering
    }
    return $Script:WmiHotfixes
}
