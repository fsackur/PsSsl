function Get-RdpSecurityLayer
{
    <#
    .SYNOPSIS
    Gets the RDP security layer.

    .DESCRIPTION
    Gets the RDP security layer.

    .OUTPUTS
    [string]

    Returns 'Rdp', 'Negotiate', or 'Tls'.

    .EXAMPLE
    Get-RdpSecurityLayer

    Gets the RDP security layer.

    .LINK
    https://docs.microsoft.com/en-us/windows/desktop/termserv/win32-tsgeneralsetting
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $WmiObject = Get-WmiObject -Namespace "ROOT\CIMV2\TerminalServices" -Query "SELECT SecurityLayer FROM Win32_TSGeneralSetting"

    switch ($WmiObject.SecurityLayer)
    {
        0       {return 'Rdp'}
        1       {return 'Negotiate'}
        2       {return 'Tls'}
        default {throw "Error determining RDP security layer."}
    }
}
