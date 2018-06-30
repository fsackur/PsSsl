function Get-SslRegState
{
    <#
        .SYNOPSIS
        Gets the state of an SSL component.

        .DESCRIPTION
        Gets the state of an SSL component ("Enabled", "Disabled", "OS Default", or "Invalid reg value").

        .OUTPUTS
        [string]
        Current state ("Enabled", "Disabled", "OS Default", or "Invalid reg value").

        .EXAMPLE
        $Element = $Elements | where {$_.Name -eq 'TLS 1.0'}
        Get-SslRegState -SslComponent $Element

        Gets the current state of the 'TLS 1.0' component.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $SslComponent
    )

    switch ($SslComponent.RegValue)
    {
        $SslComponent.RegValue_Disabled {"Disabled"; break}
        $SslComponent.RegValue_Enabled {"Enabled"; break}
        $null {"OS Default"; break}
        default {"Invalid reg value: $_"}
    }
}