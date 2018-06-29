function Get-SslRegState
{
    <#
        .DESCRIPTION
        The current effective value for the schannel element ("Enabled", "Disabled", "OS Default", "Invalid reg value")

        .EXAMPLE
        PS C:\> $Element = $Elements | where {$_.Name -eq 'TLS 1.0'}
        PS C:\> $Element.CurrentState
        Enabled
    #>
    [CmdletBinding()]
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