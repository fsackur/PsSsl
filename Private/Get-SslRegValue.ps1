function Get-SslRegValue
{
    <#
        .SYNOPSIS
        Gets the registry value for an SSL component.

        .DESCRIPTION
        Gets the registry value for an SSL component.

        .OUTPUTS
        [uint32]
        [string]
        Registry value.

        .EXAMPLE
        $Element = $Elements | where {$_.Name -eq 'TLS 1.0'}
        Get-SslRegState -SslComponent $Element

        Gets the registry value governing the 'TLS 1.0' component.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $SslComponent
    )

    try
    {
        $SslComponent.RegValue = (
            Get-ItemProperty -LiteralPath $SslComponent.RegLiteralPath -Name $SslComponent.RegName -ErrorAction Stop
        ).($SslComponent.RegName)
    }
    catch
    {
        $SslComponent.RegValue = $null
    }

    return $SslComponent.RegValue
}