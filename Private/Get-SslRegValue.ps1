function Get-SslRegValue
{
    <#
        .SYNOPSIS
        Short description

        .DESCRIPTION
        Long description

        .OUTPUTS
        Reg value

        .EXAMPLE
        An example

        .NOTES
        General notes
    #>

    [CmdletBinding()]
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