function New-SslComponentObject
{
    <#
        .SYNOPSIS
        Returns a configurable SSL component.

        .DESCRIPTION
        Returns an object representing a component of SSL configuration.

        The object has CurrentState property and Enable() and Disable() methods.

        .OUTPUTS
        [psobject]
        An object representing a component of SSL configuration.

        .PARAMETER ElementName
        Parameter description

        .PARAMETER RegMidPath
        Parameter description

        .PARAMETER RegChildPath
        Parameter description

        .PARAMETER RegName
        Parameter description

        .PARAMETER RegType
        Parameter description

        .PARAMETER RegValue_Disabled
        Parameter description

        .PARAMETER RegValue_Enabled
        Parameter description

        .PARAMETER RegParentPath
        Parameter description

        .EXAMPLE
        An example

        .NOTES
        Workaround for no class support in old versions of Powershell.
    #>
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param
    (
        [Parameter(Mandatory)]
        [string]$ElementName,

        [Parameter(Mandatory)]
        [string]$RegMidPath,

        [Parameter(Mandatory)]
        [string]$RegChildPath,

        [Parameter(Mandatory)]
        [string]$RegName,

        [Parameter(Mandatory)]
        [string]$RegType,

        [Parameter(Mandatory)]
        [string]$RegValue_Disabled,

        [Parameter(Mandatory)]
        [string]$RegValue_Enabled,

        [Parameter()]
        [string]$RegParentPath = $Script:RegParentPath
    )

    try {[void]$PSBoundParameters.Remove('RegParentPath')} catch {}

    $Element = New-Object psobject -Property $PSBoundParameters
    $Element | Add-Member NoteProperty -Name RegLiteralPath -Value ($RegParentPath, $RegMidPath, $RegChildPath -join '\')
    $Element | Add-Member ScriptMethod -Name GetRegValue -Value {
        Get-SslRegValue -SslComponent $this
    }.GetNewClosure()

    $Element | Add-Member NoteProperty -Name RegValue -Value $null
    [void]$Element.GetRegValue()  #populate the property

    $Element | Add-Member ScriptProperty -Name CurrentState -Value {
        Get-SslRegState -SslComponent $this
    }.GetNewClosure()


    $Element | Add-Member ScriptMethod -Name Disable -Value {
        [CmdletBinding()]
        param
        (
            [Parameter(Position = 0)]
            [System.Collections.Generic.List[string]]$ChangeLog
        )
        $PSBoundParameters.Add('SslComponent', $this)
        $PSBoundParameters.Add('Value', $this.RegValue_Disabled)
        Set-SslRegValue @PSBoundParameters
    }.GetNewClosure()

    $Element | Add-Member ScriptMethod -Name Enable -Value {
        [CmdletBinding()]
        param (
            [Parameter(Position = 0)]
            [System.Collections.Generic.List[string]]$ChangeLog
        )
        $PSBoundParameters.Add('SslComponent', $this)
        $PSBoundParameters.Add('Value', $this.RegValue_Enabled)
        Set-SslRegValue @PSBoundParameters
    }.GetNewClosure()

    return $Element
}