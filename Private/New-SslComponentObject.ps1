function New-SslConfigElement
{
    <#
        .Synopsis
        Returns a configurable Schannel element

        .Description
        Workaround for no class support. Returns object with CurrentState property and Enable() and Disable() methods
    #>
    param (
        $ElementName,
        $RegMidPath,
        $RegChildPath,
        $RegName,
        $RegType,
        $RegValue_Disabled,
        $RegValue_Enabled,
        $RegParentPath = $Script:RegParentPath
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