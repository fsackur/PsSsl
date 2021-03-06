function Export-SslRegBackup
{
    <#
        .SYNOPSIS
        Backs up the ssl registry key.

        .DESCRIPTION
        Backs up the ssl registry key and all subkeys to a .reg file that can be re-imported with REG IMPORT.

        Will overwrite any existing file.

        .OUTPUTS
        [void]
        This command does not return any output.

        .PARAMETER Path
        The path to the .reg file to be created.

        .EXAMPLE
        PS C:\> Export-SslRegBackup -Path C:\TEMP\schannel.reg

        Backs up the schannel registry key and subkeys to C:\TEMP\schannel.reg. The backup can be restored
        with the command REG IMPORT C:\TEMP\schannel.reg.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [ValidateScript( {Test-Path $_ -IsValid})]
        [string]$Path
    )

    if (-not $PSBoundParameters.ContainsKey('Path'))
    {
        $Path = "$env:TEMP\schannel_backup_$((Get-Date -Format s) -replace ':', '-').reg"
    }

    if (-not (Test-Path (Split-Path $Path)))
    {
        [void](New-Item (Split-Path $Path) -ItemType Directory -Force -ErrorAction Stop)
    }

    $RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    $Key = $RegParentPath -replace 'HKLM:\\', 'HKLM\'

    Write-Verbose "Exporting schannel reg key: $(reg export $Key $Path /y)"
}
