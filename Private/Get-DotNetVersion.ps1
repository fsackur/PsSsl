function Get-DotNetVersion {
    <#
        .SYNOPSIS
        Returns all installed versions of the .NET Framework from 2.0 up.

        .DESCRIPTION
        Returns all installed versions of the .NET Framework from 2.0 up.

        .NET framework versions below 2.0 are not reported.

        .PARAMETER AsString
        Specifies to return strings. By default, version objects are returned.

        .OUTPUTS
        [version[]]

        By default, version objects are returned.

        [string[]]

        When the -AsString parameter is specified, strings are returned.

        .EXAMPLE
        Get-DotNetVersion

        Major  Minor  Build  Revision
        -----  -----  -----  --------
        4      7      1      -1
        4      0      -1     -1
        3      5      1      -1
        3      0      2      -1
        2      0      2      -1

        Returns all installed versions of the .NET Framework from 2.0 up.

        .EXAMPLE
        Get-DotNetVersion -AsString

        4.7.1
        4.0
        3.5.1
        3.0.2
        2.0.2

        Returns all installed versions of the .NET Framework from 2.0 up, as a collection of strings.

        .LINK
        https://support.microsoft.com/en-gb/help/318785/how-to-determine-which-versions-and-service-pack-levels-of-the-microso
    #>
    [CmdletBinding(DefaultParameterSetName = 'AsVersion')]
    [OutputType([version[]], ParameterSetName = 'AsVersion')]
    [OutputType([string[]],  ParameterSetName = 'AsString')]
    param
    (
        [Parameter(ParameterSetName = 'AsString')]
        [switch]$AsString
    )

    $V45DisplayVersionLookup = '"Release","DisplayVersion"
        "461814","4.7.2"
        "461808","4.7.2"
        "461310","4.7.1"
        "461308","4.7.1"
        "460805","4.7"
        "460798","4.7"
        "394806","4.6.2"
        "394802","4.6.2"
        "394271","4.6.1"
        "394254","4.6.1"
        "393297","4.6"
        "393295","4.6"
        "379893","4.5.2"
        "378758","4.5.1"
        "378675","4.5.1"
        "378389","4.5"
    ' | ConvertFrom-Csv


    $DisplayVersions = New-Object System.Collections.ArrayList
    $RegKeyPath      = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'


    # .NET 4.5 and above
    $V45Releases = "$RegKeyPath\v4\Client", "$RegKeyPath\v4\Full" |
        Get-RegValue -Name Release |
        Select-Object -ExpandProperty Value -Unique

    foreach ($Release in $V45Releases)
    {
        $DisplayVersions += $V45DisplayVersionLookup |
            Where-Object {$Release -ge $_.Release} |
            Select-Object -ExpandProperty DisplayVersion -First 1
    }


    # .NET 4.0
    $V40IsInstalled = $null -ne (
        "$RegKeyPath\v4\Client", "$RegKeyPath\v4\Full" |
        Get-RegValue -Name Install |
        Select-Object -ExpandProperty Value -Unique |
        Where-Object {$_ -band 1}
    )

    if ($V40IsInstalled) {$DisplayVersions += "4.0"}


    # .NET 3.5
    $V35Key = Get-RegKey "$RegKeyPath\v3.5" |
        Select-Object Install, SP |
        Where-Object {$_.Install -band 1}

    if ($V35Key)
    {
        if ($V35Key.SP -band 1)
        {
            $DisplayVersions += "3.5.1"
        }
        else
        {
            $DisplayVersions += "3.5"
        }
    }


    # .NET 3.0
    $V30IsInstalled = $null -ne (
        Get-RegValue "$RegKeyPath\v3.0\Setup" -Name InstallSuccess |
            Where-Object {$_.Value -band 1}
    )

    $V30ServicePack = Get-RegValue "$RegKeyPath\v3.0" -Name SP |
        Select-Object -ExpandProperty Value

    if ($V30IsInstalled) {
        if ($V30ServicePack)
        {
            $DisplayVersions += "3.0.$V30ServicePack"
        }
        else
        {
            $DisplayVersions += "3.0"
        }
    }


    # .NET 2.0
    $V20Key = Get-RegKey "$RegKeyPath\v2.0.50727" |
        Select-Object Install, SP |
        Where-Object {$_.Install -band 1}
    if ($V20Key)
    {
        if ($V20Key.SP)
        {
            $DisplayVersions += "2.0.$($V20Key.SP)"
        }
        else
        {
            $DisplayVersions += "2.0"
        }
    }


    if ($PSCmdlet.ParameterSetName -eq 'AsVersion')
    {
        $DisplayVersions | ForEach-Object {[version]$_}
    }
    else
    {
        $DisplayVersions
    }
}
