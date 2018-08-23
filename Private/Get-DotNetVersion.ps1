function Get-DotNetVersion {
    <#
        .SYNOPSIS
        Returns all installed versions of the .NET Framework.

        .DESCRIPTION
        Returns all installed versions of the .NET Framework.

        .EXAMPLE
        Get-DotNetVersion

        Returns all installed versions of the .NET Framework.

        .OUTPUTS
        [psobject[]]

        .LINK
        https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed

        .LINK
        https://support.microsoft.com/en-gb/help/318785/how-to-determine-which-versions-and-service-pack-levels-of-the-microso

        .LINK
        https://blogs.msdn.microsoft.com/astebner/2005/07/12/what-net-framework-version-numbers-go-with-what-service-pack/
    #>
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param ()

    $Rev45DisplayVersion = '"Revision","DisplayVersion"
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

    $VersionToDisplayVersion = '"Version","DisplayVersion"
        "4.0.30319.1","4.0"
        "3.5.30729.1","3.5 SP1"
        "3.5.21022.8","3.5"
        "3.0.04506.2152","3.0 SP2"
        "3.0.04506.648","3.0 SP1"
        "3.0.04506.26","3.0"
        "2.0.50727.3053","2.0 SP2"
        "2.0.50727.1433","2.0 SP1"
        "2.0.50727.42","2.0"
        "2.0.50215.44","2.0 Beta 2"
        "2.0.40607.16","2.0 Beta 1"
        "1.1.4322.2300","1.1 SP1"
        "1.1.4322.2032","1.1 SP1"
        "1.1.4322.573","1.1"
        "1.0.3705.6018","1.0 SP3"
        "1.0.3705.288","1.0 SP2"
        "1.0.3705.209","1.0 SP1"
        "1.0.3705.0","1.0"
    ' | ConvertFrom-Csv

    $RegKeyPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $KeyPattern = "^" + [regex]::Escape($RegKeyPath) + "\\(" + ("v4\\(Client|Full)$", "v[2-3].\d(\.\d+)?$" -join "|") + ")"
    $RegKeys    = Get-RegKey $RegKeyPath -Recurse |
        Where-Object {$_.Key -match $KeyPattern} |
        Select-Object Version, Release -Unique


    $DotNetVersions = New-Object System.Collections.ArrayList

    foreach ($RegKey in $RegKeys)
    {
        if ($RegKey.Release)
        {
            $Version = [version]($RegKey.Version, $RegKey.Release -join '.')
        }
        else
        {
            $Version = [version]$RegKey.Version
        }

        if ($Version -ge [version]"4.1")
        {
            $DisplayVersion = $Rev45DisplayVersion | Where-Object {$Version.Revision -ge $_.Revision} | Select-Object -ExpandProperty DisplayVersion -First 1
            #$dotNet4Builds.GetEnumerator() | Where-Object {$Version.Revision -ge $_.Name} | Select-Object -ExpandProperty Value -Last 1
        }
        else
        {
            $DisplayVersion = $VersionToDisplayVersion | Where-Object {$Version -ge [version]$_.Version} | Select-Object -ExpandProperty DisplayVersion -First 1
        }

        $DotNetVersion = New-Object psobject -Property @{
            Version = $Version
            DisplayVersion = $DisplayVersion
        }
        $null = $DotNetVersions.Add($DotNetVersion)
    }

    $DotNetVersions | Sort-Object Version -Descending
}
