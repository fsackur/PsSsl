function Test-SqlTls12Readiness
{
    <#
        .Synopsis
        Assesses safety of disabling TLS 1.0 and below on SQL Server components that the current machine either serves or connects to

        .Description
        Assesses safety of disabling TLS 1.0 and below on SQL Server components that the current machine either serves or connects to.

        Checks database engine, ADO.NET, SQL native client, and ODBC.

        Returns a structured psobject.
    #>
    [CmdletBinding()]
    param ()

    #region Installed program discovery
    $MssqlPrograms = Get-InstalledSoftware | where {$_.Name -match 'SQL'}
    $DbEnginePrograms = $MssqlPrograms | where {$_.Name -match 'Database Engine'}
    $AdoDotNetPrograms = $MssqlPrograms | where {$_.Name -match 'Report|Management Studio'}
    $NativeClientPrograms = $MssqlPrograms | where {$_.Name -match 'Native Client'}
    $OdbcPrograms = $MssqlPrograms | where {$_.Name -match 'ODBC'}

    #Script provides poor output; parse to get a version from the newest version installed
    #Null if .NET is not installed
    $DotNetClientVersion = Get-DotNetVersion |
        select -ExpandProperty Version |
        sort |
        select -Last 1
    #endregion Installed program discovery


    #region Schannel client config discovery
    $OS = Get-WmiObject Win32_OperatingSystem
    $OsVersion = [version]$OS.Version
    $ClientTls11Enabled = $false
    try {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
        $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
        $ClientTls11Enabled = $RegValue -ne 0
    } catch [System.Management.Automation.ItemNotFoundException], [System.Management.Automation.ActionPreferenceStopException] {
        $ClientTls11Enabled = $OsVersion -ge [version]"6.2"
    }

    $ClientTls12Enabled = $false
    try {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
        $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
        $ClientTls12Enabled = $RegValue -ne 0
    } catch [System.Management.Automation.ItemNotFoundException], [System.Management.Automation.ActionPreferenceStopException] {
        $ClientTls12Enabled = $OsVersion -ge [version]"6.2"
    }
    #endregion Schannel client config discovery


    #region Create output object
    #Makes display of structured object more useful; overrides default ToString() of sub-objects
    $ToString = {
        if (-not $this.Installed) {return "Not installed"}
        if ($this.SupportsTls12) {return "Supports TLS 1.2"}
        return "Does not support TLS 1.2"
    }

    #PS v2 doesn't support ordered hashtable so, if we want our properties ordered, we need to use Add-Member.
    $Output = New-Object psobject |
        Add-Member -PassThru -MemberType NoteProperty -Name ComputerName -Value $env:COMPUTERNAME |
        Add-Member -PassThru -MemberType NoteProperty -Name OS -Value $OS.Caption |
        Add-Member -PassThru -MemberType NoteProperty -Name SupportsTls12 -Value $false |  #Assume false in case report returns early - see github review
        Add-Member -PassThru -MemberType NoteProperty -Name ClientTls11Enabled -Value $ClientTls11Enabled |
        Add-Member -PassThru -MemberType NoteProperty -Name ClientTls12Enabled -Value $ClientTls12Enabled |
        Add-Member -PassThru -MemberType NoteProperty -Name DbEngine -Value (
                New-Object psobject |
                    Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Value $ToString -Force |
                    Add-Member -PassThru -MemberType NoteProperty -Name Installed -Value $false
                ) |
        Add-Member -PassThru -MemberType NoteProperty -Name AdoDotNet -Value (
                New-Object psobject |
                    Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Value $ToString -Force |
                    Add-Member -PassThru -MemberType NoteProperty -Name Installed -Value $false
                ) |
        Add-Member -PassThru -MemberType NoteProperty -Name Snac -Value (
                New-Object psobject |
                    Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Value $ToString -Force |
                    Add-Member -PassThru -MemberType NoteProperty -Name Installed -Value $false
                ) |
        Add-Member -PassThru -MemberType NoteProperty -Name Odbc -Value (
                New-Object psobject |
                    Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Value $ToString -Force |
                    Add-Member -PassThru -MemberType NoteProperty -Name Installed -Value $false
                ) |
        Add-Member -PassThru -MemberType NoteProperty -Name UpdatesRequired -Value @()
    #endregion Create output object


    #region Populate component reports
    if ($DbEnginePrograms) {
        $Output.DbEngine.Installed = $true

        $DbRequiredUpdates = @()

        #Sometimes installing updates doesn't update the SQL version in the reg key. File version is reliable
        $DbEngineInstances = Get-WmiObject Win32_Service -Filter "PathName LIKE '%sqlservr.exe%'" | select `
            @{Name='Instance'; Expression={$_.DisplayName -replace '.*\(' -replace '\)'}},
            PathName

        foreach ($Instance in $DbEngineInstances) {
            $Invocation = $Instance.PathName

            #Strip out the CLI switches from the WMI Service PathName property
            if (('"', "'") -contains $Invocation[0]) {
                #First character is a quotemark
                $End = $Invocation.Substring(1).IndexOf($Invocation[0])
                $Path = $Invocation.Substring(1, $End)

            } else {
                #No leading quotemark; strip out everything after the first whitespace
                $Path = $Invocation -replace '\s.*'
            }

            $Instance.PathName = $Path
            $Version = [version](Get-Item $Path).VersionInfo.ProductVersion
            $Updates = Get-Tls12DbEngineRequiredUpdates -Version $Version

            $Instance | Add-Member -MemberType NoteProperty -Name Version -Value $Version
            $Instance | Add-Member -MemberType NoteProperty -Name RequiredUpdates -Value $Updates
            $Instance | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value $true

            if ($Updates) {
                $Instance.SupportsTls12 = $false
                $DbRequiredUpdates += $Updates
            }
        }

        $DbRequiredUpdates = $DbRequiredUpdates | select -Unique

        $Output.DbEngine | Add-Member -MemberType NoteProperty -Name SqlInstancesInstalled -Value (
            $DbEngineInstances | select -ExpandProperty Instance)
        $Output.DbEngine | Add-Member -MemberType NoteProperty -Name SqlInstancesNoTls12 -Value (
            $DbEngineInstances | where {-not $_.SupportsTls12} | select -ExpandProperty Instance)
        $Output.DbEngine | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value $DbRequiredUpdates
        $Output.DbEngine | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value ($DbRequiredUpdates.Count -eq 0)
    }


    if ($AdoDotNetPrograms -or $DotNetClientVersion) {
        $Output.AdoDotNet.Installed = $true

        $DotNetUpdatesRequired = @()
        if ($DotNetClientVersion -lt [version]"4.6") {

            if ($DotNetClientVersion -ge [version]"4.0" -and $DotNetClientVersion -lt [version]"4.5") {
                $DotNetUpdatesRequired += 'Install KB3106994 from https://support.microsoft.com/en-us/help/3106994'

            } elseif ($OsVersion.Major -lt 6) {
                #2003
                $DotNetUpdatesRequired += "limited to TLS 1.0 for this OS version"

            } else {
                #Win 10 ships with 4.6 so we know OS major version -eq 6
                switch ($OsVersion.Minor) {
                    #2012 R2
                    3   {
                            $DotNetUpdatesRequired += 'Apply KB3099842 from https://support.microsoft.com/en-us/help/3099842'
                        }

                    #2012 RTM
                    2   {
                            $DotNetUpdatesRequired += 'Apply KB3099844 from https://support.microsoft.com/en-us/help/3099844'
                        }

                    #2008 RTM & R2
                    {$_ -le 1}   {
                            switch ($DotNetClientVersion) {
                                {$_ -ge [version]"4.5.3"} {break}

                                {$_ -ge [version]"4.5.1"}   {
                                    $DotNetUpdatesRequired += 'Apply KB3099845 from https://support.microsoft.com/en-us/help/3099845'
                                    break
                                }

                                {$_ -ge [version]"4.0"}   {
                                    $DotNetUpdatesRequired += 'Install .NET 4.5.1 or higher from https://www.microsoft.com/en-gb/download/details.aspx?id=40779'
                                    break
                                }

                                {$_ -ge [version]"3.5"}   {
                                    $DotNetUpdatesRequired += 'Install KB3106991 from https://support.microsoft.com/en-us/help/3106991'
                                    break
                                }
                            }
                        }

                    default {$DotNetUpdatesRequired += "OS not recognised"}
                }
            }
        }

        $Output.AdoDotNet | Add-Member -MemberType NoteProperty -Name AdoDotNetComponentsInstalled -Value (
            $AdoDotNetPrograms | select -ExpandProperty Name | select -Unique)
        $Output.AdoDotNet | Add-Member -MemberType NoteProperty -Name DotNetVersion -Value $DotNetClientVersion
        $Output.AdoDotNet | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value $DotNetUpdatesRequired
        $Output.AdoDotNet | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value (
            $DotNetUpdatesRequired.Count -eq 0 -and ($ClientTls11Enabled -or $ClientTls12Enabled))
    }


    if ($NativeClientPrograms) {
        $Output.Snac.Installed = $true

        $UpdatesRequired = @()

        foreach ($SNAC in $NativeClientPrograms) {

            $Version = [version]$SNAC.Version

            $UpdatesRequired += switch ($Version) {
                #2012, 2014 (all SNAC versions from 2012 are called 2012 / v11)
                {$_.Major -eq 11 -and $_.Build -lt 6538}
                    {'Update the SQL Server Native Client from https://www.microsoft.com/en-us/download/details.aspx?id=50402'}

                #2008 R2
                {$_.Major -eq 10 -and $_.Minor -ge 50 -and $_.Build -lt 6537}
                    {'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098860&kbln=en-us'}

                #2008
                {$_.Major -eq 10 -and $_.Minor -lt 50 -and $_.Build -lt 6543}
                    {'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098869&kbln=en-us'}

                #2005
                {$_.Major -lt 10}
                    {'Version not known; newer version may be required'}

                default { <#implies $_.Major -gt 11, so if that ever happens it will presumably support TLS 1.2#> }
            }
        }

        $Output.Snac | Add-Member -MemberType NoteProperty -Name NativeClientsInstalled -Value (
            $NativeClientPrograms | select -ExpandProperty Name | select -Unique)
        $Output.Snac | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value (
            $UpdatesRequired | select -Unique)
        $Output.Snac | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value ($UpdatesRequired.Count -eq 0)
    }


    if ($OdbcPrograms) {
        $Output.Odbc.Installed = $true

        $UpdatesRequired = @()

        foreach ($Odbc in $OdbcPrograms)
        {
            $Version = [version]$Odbc.DisplayVersion
            if ($Version -lt [version]"12.0.4219") {
                $Updates += 'Update SQL ODBC driver from https://www.microsoft.com/en-us/download/details.aspx?id=36434'
            }
        }

        $Output.Odbc | Add-Member -MemberType NoteProperty -Name OdbcDriversInstalled -Value (
            $OdbcPrograms | select -ExpandProperty Name | select -Unique)
        $Output.Odbc | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value (
            $UpdatesRequired | select -Unique)
        $Output.Odbc | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value ($UpdatesRequired.Count -eq 0)
    }
    #endregion Populate component reports

    $Output.SupportsTls12 = $Output.DbEngine.SupportsTls12 -and
                            $Output.AdoDotNet.SupportsTls12 -and
                            $Output.Snac.SupportsTls12 -and
                            $Output.Odbc.SupportsTls12 -and
                            $OsVersion -ge [version]"6.1" #2008 R2

    if ($OsVersion -lt [version]"6.1") {$Output.UpdatesRequired += "OS: this version does not support TLS 1.1 or 1.2"}  #below 2008 R2
    $Output.DbEngine.UpdatesRequired | where {$_} | foreach {$Output.UpdatesRequired += "SQL: {0}" -f $_}
    $Output.AdoDotNet.UpdatesRequired   | where {$_} | foreach {$Output.UpdatesRequired += ".NET: {0}" -f $_}
    $Output.Snac.UpdatesRequired     | where {$_} | foreach {$Output.UpdatesRequired += "SNAC: {0}" -f $_}
    $Output.Odbc.UpdatesRequired     | where {$_} | foreach {$Output.UpdatesRequired += "ODBC: {0}" -f $_}

    return $Output
}
