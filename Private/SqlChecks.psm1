function Get-NetFrameworkVersion {
    <#

    Script Name	: Get-NetFrameworkVersion.ps1
    Description	: This script reports the various .NET Framework versions installed on the local or a remote computer.
    Author		: Martin Schvartzman
    Last Update	: Aug-2016
    Keywords	: NETFX, Registry
    Reference   : https://msdn.microsoft.com/en-us/library/hh925568

    #>

    param($ComputerName = $env:COMPUTERNAME)

    $dotNetRegistry  = 'SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $dotNet4Registry = 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $dotNet4Builds = @{
	    30319  =  '.NET Framework 4.0'
	    378389 = '.NET Framework 4.5'
	    378675 = '.NET Framework 4.5.1 (8.1/2012R2)'
	    378758 = '.NET Framework 4.5.1 (8/7 SP1/Vista SP2)'
	    379893 = '.NET Framework 4.5.2' 
	    380042 = '.NET Framework 4.5 and later with KB3168275 rollup'
	    393295 = '.NET Framework 4.6 (Windows 10)'
	    393297 = '.NET Framework 4.6 (NON Windows 10)'
	    394254 = '.NET Framework 4.6.1 (Windows 10)'
	    394271 = '.NET Framework 4.6.1 (NON Windows 10)'
	    394802 = '.NET Framework 4.6.2 (Windows 10 Anniversary Update)'
	    394806 = '.NET Framework 4.6.2 (NON Windows 10)'
    }

    foreach($Computer in $ComputerName) {

	    if($regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)) {

		    if ($netRegKey = $regKey.OpenSubKey("$dotNetRegistry")) {
			    foreach ($versionKeyName in $netRegKey.GetSubKeyNames()) {
				    if ($versionKeyName -match '^v[123]') {
					    $versionKey = $netRegKey.OpenSubKey($versionKeyName)
					    $version = [version]($versionKey.GetValue('Version', ''))
					    New-Object -TypeName PSObject -Property @{
						    ComputerName = $Computer
						    NetFXBuild = $version.Build
						    NetFXVersion = '.NET Framework ' + $version.Major + '.' + $version.Minor
					    } | Select-Object ComputerName, NetFXVersion, NetFXBuild
				    }
			    }
		    }

		    if ($net4RegKey = $regKey.OpenSubKey("$dotNet4Registry")) {
			    if(-not ($net4Release = $net4RegKey.GetValue('Release'))) {
				    $net4Release = 30319
			    }
			    New-Object -TypeName PSObject -Property @{
				    ComputerName = $Computer
				    NetFXBuild = $net4Release
				    NetFXVersion = $dotNet4Builds[$net4Release]
			    } | Select-Object ComputerName, NetFXVersion, NetFXBuild
		    }
	    }
    }
}

function Get-InstalledPrograms {
    #from https://github.com/Microsoft/tigertoolbox/tree/master/tls1.2
    #We use this rather than Win32_Product because it's faster and because querying the WMI class can trigger actions
    $array = @()
    
    #Define the variable to hold the location of Currently Installed Programs
        $UninstallKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        #Create an instance of the Registry Object and open the HKLM base key
        $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey("LocalMachine", $env:COMPUTERNAME)
        #Drill down into the Uninstall key using the OpenSubKey Method
        $regkey=$reg.OpenSubKey($UninstallKey)
        #Retrieve an array of string that contain all the subkey names
        $subkeys=$regkey.GetSubKeyNames()
        #Open each Subkey and use GetValue Method to return the required values for each
        foreach($key in $subkeys) {
            $thisKey = "$UninstallKey\$key"
            $thisSubKey=$reg.OpenSubKey($thisKey)
            $obj = New-Object PSObject
            foreach ($Property in 'DisplayName', 'DisplayVersion', 'InstallLocation', 'Publisher') {
                Add-Member -InputObject $obj `
                    -MemberType NoteProperty `
                    -Name $Property `
                    -Value $thisSubKey.GetValue($Property)
            }
            $array += $obj
        }
    return $array
}

function Get-SqlTlsUpdatesRequired {
<#
    .Synopsis
    Given a SQL version, returns the updates that must be applied before disabling TLS 1.0

    .Description
    This is just a big switch statement based on the info at https://sqlserverbuilds.blogspot.co.uk/

    Output is an array of strings; one per update

    Strings are human readable, and tell you what to install and what URL to download it from

    .Parameter Version
    SQL version to check

    .Example
    Get-SqlTlsUpdatesRequired 10.50.0.4000

    Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271
    Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144113&kbln=en-us
    Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034

    .Link
    https://sqlserverbuilds.blogspot.co.uk/
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [version]$Version
    )

    $KBs = @()
    switch ($Version) {
        #2008 RTM
        {$_.Major -eq 10 -and $_.Minor -lt 50}
            {
                switch ($Version.Build) {
                    {$_ -lt 6547}   {$KBs += 'Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034'} #Intermittent service terminations
                    {$_ -lt 6543}   {$KBs += 'Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144113&kbln=en-us'} #TLS Update https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server
                    {$_ -lt 6000}   {$KBs += 'Apply SP4 from http://www.microsoft.com/en-us/download/details.aspx?id=44278'} #SP4
                }
                break
            }

        #2008 R2
        {$_.Major -eq 10 -and $_.Minor -ge 50}
            {
                switch ($Version.Build) {
                    {$_ -lt 6542}   {$KBs += 'Apply intermittent service termination hotfix from https://support.microsoft.com/en-us/kb/3146034'}
                    {$_ -lt 6537}   {$KBs += 'Apply TLS hotfix from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3144113&kbln=en-us'}
                    {$_ -lt 6000}   {$KBs += 'Apply SP3 from http://www.microsoft.com/en-us/download/details.aspx?id=44271'}
                }
                break
            }
                    
        #2012
        {$_.Major -eq 11}
            {
                #If we're below SP3 but on or above SP2 CU10, then no change
                if ($Version.Build -lt 6020 -and $Version.Build -ge 5644) {break}

                #Below 6518, apply SP3 & at least CU1
                switch ($Version.Build) {
                    {$_ -lt 6518}   {$KBs += 'Apply CU1 (or later) from https://support.microsoft.com/en-us/kb/3123299'}
                    {$_ -lt 6020}   {$KBs += 'Apply SP3 from https://www.microsoft.com/en-us/download/details.aspx?id=49996'}
                }
                break
            }
                
        #2014
        {$_.Major -eq 12}
            {
                #If we're above SP2, then no change
                if ($Version.Build -ge 5000) {break}

                #If we're below SP2 but on or above SP1 CU5, then no change
                if ($Version.Build -lt 5000 -and $Version.Build -ge 4439) {break}

                #If we're below SP1 but on or above RTM CU12, then no change
                if ($Version.Build -lt 4050 -and $Version.Build -ge 2564) {break}

                #Otherwise, recommend SP2
                $KBs += 'Apply SP2 from https://www.microsoft.com/en-us/download/details.aspx?id=53168'

                break
            }
                
        #2016
        {$_.Major -ge 13}
            {
                break
            }


        Default
            {
                $KBs += "Version $Version not known by the SQL TLS compatibility calculator."
            }
    }

    [array]::Reverse($KBs)

    return $KBs
}

function Test-SqlTls12Readiness {
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
    $MssqlPrograms = Get-InstalledPrograms | where {$_.DisplayName -match 'SQL' -and $_.Publisher -match 'Microsoft'}
    $DbEnginePrograms = $MssqlPrograms | where {$_.DisplayName -match 'Database Engine'}
    $AdoNetPrograms = $MssqlPrograms | where {$_.DisplayName -match 'Report|Management Studio'}
    $NativeClientPrograms = $MssqlPrograms | where {$_.DisplayName -match 'Native Client'}
    $OdbcPrograms = $MssqlPrograms | where {$_.DisplayName -match 'ODBC'}
        
    #Script provides poor output; parse to get a version from the newest version installed
    #Null if .NET is not installed
    $DotNetClientVersion = Get-NetFrameworkVersion | 
        sort NetFXVersion | 
        select -Last 1 |
        select -ExpandProperty NetFxVersion |
        foreach {$_ -replace '.NET Framework ' -replace ' .*'} |
        foreach {[version]$_}
    #endregion Installed program discovery


    #region Schannel client config discovery
    $OsVersion = [version](Get-WmiObject Win32_OperatingSystem).Version
    $ClientTls11Enabled = $true
    try {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
        $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
        $ClientTls11Enabled = $RegValue -ge 1
    } catch [System.Management.Automation.ItemNotFoundException] {
        $ClientTls11Enabled = $OsVersion -ge [version]"6.2"
    }
        
    $ClientTls12Enabled = $true
    try {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
        $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
        $ClientTls12Enabled = $RegValue -ge 1
    } catch [System.Management.Automation.ItemNotFoundException] {
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
        Add-Member -PassThru -MemberType NoteProperty -Name SupportsTls12 -Value $true |  #this gets ANDed with all the assessment results
        Add-Member -PassThru -MemberType NoteProperty -Name ClientTls11Enabled -Value $ClientTls11Enabled |
        Add-Member -PassThru -MemberType NoteProperty -Name ClientTls12Enabled -Value $ClientTls12Enabled |
        Add-Member -PassThru -MemberType NoteProperty -Name DbEngine -Value (
                New-Object psobject | 
                    Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Value $ToString -Force |
                    Add-Member -PassThru -MemberType NoteProperty -Name Installed -Value $false
                ) |
        Add-Member -PassThru -MemberType NoteProperty -Name AdoNet -Value (
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
            $Updates = Get-SqlTlsUpdatesRequired -Version $Version

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
        $Output.SupportsTls12 = $Output.SupportsTls12 -and $Output.DbEngine.SqlSupportsTls12
    }
    

    if ($AdoNetPrograms -or $DotNetClientVersion) {
        $Output.AdoNet.Installed = $true

        $DotNetUpdatesRequired = @()
        if ($DotNetClientVersion -lt [version]"4.6") {

            if ($DotNetClientVersion -ge [version]"4.0" -and $DotNetClientVersion -lt [version]"4.5") {
                $DotNetUpdatesRequired += 'Install KB3106994 from https://support.microsoft.com/en-us/help/3106994'
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
                    1   {
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

                    default {$DotNetUpdatesRequired += "OS is not supported"}

                }
            }
        }

        $Output.AdoNet | Add-Member -MemberType NoteProperty -Name AdoNetComponentsInstalled -Value (
            $AdoNetPrograms | select -ExpandProperty DisplayName | select -Unique)
        $Output.AdoNet | Add-Member -MemberType NoteProperty -Name DotNetVersion -Value $DotNetClientVersion
        $Output.AdoNet | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value $DotNetUpdatesRequired
        $Output.AdoNet | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value (
            $DotNetUpdatesRequired.Count -eq 0 -and ($ClientTls11Enabled -or $ClientTls12Enabled))
        $Output.SupportsTls12 = $Output.SupportsTls12 -and $Output.AdoNet.SupportsTls12
    }


    if ($NativeClientPrograms) {
        $Output.Snac.Installed = $true

        $UpdatesRequired = @()

        foreach ($SNAC in $NativeClientPrograms) {
            
            $Version = [version]$SNAC.DisplayVersion

            $UpdatesRequired += switch ($Version.Major) {
                #2012, 2014 (all SNAC versions from 2012 are called 2012 / v11)
                {$_.Major -eq 11 -and $_.Build -lt 6538}
                    {'Update the SQL Server Native Client from https://www.microsoft.com/en-us/download/details.aspx?id=50402'}
            
                #2008 R2
                {$_.Major -eq 10 -and $_.Minor -ge 50 -and $_.Build -lt 6537}
                    {'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098860&kbln=en-us'}

                #2008
                {$_.Major -eq 10 -and $_.Minor -lt 50 -and $_.Build -lt 6543}
                    {'Update the SQL Server Native Client from https://support.microsoft.com/en-us/hotfix/kbhotfix?kbnum=3098869&kbln=en-us'}

                default {}
            }
        }
        
        $Output.Snac | Add-Member -MemberType NoteProperty -Name NativeClientInstalled -Value (
            $NativeClientPrograms | select -ExpandProperty DisplayName | select -Unique)
        $Output.Snac | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value (
            $UpdatesRequired | select -Unique)
        $Output.Snac | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value ($UpdatesRequired.Count -eq 0)
        $Output.SupportsTls12 = $Output.SupportsTls12 -and $Output.Snac.SupportsTls12
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

        $Output.Odbc | Add-Member -MemberType NoteProperty -Name OdbcDriverInstalled -Value (
            $OdbcPrograms | select -ExpandProperty DisplayName | select -Unique)
        $Output.Odbc | Add-Member -MemberType NoteProperty -Name UpdatesRequired -Value (
            $UpdatesRequired | select -Unique)
        $Output.Odbc | Add-Member -MemberType NoteProperty -Name SupportsTls12 -Value ($UpdatesRequired.Count -eq 0)
        $Output.SupportsTls12 = $Output.SupportsTls12 -and $Output.Odbc.SupportsTls12
    }
    #endregion Populate component reports


    $Output.DbEngine, $Output.AdoNet, $Output.Snac, $Output.Odbc | 
        where {$_.UpdatesRequired} | foreach {$Output.UpdatesRequired += $_.UpdatesRequired}

    return $Output
}
