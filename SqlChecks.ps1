
if (-not (Test-Path "$PSScriptRoot\Get-NetFrameworkVersion.ps1")) {throw "Missing $PSScriptRoot\Get-NetFrameworkVersion.ps1"}

function Get-InstalledPrograms {
    #from https://github.com/Microsoft/tigertoolbox/tree/master/tls1.2
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
    param(
        [Parameter(Mandatory=$true)]
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


function Get-SqlTls12Report {

    #Get-WmiObject -Class Win32reg_AddRemovePrograms | Where-Object {$_.DisplayName -like "*SQL*" -and $_.Publisher -like "*Microsoft*"} | Select DisplayName,Version
    $MssqlPrograms = Get-InstalledPrograms | where {$_.DisplayName -match 'SQL' -and $_.Publisher -match 'Microsoft'}
    $DbEnginePrograms = $MssqlPrograms | where {$_.DisplayName -match 'Database Engine'}
    $AdoNetPrograms = $MssqlPrograms | where {$_.DisplayName -match 'Report|Management Studio'}
    $NativeClientPrograms = $MssqlPrograms | where {$_.DisplayName -match 'Native Client'}
    $OdbcPrograms = $MssqlPrograms | where {$_.DisplayName -match 'ODBC'}
        #SSMS, report server, report manager require ADO.NET to support tls1.2  https://blogs.msdn.microsoft.com/sqlreleaseservices/tls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014/
        #Reporting Services Configuration Manager fix HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client : REG_DWORD=Enabled, "Enabled"=dword:00000001
        #[System.Reflection.Assembly]::GetAssembly([System.Data.SqlClient.SqlConnection]).Version
        #[System.Data.Common.DbProviderFactories]::GetFactoryClasses()
    
    #Get-Hotfix doesn't work in PS v2.0
    #$HotfixesInstalled = Get-WmiObject Win32_QuickFixEngineering


    #SSMS, report server, report manager require ADO.NET to support tls1.2  https://blogs.msdn.microsoft.com/sqlreleaseservices/tls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014/
    #Reporting Services Configuration Manager fix HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client : REG_DWORD=Enabled, “Enabled”=dword:00000001
    
    $Report = New-Object psobject -Property @{
        Computer = $env:COMPUTERNAME
        SupprtsTls12 = $true
    }


    if ($DbEnginePrograms) {
        
        $DbRequiredUpdates = @()

        #Sometimes installing updates doesn't update the SQL version in the reg key. A more reliable way to check
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

        $Report | Add-Member -MemberType NoteProperty -Name SqlInstancesInstalled -Value (
            $DbEngineInstances | select -ExpandProperty Instance)
        $Report | Add-Member -MemberType NoteProperty -Name SqlInstancesNoTls12 -Value (
            $DbEngineInstances | where {-not $_.SupportsTls12} | select -ExpandProperty Instance)
        $Report | Add-Member -MemberType NoteProperty -Name SqlUpdatesRequired -Value $DbRequiredUpdates
    }
    

    if ($AdoNetPrograms) {

        $OsVersion = [version](Get-WmiObject Win32_OperatingSystem).Version

        #Script provides poor output; parse to get a version from the newest version installed
        $DotNetClientVersion = & $PSScriptRoot\Get-NetFrameworkVersion.ps1 | 
            sort NetFXVersion | 
            select -Last 1 |
            select -ExpandProperty NetFxVersion |
            foreach {$_ -replace '.NET Framework ' -replace ' .*'} |
            foreach {[version]$_}




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

        
        $ClientTls11Enabled = $true
        try {
            $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
            $ClientTls11Enabled = $RegValue -eq 1
        } catch [System.Management.Automation.ItemNotFoundException] {
            
            $ClientTls11Enabled = $OsVersion -ge [version]"6.2"
        }
        
        $ClientTls12Enabled = $true
        try {
            $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            $RegValue = (Get-ItemProperty $RegPath -Name 'Enabled' -ErrorAction Stop).Enabled
            $ClientTls12Enabled = $RegValue -eq 1
        } catch [System.Management.Automation.ItemNotFoundException] {
            $OS = Get-WmiObject Win32_OperatingSystem
            $ClientTls12Enabled = $OsVersion -ge [version]"6.2"
        }


        $Report | Add-Member -MemberType NoteProperty -Name AdoNetComponentsInstalled -Value (
            $AdoNetPrograms | select -ExpandProperty DisplayName | select -Unique)
        $Report | Add-Member -MemberType NoteProperty -Name DotNetVersion -Value $DotNetClientVersion
        $Report | Add-Member -MemberType NoteProperty -Name DotNetUpdatesRequired -Value $DotNetUpdatesRequired
        $Report | Add-Member -MemberType NoteProperty -Name ClientTls11Enabled -Value $ClientTls11Enabled
        $Report | Add-Member -MemberType NoteProperty -Name ClientTls12Enabled -Value $ClientTls12Enabled
        $Report | Add-Member -MemberType NoteProperty -Name AdoNetSupportsTls12 -Value (
            $DotNetUpdatesRequired.Count-eq 0 -and ($ClientTls11Enabled -or $ClientTls12Enabled))

    }


    return $Report
}

Get-SqlTls12Report | fl
