function Get-SqlTls12Report {

#Get-WmiObject -Class Win32reg_AddRemovePrograms | Where-Object {$_.DisplayName -like "*SQL*" -and $_.Publisher -like "*Microsoft*"} | Select DisplayName,Version
    $MssqlPrograms = Get-InstalledPrograms | where {$_.DisplayName -match 'SQL' -and $_.Publisher -match 'Microsoft'}
    $DbEnginePrograms = $MssqlPrograms | where {$_.DisplayName -match 'Database Engine'}
    $AdoNetPrograms = $MssqlPrograms | where {$_.DisplayName -match 'Report|Management Studio'}

        #SSMS, report server, report manager require ADO.NET to support tls1.2  https://blogs.msdn.microsoft.com/sqlreleaseservices/tls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014/
        #Reporting Services Configuration Manager fix HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client : REG_DWORD=Enabled, “Enabled”=dword:00000001
        #[System.Reflection.Assembly]::GetAssembly([System.Data.SqlClient.SqlConnection]).Version
        #[System.Data.Common.DbProviderFactories]::GetFactoryClasses()
    $DotNetClientVersion = [version](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client' -Name Version).Version
    $HotfixesInstalled = Get-WmiObject Win32_QuickFixEngineering




    $Version -lt 1











    foreach ($Version in $SqlVersions) {

        #sometimes 2008R2 shows up as 10.52
        if ($Version.Minor -gt 50) {$Version = [version]($Version.ToString() -replace $Version.Minor, '50')}

        $AllSqlVersionsSupportTls = $AllSqlVersionsSupportTls -and $(

            $KBs = @()
            switch ($Version.Major) {

                10
                    {
                        if ($Version.Minor -lt 50) {
                            switch ($Version.Build) {
                                {$_ -lt 6547}   {$KBs += 'https://support.microsoft.com/en-us/kb/3146034'}
                                {$_ -lt 6543}   {$KBs += 'https://support.microsoft.com/en-us/kb/3135244'}
                                {$_ -lt 6000}   {$KBs += 'http://www.microsoft.com/en-us/download/details.aspx?id=44278'}
                            }    
                        } else {
                            switch ($Version.Build) {
                                {$_ -lt 6542}   {$KBs += 'https://support.microsoft.com/en-us/kb/3146034'}
                                {$_ -lt 6537}   {$KBs += 'https://support.microsoft.com/en-us/kb/3135244'}
                                {$_ -lt 6000}   {$KBs += 'http://www.microsoft.com/en-us/download/details.aspx?id=44271'}
                            }
                        }
                        break
                    }
                    

                11
                    {
                        #If we're below SP3 but on SP2 CU10, then no change
                        if ($Version.Build -lt 6020 -and $Version.Build -ge 5644) {break}

                        #Below 6518, apply SP3 & CU1
                        switch ($Version.Build) {
                            {$_ -lt 6518}   {$KBs += 'https://support.microsoft.com/en-us/kb/3123299'}
                            #Alternatively, TLS update
                            #{$_ -lt 6216}   {$KBs += ''}

                            #Below SP3? Apply SP3
                            {$_ -lt 6020 -and $_ -gt }   {$KBs += 'https://www.microsoft.com/en-us/download/details.aspx?id=49996'}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                        }
                        break
                    }

                12
                    {
                        switch ($Version.Build) {
                            {$_ -lt 6518}   {$KBs += 'https://support.microsoft.com/en-us/kb/3123299'}
                            {$_ -lt 6215}   {$KBs += ''}
                            {$_ -lt 6020 -and $_ -gt }   {$KBs += 'https://www.microsoft.com/en-us/download/details.aspx?id=49996'}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                            {$_ -lt }   {$KBs += ''}
                        }
                        break
                    }

                {$_ -ge 13}
                    {$true}

                default
                    {$false}

            }
        )
    }

}

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