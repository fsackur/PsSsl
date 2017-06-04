    function Get-SslRegLookupTable {
    <#
        .Synopsis
        Returns a hashtable of protocols and ciphers, and the registry edits needed to configure them.

        .Description
        We have no CLI tool to configure schannel ciphers and protocols. IISCryptoCLI does not offer per-protocol configuration.

        We do not want to hard-code each and every change. Given a protocol name, e.g. 'TLS 1.0', we want to be able to look up what reg edit to make to enable or disable it.

        Returns a hashtable where the keys are protocol and cipher names, e.g. 'TLS 1.0', 'Triple-DES', and the values are objects representing a registry property and the valid values for that property

        .Example
        PS C:\> $RegLookup = Get-SslRegLookupTable

        PS C:\> $RegLookup['TLS1.0']


        RegKey         : HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
        RegProperty    : Enabled
        Type           : DWord
        Value_Disabled : 0
        Value_Enabled  : 1

        Gets the registry locations and values required to enable or disable TLS 1.0.

        .Example
        PS C:\> $RegLookup = Get-SslRegLookupTable

        PS C:\> $RegLookup.Keys
        SSL2.0
        SSL3.0
        TLS1.0
        TLS1.1
        RC4 40
        RC4 56
        RC4 64
        RC4 128
        Diffie-Hellman
        ECDH

        Gets the valid names of protocols and ciphers to enable or disable. This list is extensible by editing the table in this function.

        .Example
        PS C:\> $RegLookup = Get-SslRegLookupTable

        PS C:\> $RegObj = $RegLookup['TLS1.0']

        PS C:\> Set-ItemProperty -LiteralPath $RegObj.RegKey -Name $RegObj.RegProperty -Value $RegObj.Value_Disabled

        Disables TLS 1.0. This does the same as Set-SslRegValues -Disable 'TLS1.0'

        .Notes
        Some reg keys contain forward slashes that are NOT path delimiters. However, forward slash IS a valid path delimiter in Windows. This causes problems with *-Item* cmdlets, as they intepret this forward slash and there is no way to escape it. To avoid errors, you must use the -LiteralPath parameter when working with these paths

    #>
        [CmdletBinding()]
        [OutputType([System.Collections.IDictionary])]
        param()

        if (Get-Variable RegLookup -Scope Script -ErrorAction SilentlyContinue) {return $Script:RegLookup}

        
        #Data table. Update this to extend support to other protocols and ciphers.
        $RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

        $Headers = (     'Category',     'RegKey',               'RegProperty', 'RegType', 'Value_Disabled', 'Value_Enabled')
        $Table = @( #     --------        ------                  -----------    -------    --------------    -------------
            ('SSL2.0',   'Protocols',    'SSL 2.0\Server',       'Enabled',     'DWord',    0,                1              ),
            ('SSL3.0',   'Protocols',    'SSL 3.0\Server',       'Enabled',     'DWord',    0,                1              ),
            ('TLS1.0',   'Protocols',    'TLS 1.0\Server',       'Enabled',     'DWord',    0,                1              ),
            ('TLS1.1',   'Protocols',    'TLS 1.1\Server',       'Enabled',     'DWord',    0,                1              ),
            ('RC4 40',   'Ciphers',      'RC4 40/128',           'Enabled',     'DWord',    0,                4294967295     ),     #0xffffffff
            ('RC4 56',   'Ciphers',      'RC4 56/128',           'Enabled',     'DWord',    0,                4294967295     ),
            ('RC4 64',   'Ciphers',      'RC4 64/128',           'Enabled',     'DWord',    0,                4294967295     ),
            ('RC4 128',  'Ciphers',      'RC4 128/128',          'Enabled',     'DWord',    0,                4294967295     ),
            ('Diffie-Hellman','KeyExchangeAlgorithms','Diffie-Hellman','Enabled','DWord',   0,                1              ),
            ('ECDH',     'KeyExchangeAlgorithms','ECDH',         'Enabled',     'DWord',    0,                1              )
        )


        #Table is most useful for datafile, but dictionary is better to work with
        $RegLookup = New-Object System.Collections.Specialized.OrderedDictionary

        #Convert table to dictionary
        foreach ($Row in $Table) {
            $RegObj = New-Object psobject

            #Add all columns as object properties
            for ($colnum=0; $colnum -lt $Headers.Count; $colnum++) {
                
                $ColHeader = $Headers[$colnum]
                $Value = $Row[$colnum + 1]

                $RegObj | Add-Member Noteproperty `
                    -Name $ColHeader `
                    -Value $Value
            }

            #Then add a final property by constructing full path of reg key
            $RegObj | Add-Member Noteproperty `
                -Name 'RegLiteralPath' `
                -Value ([string]::Format(
                    "{0}\{1}\{2}",
                    $RegParentPath,
                    $RegObj.Category,
                    $RegObj.RegKey
                ))
    
            $RegLookup.Add($Row[0], $RegObj)
        }

        return $RegLookup
    }
    
    $Script:RegLookup = Get-SslRegLookupTable
    

    function Get-SslRegValues {
    <#
        .Synopsis
        Returns registry values relating to SSL configuration

        .Description
        Returns all the current registry values for ciphers and protocols supported by this module.

        .Example
        PS C:\> Get-SslRegValues

        Name                           Value
        ----                           -----
        SSL2.0                         1
        SSL3.0                         1
        TLS1.0                         1
        TLS1.1                         1
        RC4 40                         0
        RC4 56                         0
        RC4 64                         0
        RC4 128                        0
        Diffie-Hellman                 4294967295
        ECDH                           4294967295

        Provides the current values of the registry properties that configure each protocol or cipher

    #>
        [CmdletBinding()]
        [OutputType([System.Collections.IDictionary])]
        param(
            [Parameter(Position=0)]
            [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable)
        )

        #New hashtable of same type as supplied one
        $RegValues = New-Object ($RegLookup.GetType())

        #Use the properties from supplied hashtable to look up in reg and populate new hashtable
        foreach ($Key in $RegLookup.Keys) {
            $Splat = @{
                LiteralPath = $RegLookup[$Key].RegLiteralPath;
                Name = $RegLookup[$Key].RegProperty;
                ErrorAction = 'Stop'
            }
            
            try {
                $Value = Get-ItemProperty @Splat | select -ExpandProperty $Splat.Name
            } catch [System.Management.Automation.ItemNotFoundException] {
                $Value = $null
            }
            if ($Value -eq -1) {$Value = 4294967295}   #workaround for int/uint32 casting
            $RegValues.Add($Key, $Value)
        }

        return $RegValues
    }


    function Set-SslRegValues {
    <#
        .Synopsis
        Sets registry values relating to SSL configuration

        .Description
        Sets any of the current registry values for ciphers and protocols supported by this module.

        .Parameter Enable
        A list of ciphers or protocols to enable
        
        .Parameter Disable
        A list of ciphers or protocols to disable

        .Parameter RegValues
        A hashtable of ciphers or protocols with the values for setting registry properties

        .Example
        PS C:\> Set-SslRegValues -Enable 'TLS1.1'

        Enables the TLS 1.1 protocol

        .Example
        PS C:\> Set-SslRegValues -Disable 'SSL3.0'

        Disables the SSL 3.0 protocol

        .Example
        PS C:\> Set-SslRegValues -Enable 'TLS1.1' -Disable 'SSL3.0', 'RC4 40', 'RC4 56'

        Enables the TLS 1.1 protocol and disables the SSL3.0 protocol and the RC4 40/128 and RC4 56/128 ciphers

        .Example
        PS C:\> $ValuesToSet = @{'TLS1.1'=1;'SSL3.0'=0}

        PS C:\> Set-SslRegValues -RegValues $ValuesToSet

        Enables the TLS 1.1 protocol and disables the SSL3.0 protocol

    #>
        [CmdletBinding(DefaultParameterSetName='RegValues')]
        [OutputType([void])]
        param(
            [Parameter(ParameterSetName='ProtocolList')]
            [ValidateSet(
                'SSL2.0', 'SSL3.0', 'TLS1.0', 'TLS1.1', 'RC4 40', 'RC4 56', 'RC4 64', 'RC4 128', 'Diffie-Hellman', 'ECDH'
            )]
            [string[]]$Enable,

            [Parameter(ParameterSetName='ProtocolList')]
            [ValidateSet(
                'SSL2.0', 'SSL3.0', 'TLS1.0', 'TLS1.1', 'RC4 40', 'RC4 56', 'RC4 64', 'RC4 128', 'Diffie-Hellman', 'ECDH'
            )]
            [string[]]$Disable,

            [Parameter(Mandatory=$true, Position=0, ParameterSetName='RegValues')]
            [System.Collections.IDictionary]$RegValues,

            [Parameter()]
            [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable),

            [Parameter()]
            [string]$BackupFile
        )

        
        if ($PSBoundParameters.ContainsKey('BackupFile')) {
            Export-SslRegBackup -Path $BackupFile
            $PSBoundParameters.Remove('BackupFile')
        }

        if ($PSCmdlet.ParameterSetName -eq 'ProtocolList') {
            $RegValues = New-SslRegValues @PSBoundParameters
        }

        #Use the properties from supplied hashtable to look up in reg and populate new hashtable
        foreach ($Key in $RegValues.Keys) {
            $Splat = @{
                LiteralPath = $RegLookup[$Key].RegLiteralPath;
                Name = $RegLookup[$Key].RegProperty;
                Value = $RegValues[$Key];
                ErrorAction = 'Stop';
                Force = $true;
            }
            if ($PSBoundParameters.ContainsKey('WhatIf')) {$Splat.WhatIf = $PSBoundParameters.WhatIf}
            try {
                Set-ItemProperty @Splat
            } catch [System.Management.Automation.ItemNotFoundException] {
                New-RegKey $Splat.LiteralPath
                Set-ItemProperty @Splat
            }
        }
    }

    function New-RegKey {
    <#
        .Synopsis
        Create a registry key

        .Description
        This exists as a separate function because it makes the code testable

        .Example
        PS C:\> New-RegKey -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'

        Creates a new empty registry key at the specified location, if none exists already

        .Link
        https://msdn.microsoft.com/en-us/library/aa389385(v=vs.85).aspx
    #>
        [CmdletBinding()]
        [OutputType([void])]
        param(
            [Parameter(Mandatory=$true, Position=0)]
            [string]$LiteralPath
        )

        [ValidateSet('HKCR','HKLM', 'HKCC', 'HKU', 'HKCU')]
        [string]$RootKey = $LiteralPath -replace ':.*'

        [string]$SubKey = $LiteralPath -replace '(HKCR|HKLM|HKCC|HKU|HKCU):\\'

        $RootKeyFlags = switch ($RootKey) {
            'HKCR' {2147483648}
            'HKCU' {2147483649}
            'HKLM' {2147483650}
            'HKU'  {2147483651}
            'HKCC' {2147483653}
        }

        $RegProvider = Get-WmiObject -List -Namespace 'ROOT\DEFAULT' | where {$_.Name -eq 'StdRegProv'}
        $Result = $RegProvider.CreateKey(
            $RootKeyFlags,
            $SubKey
        )

        switch ($Result.ReturnValue) {
            0 {return}
            5 {throw New-Object System.Security.SecurityException ('Requested registry access is not allowed.')}
            Default {throw "CreateKey failed with return value $_"}
        }

    }

    function New-SslRegValues {
    <#
        .Synopsis
        Creates a dictionary object of registry values relating to SSL configuration

        .Description
        Creates a new dictionary object with the correct registry values for any of the ciphers and protocols supported by this module.

        Enable arguments take precedence over disable arguments. If a protocol or cipher is specificed to both the Enable parameter and the Disable parameter, it will be enabled.

        .Parameter Enable
        A list of ciphers or protocols to enable
        
        .Parameter Disable
        A list of ciphers or protocols to disable

        .Example
        PS C:\> New-SslRegValues -Enable 'TLS1.1'

        Name                           Value
        ----                           -----
        TLS1.1                         1

        .Example
        PS C:\> New-SslRegValues -Disable 'SSL3.0'

        Name                           Value
        ----                           -----
        SSL3.0                         0

        .Example
        PS C:\> New-SslRegValues -Enable 'TLS1.1' -Disable 'SSL3.0', 'RC4 40', 'RC4 56'

        Name                           Value
        ----                           -----
        SSL3.0                         0
        TLS1.1                         1
        RC4 40                         0
        RC4 56                         0

    #>
        [CmdletBinding()]
        [OutputType([System.Collections.IDictionary])]
        param(
            [Parameter()]
            [ValidateSet(
                'SSL2.0', 'SSL3.0', 'TLS1.0', 'TLS1.1', 'RC4 40', 'RC4 56', 'RC4 64', 'RC4 128', 'Diffie-Hellman', 'ECDH'
            )]
            [string[]]$Enable,

            [Parameter()]
            [ValidateSet(
                'SSL2.0', 'SSL3.0', 'TLS1.0', 'TLS1.1', 'RC4 40', 'RC4 56', 'RC4 64', 'RC4 128', 'Diffie-Hellman', 'ECDH'
            )]
            [string[]]$Disable,

            [Parameter()]
            [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable)
        )

        $RegValues = @{}

        if ($Enable) {
            foreach ($Key in $Enable) {
                $RegValues.Add($Key, $RegLookup[$Key].Value_Enabled)
            }
        }
        if ($Disable) {
            foreach ($Key in $Disable) {
                if (-not $RegValues.Contains($Key)) {
                    $RegValues.Add($Key, $RegLookup[$Key].Value_Disabled)
                }
            }
        }
        return $RegValues
    }

    function Get-SslRegReport {
    <#
        .Synopsis
        Returns a collection of protocols and their configured status

        .Description
        For each protocol and cipher, return Enabled / Disabled / Not Configured / Invalid Value ($Value)

        .Parameter RegValues
        A hashtable of registry values. If not specified, the function reads the current values from the registry

        .Parameter RegValuesBefore
        A hashtable of registry values to use as the 'before' comparison side. If specified, only elements that differ will be output.

        .Parameter RegValuesAfter
        A hashtable of registry values to use as the 'after' comparison side. If RegValuesBefore is specified but RegValuesAfter is not, current registry values will be used. only elements that differ will be output.

        .Example
        PS C:\> Get-SslRegReport

        Property       Value         
        --------       -----         
        SSL2.0         Disabled
        SSL3.0         Disabled
        TLS1.0         Not configured
        TLS1.1         Not configured
        RC4 40         Not configured
        RC4 56         Not configured
        RC4 64         Not configured
        RC4 128        Not configured
        Diffie-Hellman Not configured
        ECDH           Enabled

        Returns current registry configurations. In this case, ECDH has been explicitly enabled; SSL 2.0 and SSL 3.0 have been explicitly disabled; all other elements have no explicit setting in the registry and will be enabled or disabled depending on OS default for that element

        .Example
        PS C:\> $ValuesToSet = New-SslRegValues -Disable 'SSL3.0'

        PS C:\> Get-SslRegReport $ValuesToSet

        Property       Value         
        --------       -----         
        SSL2.0         Not configured
        SSL3.0         Disabled      
        TLS1.0         Not configured
        TLS1.1         Not configured
        RC4 40         Not configured
        RC4 56         Not configured
        RC4 64         Not configured
        RC4 128        Not configured
        Diffie-Hellman Not configured
        ECDH           Not configured

        Prepares registry changes to commit and stores in variable $ValuesToSet. Reports on the changes that will be made when you pass $ValuesToSet to Set-SslRegValues

        .Example
        PS C:\> $ConfigBefore = Get-SslRegValues

        PS C:\> Set-SslRegValues -Disable 'SSL3.0'

        PS C:\> $ConfigAfter = Get-SslRegValues

        PS C:\> Get-SslRegReport -RegValuesBefore $ConfigBefore -RegValuesAfter $ConfigAfter

        Property       Value         
        --------       -----         
        SSL3.0         Disabled

        Reports on the effect of running Set-SslRegValues -Disable 'SSL3.0'. If SSL 3.0 was already disabled, there will be no output.

    #>
        [CmdletBinding(DefaultParameterSetName='Default')]
        [OutputType([System.Collections.IDictionary])]
        param(
            [Parameter(Mandatory=$false, ParameterSetName='Default', Position=0)]
            [System.Collections.IDictionary]$RegValues = (Get-SslRegValues),

            [Parameter(Mandatory=$true, ParameterSetName='BeforeAndAfter')]
            [System.Collections.IDictionary]$RegValuesBefore,

            [Parameter(Mandatory=$false, ParameterSetName='BeforeAndAfter')]
            [System.Collections.IDictionary]$RegValuesAfter  = (Get-SslRegValues),

            [Parameter()]
            [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable)
        )

        #Single set of values, no comparison to be performed
        if ($PSCmdlet.ParameterSetName -eq 'Default') {
            foreach ($Key in $RegLookup.Keys) {

                $Value = switch ($RegValues[$Key]) {
                    $RegLookup[$Key].Value_Enabled {"Enabled"}
                    $RegLookup[$Key].Value_Disabled {"Disabled"}
                    $null {"Not configured"}
                    Default {"Invalid value ($_)"}
                }
        
                New-Object psobject |
                    Add-Member -MemberType NoteProperty -Name 'Property' -Value $Key -PassThru | 
                    Add-Member -MemberType NoteProperty -Name 'Value' -Value $Value -PassThru
            }

        #Perform comparison between two sets of values and output the differences only
        } else {
            
            $ValuesBefore = Get-SslRegReport -RegValues $RegValuesBefore -RegLookup $RegLookup
            $ValuesAfter = Get-SslRegReport -RegValues $RegValuesAfter -RegLookup $RegLookup

            foreach ($Key in $RegLookup.Keys) {
                $Before = $ValuesBefore[$Key]
                $After = $ValuesAfter[$Key]
                if ($Before -like $After) {continue}   #Keep only the differences

                New-Object psobject |
                    Add-Member -MemberType NoteProperty -Name 'Property' -Value $Key -PassThru | 
                    Add-Member -MemberType NoteProperty -Name 'ValueBefore' -Value $Before -PassThru | 
                    Add-Member -MemberType NoteProperty -Name 'ValueAfter' -Value $After -PassThru
            }
        }
    }


    function DoIt {
        $RegLookup = Get-SslRegLookupTable
        $ConfigBefore = Get-SslRegValues
        #Get-SslRegReport -RegValues $ConfigBefore
        $ValuesToSet = New-SslRegValues -Disable 'SSL3.0', 'TLS1.1' -ENable 'SSL3.0'
        #Get-SslRegReport $ValuesToSet
        Set-SslRegValues -RegValues $ValuesToSet
        $ConfigAfter = Get-SslRegValues
        return Get-SslRegReport -RegValuesBefore $ConfigBefore -RegValuesAfter $ConfigAfter

    }
    

    function Test-SqlSupportsTls12 {
    <#
        .Synopsis
        Tests whether disabling TLS and SSL protocols will disrupt SQL Server connections

        .Description
        SQL Server 2016 is the first verison of SQL Server that supports TLS 1.2 on all builds. All previous versions require one or more updates to support TLS1.2.

        Disabling SSL and TLS protocols up to TLS 1.0 or TLS 1.1 on a server where the SQL components do not support TLS 1.2 is likely to break SQL.

        This function returns true if SQL is not installed, or if all installed components support TLS1.2. Returns false if any components do not support TLS1.2.

        .Example
        PS C:\> Test-SqlSupportsTls12

        False

        This tests for any installed SQL Server components and, if found, returns whether it is safe to disable SSL and TLS protocols up to TLS 1.0. If no installed SQL components are found, it returns true.
            
        .Link
        https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server

        .Link
        https://blogs.sentryone.com/aaronbertrand/tls-1-2-support-read-first/

        .Link
        https://blogs.msdn.microsoft.com/sqlreleaseservices/tls-1-2-support-for-sql-server-2008-2008-r2-2012-and-2014/
    #>
        [OutputType([bool])]
        param()

        $AffectedSqlComponents = @(
            'Database Engine',
            'Client Tools'
        )
        $AllSqlProducts = Get-WmiObject Win32_Product -Filter "Vendor LIKE 'Microsoft Corporation' AND Name LIKE 'SQL Server %'"
        $AffectedSqlProducts = $AllSqlProducts | where {$_.Name -match ($AffectedSqlComponents -join '|')}
        $SqlVersions = $AffectedSqlProducts | select -ExpandProperty Version

        $AllSqlVersionsSupportTls = $true

        foreach ($Version in $SqlVersions) {

            #sometimes 2008R2 shows up as 10.52
            if ($Version.Minor -gt 50) {$Version = [version]($Version.ToString() -replace $Version.Minor, '50')}

            #https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server
            $AllSqlVersionsSupportTls = $AllSqlVersionsSupportTls -and $(
                switch ($Version.Major) {

                    10
                        {($Version -ge [version]"10.50.6542.0")}

                    11
                        {($Version -ge [version]"11.0.6542.0") -or
                            ($Version -lt [version]"11.0.6020.0" -and $Version -ge [version]"11.0.5352.0")}

                    12
                        {($Version -ge [version]"12.0.4219.0") -or
                            ($Version -lt [version]"12.0.4100.0" -and $Version -ge [version]"12.0.2564.0")}

                    {$_ -ge 13}
                        {$true}

                    default
                        {$false}

                }
            )
        }

        return $AllSqlVersionsSupportTls
    }


    function Test-RdpSupportsTls12 {
    <#
        .Synopsis
        Tests whether disabling TLS and SSL protocols will disrupt RDP connections

        .Description
        Server 2008 does not support TLS 1.1 or TLS 1.2 on RDP connections that use TLS as a transport security layer. A hotfix is available (KB3080079) that enables these protocols

        Disabling SSL and TLS protocols up to TLS 1.0 or TLS 1.1 on a Server 2008 or 2008 R2 installation where the hotfix is not present may prevent RDP.

        This does not affect RDP connections that use the RDP security layer; however, TLS is frequently mandated by policy. It is best practice to install the relevant hotfix before altering the TLS configuration.

        This function returns true the server version is Server 2012 or greater, or if the server version is 2008 or 2008 R2 and the hotfix is installed.

        .Example
        PS C:\> Test-RdpSupportsTls12

        False

        This tests for RDP incompatibility with TLS 1.1 and TLS 1.2, and returns whether it is safe to disable SSL and TLS protocols up to TLS 1.0.
            
        .Link
        https://support.microsoft.com/en-us/help/3080079/update-to-add-rds-support-for-tls-1.1-and-tls-1.2-in-windows-7-or-windows-server-2008-r2
    #>
        [OutputType([bool])]
        param()

        $OsVersion = [version](Get-WmiObject Win32_OperatingSystem).Version
        if ($OsVersion -lt [version]"6.1") {
            return $false
        }
        if ($OsVersion -ge [version]"6.2") {
            return $true
        }
        $RdpHotfix = Get-WmiObject Win32_QuickFixEngineering -Filter "HotFixID LIKE 'KB3080079'"
        if ($RdpHotfix) {return $true}

        return $false
    }


    function Export-SslRegBackup {
    <#
        .Synopsis
        Backs up the schannel registry key

        .Description
        Backs up the schannel registry key and all subkeys to a .reg file that can be re-imported with REG IMPORT

        Will overwrite any existing file

        .Parameter Path
        The path to the .reg file to be created

        .Example
        PS C:\> Export-SslRegBackup -Path C:\TEMP\schannel.reg

        Backs up the schannel registry key and subkeys to C:\TEMP\schannel.reg. The backup can be restored with the command REG IMPORT C:\TEMP\schannel.reg
    #>
        [CmdletBinding()]
        [OutputType([void])]
        param(
            [ValidateScript({Test-Path $_ -IsValid})]
            [string]$Path
        )

        if (-not (Test-Path (Split-Path $Path))) {
            [void](New-Item (Split-Path $Path) -ItemType Directory -Force -ErrorAction Stop)
        }

        $RegParentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        $Key = $RegParentPath -replace 'HKLM:\\', 'HKLM\'
        
        Write-Verbose "Exporting schannel reg key: $(reg export $Key $Path /y)"

    }

    #RDP hotfix allows TLS 1.2
    if (
        (($Disable -contains 'SSL3.0') -or ($Disable -contains 'TLS1.0') -or ($Disable -contains 'TLS1.1')) -and
        ([version](Get-WmiObject Win32_OperatingSystem).Version -lt [version]"6.2") -and
        ($null -eq $(Get-HotFix KB3080079 -ErrorAction SilentlyContinue))
    ) {
        $Output.RegChanges = "Aborting; KB3080079 is not installed, or PS<3. Ref: https://support.microsoft.com/en-us/help/3080079/update-to-add-rds-support-for-tls-1.1-and-tls-1.2-in-windows-7-or-windows-server-2008-r2"
        return $Output
    }


    #SQL updates enable TLS 1.2
    if (
        (-not $SkipSqlChecks) -and
        (($Disable -contains 'TLS1.0') -or ($Disable -contains 'TLS1.1')) -and
        ($null -ne (Get-WmiObject -Namespace "ROOT\Microsoft\SqlServer" -Class "__Namespace"  -ErrorAction SilentlyContinue)) -and
        (-not (Get-InstalledSqlSupportsTls12))
    ) {
        $Output.RegChanges = "Aborting; SQL is installed but not all instances support TLS1.2. Ref: https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server"
        return $Output
    }

    #Don't disable old TLS or SSL if no newer are enabled

Export-ModuleMember @(
    #'New-RegKey',
    'Get-SslRegLookupTable',
    'Get-SslRegReport',
    'Get-SslRegValues',
    'New-SslRegValues',
    'Set-SslRegValues',
    'Test-SqlSupportsTls12',
    'Test-RdpSupportsTls12',
    'Export-SslRegBackup'
)