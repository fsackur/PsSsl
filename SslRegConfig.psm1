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

        $Headers = (     'RegKey',                          'RegProperty', 'Type',  'Value_Disabled', 'Value_Enabled')
        $Table = @( #     -------                            ------------   -----    ---------------   -------------
            ('SSL2.0',   'Protocols\SSL 2.0\Server',           'Enabled',  'DWord', 0,                1              ),
            ('SSL3.0',   'Protocols\SSL 3.0\Server',           'Enabled',  'DWord', 0,                1              ),
            ('TLS1.0',   'Protocols\TLS 1.0\Server',           'Enabled',  'DWord', 0,                1              ),
            ('TLS1.1',   'Protocols\TLS 1.1\Server',           'Enabled',  'DWord', 0,                1              ),
            ('RC4 40',   'Ciphers\RC4 40/128',                 'Enabled',  'DWord', 0,                4294967295     ),     #0xffffffff
            ('RC4 56',   'Ciphers\RC4 56/128',                 'Enabled',  'DWord', 0,                4294967295     ),
            ('RC4 64',   'Ciphers\RC4 64/128',                 'Enabled',  'DWord', 0,                4294967295     ),
            ('RC4 128',  'Ciphers\RC4 128/128',                'Enabled',  'DWord', 0,                4294967295     ),
       ('Diffie-Hellman','KeyExchangeAlgorithms\Diffie-Hellman','Enabled', 'DWord', 0,                1              ),
            ('ECDH',     'KeyExchangeAlgorithms\ECDH',         'Enabled',  'DWord', 0,                1              )
        )


        #Table is most useful for datafile, but dictionary is better to work with
        $RegLookup = New-Object System.Collections.Specialized.OrderedDictionary

        #Convert table to dictionary
        foreach ($Row in $Table) {
            $RegObj = New-Object psobject

            for ($colnum=0; $colnum -lt $Headers.Count; $colnum++) {
                
                $ColHeader = $Headers[$colnum]
                $Value = $Row[$colnum + 1]

                #replace relative path of reg key with full path
                if ($ColHeader -eq 'RegKey') {$Value = "$RegParentPath\$Value"}

                $RegObj | Add-Member Noteproperty `
                    -Name $ColHeader `
                    -Value $Value
            }
    
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
                LiteralPath = $RegLookup[$Key].Regkey;
                Name = $RegLookup[$Key].RegProperty;
                ErrorAction = 'SilentlyContinue'
            }
            $Value = $null
            $Value = Get-ItemProperty @Splat | select -ExpandProperty $Splat.Name
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
            [ValidateScript({$Script:RegLookup.Contains($_)})]
            [string[]]$Enable,

            [Parameter(ParameterSetName='ProtocolList')]
            [ValidateScript({$Script:RegLookup.Contains($_)})]
            [string[]]$Disable,

            [Parameter(Mandatory=$true, Position=0, ParameterSetName='RegValues')]
            [System.Collections.IDictionary]$RegValues,

            [Parameter()]
            [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable)
        )

        if ($PSCmdlet.ParameterSetName -eq 'ProtocolList') {
            $RegValues = New-SslRegValues @PSBoundParameters
        }

        #Use the properties from supplied hashtable to look up in reg and populate new hashtable
        foreach ($Key in $RegValues.Keys) {
            $Splat = @{
                LiteralPath = $RegLookup[$Key].Regkey;
                Name = $RegLookup[$Key].RegProperty;
                Value = $RegValues[$Key];
                ErrorAction = 'SilentlyContinue';
                Force = $true;
            }
            if ($PSBoundParameters.ContainsKey('WhatIf')) {$Splat.WhatIf = $PSBoundParameters.WhatIf}
            Set-ItemProperty @Splat
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
            [ValidateScript({$Script:RegLookup.Contains($_)})]
            [string[]]$Enable,

            [Parameter()]
            [ValidateScript({$Script:RegLookup.Contains($_)})]
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
        For each protocol and cipher, 

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

        } else {

            $ValuesBefore = Get-SslRegReport -RegValues $RegValuesBefore -RegLookup $RegLookup
            $ValuesAfter = Get-SslRegReport -RegValues $RegValuesAfter -RegLookup $RegLookup

            foreach ($Key in $RegLookup.Keys) {
                $Before = $ValuesBefore[$Key]
                $After = $ValuesAfter[$Key]
                if ($Before -like $After) {continue}

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
                
