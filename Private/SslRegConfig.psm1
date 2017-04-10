<#
    .Synopsis
    A module to directly set registry values for Schannel rpotocols, ciphers and key-exchange algorithms

    .Description
    This is a mid-level module. It is intended to be consumed by higher-level modules that manage compatibility tests, e.g. RDP and SQL compatibility.
#>



#region private functions

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

    $Table = Import-Csv $PSScriptRoot\RegLookup.csv

    #Table is most useful for datafile, but dictionary is better to work with
    $RegLookup = New-Object System.Collections.Specialized.OrderedDictionary

    #Convert table to dictionary
    foreach ($Row in $Table) {
        $RegObj = New-Object psobject -Property @{
            Category = $Row.Category;
            RegKey = $Row.RegKey;
            RegLiteralPath = ([string]::Format(
                "{0}\{1}\{2}",
                $RegParentPath,
                $Row.Category,
                $Row.RegKey
            ));
            RegProperty = $Row.RegProperty;
            RegType = $Row.RegType;
            Value_Disabled = [uint32]$Row.Value_Disabled;
            Value_Enabled = [uint32]$Row.Value_Enabled
        }
        $RegLookup.Add($Row.Name, $RegObj)
    }

    return $RegLookup
}


function Get-SslDynamicParameter {
<#
    .Synopsis

    .Description

    .Parameter ParameterName
    The name of the parameter to construct. Users of the function will see this as an available parameter

    .Example
    PS C:\> Get-SslDynamicParameter -ParameterName 'Enable' -Property @{Mandatory=$true}

    Name          : Enable
    ParameterType : System.String[]
    Value         : 
    IsSet         : False
    Attributes    : {__AllParameterSets, System.Management.Automation.ValidateSetAttribute}

    Returns a dynamic parameter that can be added as a value to a dynamic parameter dictionary in a function DynamicParam block
#>
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ParameterName,

        [Parameter(Mandatory=$false, Position=1)]
        [hashtable]$Property = @{}
    )
    $ParameterType = [string[]]

    $ParameterAttribute = [System.Management.Automation.ParameterAttribute]$Property
 
    $ValidateAttribute = (New-Object System.Management.Automation.ValidateSetAttribute((Get-SslRegLookupTable).Keys))

    $Attributes = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    $Attributes.Add($ParameterAttribute)
    $Attributes.Add($ValidateAttribute)
 
    $Parameter = New-Object System.Management.Automation.RuntimeDefinedParameter(
        $ParameterName, 
        $ParameterType, 
        $Attributes
    )

    return $Parameter
}

#endregion private functions


#region public functions

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
        [Parameter(DontShow=$true)]
        [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable)
    )

    dynamicparam {
        $DynamicParameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $DynamicParameters.Add('Enable', (Get-SslDynamicParameter 'Enable'))
        $DynamicParameters.Add('Disable', (Get-SslDynamicParameter 'Disable'))
        return $DynamicParameters
    }

    begin {
        $Enable = $PSBoundParameters.Enable
        $Disable = $PSBoundParameters.Disable
    }


    end {
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
}


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
            $Value = (Get-ItemProperty @Splat).$($Splat.Name)
        } catch {
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
    PS C:\> $ValuesToSet = @{'TLS1.1'=1;'SSL3.0'=0}; Set-SslRegValues -RegValues $ValuesToSet

    Enables the TLS 1.1 protocol and disables the SSL3.0 protocol

#>
    [CmdletBinding(DefaultParameterSetName='RegValues')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='RegValues')]
        [System.Collections.IDictionary]$RegValues,

        [Parameter()]
        [System.Collections.IDictionary]$RegLookup = (Get-SslRegLookupTable),

        [Parameter()]
        [string]$BackupFile
    )

    dynamicparam {
        $DynamicParameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $DynamicParameters.Add(
            'Enable', 
            (Get-SslDynamicParameter 'Enable' @{ParameterSetName='ProtocolList'})
        )
        $DynamicParameters.Add(
            'Disable', 
            (Get-SslDynamicParameter 'Disable' @{ParameterSetName='ProtocolList'})
        )
        return $DynamicParameters
    }
    
    begin {
        if ($PSBoundParameters.ContainsKey('BackupFile')) {
            Export-SslRegBackup -Path $BackupFile
            $PSBoundParameters.Remove('BackupFile')
        }

        if ($PSCmdlet.ParameterSetName -eq 'ProtocolList') {
            $RegValues = New-SslRegValues @PSBoundParameters
        }
    }

    end {
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
        } #end foreach
    }
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

#endregion public functions



#If you want to use this module as a standalone module, uncomment the export block below
<#
Export-ModuleMember @(
    #'Get-SslRegLookupTable',
    'Get-SslRegReport',
    'Get-SslRegValues',
    'New-SslRegValues',
    'Set-SslRegValues',
    'Export-SslRegBackup'
)
#>
