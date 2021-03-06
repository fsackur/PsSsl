function Set-SslComponent
{
    <#
        .SYNOPSIS
        Enable or disable SSL components.

        .DESCRIPTION
        Enable or disable SSL components, such as protocols, ciphers and key exchange algorithms.

        .OUTPUTS
        [psobject]
        Object representing the state of the operation.

        .PARAMETER ElementsToDisable
        SSL components to disable.

        .PARAMETER ElementsToEnable
        SSL components to enable.

        .PARAMETER Force
        Do not prompt before making changes.

        .EXAMPLE
        Set-SslComponent -ElementsToEnable 'TLS 1.2'

        Enables TLS 1.2.

        .NOTES
        Both enabling and disabling SSL components is risky to application functionality, and requires a reboot.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter()]
        [string[]]$ElementsToDisable,

        [Parameter()]
        [string[]]$ElementsToEnable,

        [Parameter()]
        [switch]$Force
    )


    #Skip the user validation if the force parameter is used
    if ((-not $Force) -and ((Read-Host "Warning: you are about to edit Schannel reg settings. Are you sure you wish to continue? (Y/N)") -notlike "y*")) {exit}

    $OS = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop

    $Output = New-Object psobject -Property @{
        Server    = $env:COMPUTERNAME;
        OS        = $OS.Caption;
        ChangeLog = New-Object System.Collections.Generic.List[string];
        ErrorLog  = "";
    }


    #Data table. Update this to extend support to other protocols and ciphers.
    $RegLookupCsv = "
        ElementName,RegMidPath,RegChildPath,RegName,RegType,RegValue_Disabled,RegValue_Enabled
        SSL 2.0,Protocols,SSL 2.0\Server,Enabled,DWord,0,1
        SSL 2.0 DbD,Protocols,SSL 2.0\Server,DisabledByDefault,DWord,1,0
        SSL 3.0,Protocols,SSL 3.0\Server,Enabled,DWord,0,1
        SSL 3.0 DbD,Protocols,SSL 3.0\Server,DisabledByDefault,DWord,1,0
        TLS 1.0,Protocols,TLS 1.0\Server,Enabled,DWord,0,1
        TLS 1.0 DbD,Protocols,TLS 1.0\Server,DisabledByDefault,DWord,1,0
        TLS 1.1,Protocols,TLS 1.1\Server,Enabled,DWord,0,1
        TLS 1.1 DbD,Protocols,TLS 1.1\Server,DisabledByDefault,DWord,1,0
        TLS 1.2,Protocols,TLS 1.2\Server,Enabled,DWord,0,1
        TLS 1.2 DbD,Protocols,TLS 1.2\Server,DisabledByDefault,DWord,1,0
        RC4 40/128,Ciphers,RC4 40/128,Enabled,DWord,0,4294967295
        RC4 56/128,Ciphers,RC4 56/128,Enabled,DWord,0,4294967295
        RC4 64/128,Ciphers,RC4 64/128,Enabled,DWord,0,4294967295
        RC4 128/128,Ciphers,RC4 128/128,Enabled,DWord,0,4294967295
        Diffie-Hellman,KeyExchangeAlgorithms,Diffie-Hellman,Enabled,DWord,0,1
        ECDH,KeyExchangeAlgorithms,ECDH,Enabled,DWord,0,1
    "

    #trim out whitespace and break into lines
    $RegLookupDataTable = New-Object System.Collections.Generic.List[array]
    $RegLookupCsv -split "\r\n" |
        where {$_ -match '[^\s]'} |
        foreach {$_ -replace '\s\s+'} |
        foreach {$RegLookupDataTable.Add($_ -split ',\s*')}

    #Prepare to convert to objects
    $RegLookupSplats = @()
    foreach ($Row in ($RegLookupDataTable | select -Skip 1))
    {
        $Splat = @{}
        for ($i = 0; $i -lt $RegLookupDataTable[0].Count; $i++)
        {
            $Splat.Add($RegLookupDataTable[0][$i], $Row[$i])
        }
        $RegLookupSplats += $Splat
    }

    $RegConfig = New-Object System.Collections.Specialized.OrderedDictionary
    $RegLookupSplats | foreach {
        $RegConfig[$_.ElementName] = New-SslComponentObject @_
    }

    <#
        We now have something similar to a static class, where each key is the name of an
        Schannel configurable element and each value exposes Enable() and Disable()

        So you can do: $RegConfig.'TLS 1.0'.Disable()

        It is the user's responsibility to include the DisabledByDefault elements where appropriate
    #>



    #Now we can do input validation! (to do this in param block would require dynamic params)
    $ValidValues = $RegConfig.Keys | where {$_ -notmatch 'DbD$'}
    if
    (
        ($ElementsToDisable | where {$ValidValues -notcontains $_}) -or
        ($ElementsToEnable | where {$ValidValues -notcontains $_})
    )
    {
        $Output.ErrorLog = "Input was not in valid values: $($ValidValues -join ', ')"
        return $Output
    }

    $BothEnableAndDisable = $ElementsToEnable | where {$_ElementsToDisable -contains $_}
    if ($BothEnableAndDisable)
    {
        $Output.ErrorLog = "$($BothEnableAndDisable -join ', ') specified twice - aborting"
    }

    #the validation is case-insensitive, but we need an exact match for dictionary lookup
    $ElementsToDisable = $ValidValues | where {$ElementsToDisable -contains $_}
    $ElementsToEnable = $ValidValues | where {$ElementsToEnable -contains $_}





    $RegBackupPath = "$env:TEMP\schannel_backup_$((Get-Date -Format s) -replace ':', '-').reg"
    Export-SslRegBackup -Path $RegBackupPath
    if (-not (Test-Path $RegBackupPath))
    {
        $Output.ErrorLog = "Failed to back up registry; aborting"
        return $Output
    }


    if ($ElementsToDisable)
    {
        foreach ($Element in $ElementsToDisable)
        {
            $RegConfig.$Element.Disable($Output.ChangeLog)
            $DbD = $Element + " DbD"
            if ($RegConfig.$DbD)
            {
                $RegConfig.$DbD.Disable($Output.ChangeLog)
            }
        }
    }

    if ($ElementsToEnable)
    {
        foreach ($Element in $ElementsToEnable)
        {
            $RegConfig.$Element.Enable($Output.ChangeLog)
            $DbD = $Element + " DbD"
            if ($RegConfig.$DbD)
            {
                $RegConfig.$DbD.Enable($Output.ChangeLog)
            }
        }
    }

    $Output.ChangeLog = $Output.ChangeLog -join "`n"
    return $Output
}
