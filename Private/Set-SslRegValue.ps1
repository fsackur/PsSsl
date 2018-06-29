function Set-SslRegValue
{
    <#
        .DESCRIPTION
        Sets the registry value for the schannel element

        .EXAMPLE
        PS C:\> $Element = $Elements | where {$_.Name -eq 'TLS 1.0'}
        PS C:\> $Element.SetRegValue(0)

        .EXAMPLE
        PS C:\> $Element = $Elements | where {$_.Name -eq 'TLS 1.0'}
        PS C:\> $Changes = New-Object System.Collections.Generic.List[string]
        PS C:\> $Element.SetRegValue(0, $Changes)
        PS C:\> $Changes
        TLS 1.0\Server\Enabled changed from 1 to 0

        .PARAMETER RegValue
        The value to be saved in the registry for the current element's reg path. Type varies depending on reg value type.

        .PARAMETER ChangeLog
        An optional string collection for verbose output. If this is not specified, verbose output follows VerbosePreference.
    #>
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        $SslComponent,

        [Parameter(Mandatory = $true, Position = 1)]
        $RegValue,

        [Parameter()]
        [System.Collections.Generic.List[string]]$ChangeLog
    )
    $PreviousValue = $SslComponent.RegValue
    try
    {
        #Create key if it doesn't exist. Have to use .CreateSubKey() because New-Item doesn't support forward slash
        if (-not (Test-Path $SslComponent.RegLiteralPath))
        {
            $Root, $Key = $SslComponent.RegLiteralPath -split ':\\'
            $Root += ':\'
            [void](Get-Item $Root).CreateSubKey($Key)
        }

        #Reg Dwords are UInt32, but New-ItemProperty takes Int32 - even if you specify Dword. This is a pain.
        #0xffffffff is 4294967295 as a UInt, but -1 as an Int32. You have to provide -1 to New-ItemProperty.
        #This bitwise conversion does that, so our function can accept 4294967295 as input.
        if ($SslComponent.RegType -match 'Dword')
        {
            $Bytes = [System.BitConverter]::GetBytes([Int64]$RegValue)
            $RegValue = [System.BitConverter]::ToInt32($Bytes, 0)
        }

        $Splat = @{
            LiteralPath  = $SslComponent.RegLiteralPath;
            Name         = $SslComponent.RegName;
            Value        = $RegValue;
            PropertyType = $SslComponent.RegType;
            Force        = [switch]::Present
        }
        New-ItemProperty @Splat -ErrorAction Stop | Out-Null

        $NewValue = $SslComponent.GetRegValue()

        #Reg stores 0xffffffff; PS casts to Int32, i.e., -1. This converts it back to UInt numeric value,
        #so 0xffffffff displays as 4294967295 instead of -1.
        if ($SslComponent.RegType -match 'Dword')
        {
            trap {continue}
            $PreviousValue = [System.BitConverter]::ToUInt32(([System.BitConverter]::GetBytes($PreviousValue)), 0)
            $NewValue = [System.BitConverter]::ToUInt32(([System.BitConverter]::GetBytes($NewValue)), 0)
        }


        if ($NewValue -eq $PreviousValue)
        {
            $LogEntry = ($SslComponent.RegChildPath, $SslComponent.RegName -join '\') + " remains at " + $PreviousValue
        }
        else
        {
            $LogEntry = "{0} changed from {1} to {2}" -f (
                ($SslComponent.RegChildPath, $SslComponent.RegName -join '\'),
                $(if ($null -eq $PreviousValue) {"Not configured"} else {$PreviousValue}),
                $(if ($null -eq $SslComponent.RegValue) {"Not configured"} else {$NewValue})
            )
        }

        if ($PSBoundParameters.ContainsKey("ChangeLog"))
        {
            $ChangeLog.Add($LogEntry)
        }
        else
        {
            Write-Verbose $LogEntry
        }
    }
    catch
    {
        $LogEntry = ($SslComponent.RegChildPath, $SslComponent.RegName -join '\') +
        " failed to set value: " +
        $_.ToString()

        if ($PSBoundParameters.ContainsKey("ChangeLog"))
        {
            $ChangeLog.Add($LogEntry)
        }
        else
        {
            Write-Error $LogEntry
        }
    }
}